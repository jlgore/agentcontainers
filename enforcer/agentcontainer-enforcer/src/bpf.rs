//! BPF program loader and map manager.
//!
//! [`BpfPolicyManager`] implements [`PolicyManager`] by translating high-level
//! policy requests into BPF map operations via aya.
//!
//! On non-Linux platforms (macOS, Windows), BPF is unavailable so a stub
//! implementation logs warnings and returns `Ok(())` for all operations.
//! This allows the enforcer to compile and run its gRPC server on macOS
//! during development, deferring BPF enforcement to Linux containers.

use std::collections::HashMap;
use std::sync::RwLock;

use tonic::async_trait;
#[cfg(target_os = "linux")]
use tracing::info;
use tracing::warn;

use crate::events::{ContainerRegistry, EventBus};
use crate::policy::{
    ContainerHandle, CredentialPolicy, EnforcementEvent, EnforcementStats, FilesystemPolicy,
    NetworkPolicy, PolicyManager, ProcessPolicy,
};

#[derive(Clone, Debug)]
struct ToolWindow {
    correlation_id: String,
    start_ns: u64,
    end_ns: Option<u64>,
}

type CorrelationWindows = std::sync::Arc<RwLock<HashMap<u64, Vec<ToolWindow>>>>;

#[cfg(target_os = "linux")]
fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

#[cfg(not(target_os = "linux"))]
fn monotonic_ns() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_nanos() as u64
}

/// Decode a userspace `stat.st_dev` into the true (major, minor) pair.
///
/// `st_dev` carries glibc's expanded dev_t encoding (major split across bits
/// 8–19 and 32+, minor across bits 0–7 and 20–31) — NOT the kernel's internal
/// `sb->s_dev` layout (`major << 20 | minor`) that the BPF LSM hooks decode.
/// Both sides must reduce to the same true (major, minor) or every
/// FsInodeKey/SecretAclKey lookup silently misses, leaving the inode
/// deny-list and credential gating inert (fail-open).
#[cfg(target_os = "linux")]
fn decode_dev(st_dev: u64) -> (u32, u32) {
    (libc::major(st_dev), libc::minor(st_dev))
}

fn assign_correlation(event: &mut EnforcementEvent, windows: &CorrelationWindows) {
    let guard = windows.read().unwrap();
    let Some(items) = guard.get(&event.cgroup_id) else {
        return;
    };
    for w in items.iter().rev() {
        if event.timestamp_ns >= w.start_ns && w.end_ns.is_none_or(|end| event.timestamp_ns <= end)
        {
            event.correlation_id = w.correlation_id.clone();
            return;
        }
    }
}

// ===========================================================================
// Linux implementation — real BPF via aya
// ===========================================================================

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::events::{parse_cred_event, parse_exec_event, parse_fs_event, parse_network_event};
    use agentcontainer_common::events as bpf_events;
    use agentcontainer_common::maps::{
        CgroupStats, DomainKey, FsInodeKey, LpmDataV4, LpmDataV6, PortKeyV4, SecretAclKey,
        SecretAclValue, FS_PERM_READ, FS_PERM_WRITE, LPM_CGROUP_PREFIX,
    };
    use agentcontainer_common::siphash::{siphash128_bytes, SipHashKey};
    use aya::maps::lpm_trie::Key as LpmKey;
    use aya::maps::{Array as AyaArray, HashMap as AyaHashMap, LpmTrie, PerCpuHashMap, RingBuf};
    use aya::programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType, CgroupSockAddr, Lsm};
    use aya::{Btf, Ebpf};
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;

    /// Well-known paths where the BPF ELF may be found, in priority order.
    ///
    /// 1. Installed path (in containers).
    /// 2. xtask release build (manual `cargo xtask build-ebpf --release`).
    /// 3. xtask debug build (manual `cargo xtask build-ebpf`).
    const BPF_ELF_PATHS: &[&str] = &[
        "/usr/lib/agentcontainer-enforcer/agentcontainer-ebpf-progs",
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../target/bpfel-unknown-none/release/agentcontainer-ebpf-progs"
        ),
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../target/bpfel-unknown-none/debug/agentcontainer-ebpf-progs"
        ),
    ];

    /// Path to BPF ELF compiled by aya-build during `cargo build`.
    /// Set by build.rs via `cargo:rustc-env`. None when BPF build was skipped.
    const BPF_ELF_AYA_BUILD: Option<&str> = option_env!("AC_BPF_OUT_DIR");

    /// Environment variable to override the BPF ELF path.
    const BPF_ELF_ENV: &str = "AC_BPF_ELF_PATH";

    /// Real BPF-backed policy manager for Linux.
    ///
    /// Holds the loaded BPF programs and typed map handles. Methods translate
    /// high-level policy types from [`crate::policy`] into BPF map key/value
    /// insertions via aya.
    pub struct BpfPolicyManager {
        /// The loaded eBPF programs (network hooks, LSM hooks, DNS parser).
        programs: std::sync::Mutex<Ebpf>,

        /// Tracks cgroup_id -> container_id for ring buffer event correlation.
        registry: ContainerRegistry,

        /// Fan-out event bus for gRPC streaming.
        #[allow(dead_code)]
        event_bus: EventBus,

        /// In-memory tracking of which cgroup IDs have been registered,
        /// so we can clean up all related map entries on unregister.
        container_cgroups: RwLock<HashMap<String, u64>>,

        /// Container init PIDs supplied at registration. Policy paths for a
        /// container with a known PID resolve through `/proc/<pid>/root` —
        /// its mount namespace — so pinned inodes match what the LSM hooks
        /// observe (overlayfs files differ from same-named host paths).
        container_pids: RwLock<HashMap<String, u32>>,

        /// Per-cgroup tool-call windows used to attach MCP correlation IDs
        /// to asynchronous kernel events by event timestamp.
        correlations: CorrelationWindows,

        /// SipHash-2-4 key shared with the BPF DNS parser (written to the
        /// SIPHASH_KEY map at startup). Used to hash policy domains when
        /// populating TRACKED_DOMAINS.
        siphash_key: SipHashKey,
    }

    impl BpfPolicyManager {
        /// Load BPF programs from the compiled ELF object.
        ///
        /// The ELF is located by checking (in order):
        /// 1. `AC_BPF_ELF_PATH` environment variable
        /// 2. aya-build output (compiled automatically by build.rs)
        /// 3. `/usr/lib/agentcontainer-enforcer/agentcontainer-ebpf` (installed path)
        /// 4. `target/bpfel-unknown-none/release/agentcontainer-ebpf` (xtask release build)
        /// 5. `target/bpfel-unknown-none/debug/agentcontainer-ebpf` (xtask debug build)
        ///
        /// This requires:
        /// - Linux 5.15+ with BTF support
        /// - CAP_BPF + CAP_NET_ADMIN capabilities
        /// - The `agentcontainer-ebpf` crate compiled to BPF bytecode (automatic via `cargo build`)
        pub fn new() -> anyhow::Result<Self> {
            let elf_bytes = Self::load_bpf_elf()?;
            let mut bpf = Ebpf::load(&elf_bytes)
                .map_err(|e| anyhow::anyhow!("failed to load BPF programs: {e}"))?;

            // Initialize BPF logging (non-fatal — tracing may not be wired yet).
            if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
                warn!("BPF logger initialization failed (non-fatal): {e}");
            }

            // Attach the programs — Ebpf::load only places them in the
            // kernel; nothing enforces until each program is attached.
            Self::attach_programs(&mut bpf)?;

            // Generate and publish the SipHash key shared with the BPF DNS
            // parser. Kept on the manager so apply_network can hash policy
            // domains identically when populating TRACKED_DOMAINS.
            let siphash_key = Self::init_siphash_key(&mut bpf)?;

            info!("BPF programs loaded and attached successfully");

            let registry = ContainerRegistry::new();
            let event_bus = EventBus::new();

            let mgr = Self {
                programs: std::sync::Mutex::new(bpf),
                registry,
                event_bus,
                container_cgroups: RwLock::new(HashMap::new()),
                container_pids: RwLock::new(HashMap::new()),
                correlations: std::sync::Arc::new(RwLock::new(HashMap::new())),
                siphash_key,
            };

            // Spawn background ring buffer readers for all event sources.
            mgr.spawn_event_readers();

            Ok(mgr)
        }

        /// Attach all BPF programs.
        ///
        /// Network hooks (connect4/6, sendmsg4/6) and the DNS parser attach
        /// to the cgroup2 root — they self-filter via ENFORCED_CGROUPS, so
        /// non-registered cgroups pay one map lookup and pass through.
        /// `AllowMultiple` so we coexist with other cgroup BPF programs
        /// (e.g. systemd socket filtering).
        ///
        /// LSM hooks (file_open, bprm_check) attach system-wide via BTF.
        /// LSM attach failure is tolerated with a loud warning: kernels
        /// without CONFIG_BPF_LSM (or "bpf" missing from the lsm= cmdline)
        /// can still enforce the network boundary.
        fn attach_programs(bpf: &mut Ebpf) -> anyhow::Result<()> {
            let cgroup = std::fs::File::open("/sys/fs/cgroup")
                .map_err(|e| anyhow::anyhow!("opening cgroup2 root /sys/fs/cgroup: {e}"))?;

            for name in ["ac_connect4", "ac_connect6", "ac_sendmsg4", "ac_sendmsg6"] {
                let prog: &mut CgroupSockAddr = bpf
                    .program_mut(name)
                    .ok_or_else(|| anyhow::anyhow!("BPF program {name} not found"))?
                    .try_into()
                    .map_err(|e| anyhow::anyhow!("program {name} type mismatch: {e}"))?;
                prog.load()
                    .map_err(|e| anyhow::anyhow!("loading {name}: {e}"))?;
                prog.attach(&cgroup, CgroupAttachMode::AllowMultiple)
                    .map_err(|e| anyhow::anyhow!("attaching {name} to cgroup root: {e}"))?;
                info!(program = name, "attached network enforcement hook");
            }

            let dns: &mut CgroupSkb = bpf
                .program_mut("ac_dns_ingress")
                .ok_or_else(|| anyhow::anyhow!("BPF program ac_dns_ingress not found"))?
                .try_into()
                .map_err(|e| anyhow::anyhow!("program ac_dns_ingress type mismatch: {e}"))?;
            dns.load()
                .map_err(|e| anyhow::anyhow!("loading ac_dns_ingress: {e}"))?;
            dns.attach(
                &cgroup,
                CgroupSkbAttachType::Ingress,
                CgroupAttachMode::AllowMultiple,
            )
            .map_err(|e| anyhow::anyhow!("attaching ac_dns_ingress: {e}"))?;
            info!("attached DNS observation hook");

            match Btf::from_sys_fs() {
                Ok(btf) => {
                    for (name, hook) in [
                        ("ac_file_open", "file_open"),
                        ("ac_bprm_check", "bprm_check_security"),
                    ] {
                        let attach = (|| -> anyhow::Result<()> {
                            let prog: &mut Lsm = bpf
                                .program_mut(name)
                                .ok_or_else(|| anyhow::anyhow!("BPF program {name} not found"))?
                                .try_into()
                                .map_err(|e| anyhow::anyhow!("type mismatch: {e}"))?;
                            prog.load(hook, &btf)
                                .map_err(|e| anyhow::anyhow!("loading: {e}"))?;
                            prog.attach()
                                .map_err(|e| anyhow::anyhow!("attaching: {e}"))?;
                            Ok(())
                        })();
                        match attach {
                            Ok(()) => info!(program = name, hook, "attached LSM hook"),
                            Err(e) => warn!(
                                program = name,
                                hook,
                                error = %e,
                                "LSM hook NOT attached — kernel deny-list filesystem/exec \
                                 enforcement and exec audit events are inactive (requires \
                                 CONFIG_BPF_LSM and 'bpf' in the lsm= kernel cmdline)"
                            ),
                        }
                    }
                }
                Err(e) => warn!(
                    error = %e,
                    "BTF unavailable — LSM hooks not attached; kernel deny-list \
                     filesystem/exec enforcement and exec audit events are inactive"
                ),
            }

            Ok(())
        }

        /// Generate a random SipHash-2-4 key and write it to the SIPHASH_KEY
        /// map so the BPF DNS parser and userspace hash domains identically.
        fn init_siphash_key(bpf: &mut Ebpf) -> anyhow::Result<SipHashKey> {
            let mut kb = [0u8; 16];
            std::fs::File::open("/dev/urandom")
                .and_then(|mut f| f.read_exact(&mut kb))
                .map_err(|e| anyhow::anyhow!("reading /dev/urandom for SipHash key: {e}"))?;
            let key = SipHashKey {
                k0: u64::from_ne_bytes(kb[..8].try_into().unwrap()),
                k1: u64::from_ne_bytes(kb[8..].try_into().unwrap()),
            };

            let map_data = bpf
                .map_mut("SIPHASH_KEY")
                .ok_or_else(|| anyhow::anyhow!("BPF map SIPHASH_KEY not found"))?;
            let mut map: AyaArray<_, SipHashKey> = AyaArray::try_from(map_data)?;
            map.set(0, key, 0)?;
            Ok(key)
        }

        /// Spawn background tasks that drain all BPF ring buffers and publish
        /// parsed events to the [`EventBus`].
        ///
        /// Each ring buffer gets its own tokio task. Tasks run until the
        /// ring buffer is closed (i.e. the BPF programs are unloaded). Events
        /// are parsed into [`EnforcementEvent`]s and fanned out via the
        /// [`EventBus`] to all gRPC stream subscribers.
        fn spawn_event_readers(&self) {
            // Spawn a dedicated OS thread that holds the BPF programs lock and
            // runs all ring buffer readers. We pass a raw pointer to self.programs
            // because the Mutex<Ebpf> is not Arc-wrapped. This is safe because
            // BpfPolicyManager lives for the process lifetime (created at startup,
            // never dropped).
            let programs_ptr = &self.programs as *const std::sync::Mutex<Ebpf>;
            // SAFETY: BpfPolicyManager is created once at startup and lives until
            // process exit. The thread we spawn accesses programs through this
            // pointer for its entire lifetime.
            let programs: &'static std::sync::Mutex<Ebpf> = unsafe { &*programs_ptr };
            let bus = self.event_bus.clone();
            let registry = self.registry.clone();
            let correlations = self.correlations.clone();

            std::thread::Builder::new()
                .name("event-readers".into())
                .spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("event reader runtime");

                    let local = tokio::task::LocalSet::new();
                    local.block_on(&rt, async {
                        // Leak the MutexGuard — held for the process lifetime.
                        // Ring buffer readers need 'static refs to MapData inside.
                        let bpf = Box::leak(Box::new(programs.lock().unwrap()));
                        let mut handles = Vec::new();

                        macro_rules! spawn_reader {
                            ($map_name:expr, $event_type:ty, $parse_fn:expr) => {
                                if let Some(map_data) = bpf.map($map_name) {
                                    if let Ok(ring_buf) = RingBuf::try_from(map_data) {
                                        let b = bus.clone();
                                        let r = registry.clone();
                                        let c = correlations.clone();
                                        handles.push(tokio::task::spawn_local(async move {
                                            Self::run_ring_buf_reader(
                                                ring_buf,
                                                b,
                                                r,
                                                c,
                                                |data, cid| {
                                                    if data.len()
                                                        >= std::mem::size_of::<$event_type>()
                                                    {
                                                        let raw: $event_type = unsafe {
                                                            std::ptr::read_unaligned(
                                                                data.as_ptr() as *const _
                                                            )
                                                        };
                                                        Some($parse_fn(&raw, cid))
                                                    } else {
                                                        None
                                                    }
                                                },
                                            )
                                            .await;
                                        }));
                                        info!("{} ring buffer reader started", $map_name);
                                    }
                                }
                            };
                        }

                        spawn_reader!("NET_EVENTS", bpf_events::NetworkEvent, parse_network_event);
                        spawn_reader!("FS_EVENTS", bpf_events::FsEvent, parse_fs_event);
                        spawn_reader!("PROC_EVENTS", bpf_events::ExecEvent, parse_exec_event);
                        spawn_reader!("CRED_EVENTS", bpf_events::CredEvent, parse_cred_event);

                        for h in handles {
                            let _ = h.await;
                        }
                    });
                })
                .expect("spawn event reader thread");
        }

        /// Generic ring buffer drain loop.
        ///
        /// Reads events from the ring buffer, resolves the `cgroup_id` field in the
        /// raw data to a container ID via the [`ContainerRegistry`], calls `parse` to
        /// produce an [`EnforcementEvent`], and publishes it to the [`EventBus`].
        ///
        /// `parse` receives the raw byte slice and the resolved container ID string.
        /// It returns `None` if the data is malformed or should be skipped.
        ///
        /// The loop terminates when the ring buffer returns no items (i.e. the BPF
        /// programs have been unloaded) — this is expected during normal shutdown.
        async fn run_ring_buf_reader<F>(
            mut ring_buf: RingBuf<&aya::maps::MapData>,
            bus: EventBus,
            registry: ContainerRegistry,
            correlations: CorrelationWindows,
            parse: F,
        ) where
            F: Fn(&[u8], &str) -> Option<crate::policy::EnforcementEvent> + Send + 'static,
        {
            use aya::util::online_cpus;
            use tokio::io::unix::AsyncFd;

            // Wrap the ring buffer fd for async readiness notifications.
            let raw_fd = {
                use std::os::unix::io::AsRawFd;
                ring_buf.as_raw_fd()
            };

            // Safety: we hold `ring_buf` for the lifetime of this future, so the fd is valid.
            let async_fd = match AsyncFd::new(raw_fd) {
                Ok(fd) => fd,
                Err(e) => {
                    warn!(error = %e, "failed to create AsyncFd for ring buffer — event reader disabled");
                    return;
                }
            };

            loop {
                // Wait until the ring buffer has data.
                let mut guard = match async_fd.readable().await {
                    Ok(g) => g,
                    Err(e) => {
                        warn!(error = %e, "ring buffer readable() error, stopping reader");
                        break;
                    }
                };

                // Drain all available records.
                while let Some(item) = ring_buf.next() {
                    let data: &[u8] = &item;

                    if let Some(mut event) = parse(data, "") {
                        if let Some(container_id) = registry.lookup(event.cgroup_id).await {
                            event.container_id = container_id;
                        }
                        assign_correlation(&mut event, &correlations);
                        bus.publish(event);
                    }
                }

                guard.clear_ready();
                let _ = online_cpus(); // suppress unused import warning
            }
        }

        /// Locate and read the BPF ELF binary.
        fn load_bpf_elf() -> anyhow::Result<Vec<u8>> {
            // Check environment variable override first.
            if let Ok(path) = std::env::var(BPF_ELF_ENV) {
                info!(path, "loading BPF ELF from environment variable");
                return std::fs::read(&path).map_err(|e| {
                    anyhow::anyhow!("failed to read BPF ELF from {BPF_ELF_ENV}={path}: {e}")
                });
            }

            // Check aya-build output (compiled automatically by build.rs).
            if let Some(out_dir) = BPF_ELF_AYA_BUILD {
                let path = format!("{out_dir}/agentcontainer-ebpf-progs");
                if std::path::Path::new(&path).exists() {
                    info!(path, "loading BPF ELF from aya-build output");
                    return std::fs::read(&path)
                        .map_err(|e| anyhow::anyhow!("failed to read BPF ELF from {path}: {e}"));
                }
            }

            // Try well-known paths.
            for path in BPF_ELF_PATHS {
                if std::path::Path::new(path).exists() {
                    info!(path, "loading BPF ELF from well-known path");
                    return std::fs::read(path)
                        .map_err(|e| anyhow::anyhow!("failed to read BPF ELF from {path}: {e}"));
                }
            }

            anyhow::bail!(
                "BPF ELF not found. Run `cargo build` (aya-build compiles it automatically) \
                 or set {BPF_ELF_ENV} to the path of the compiled agentcontainer-ebpf binary. \
                 Searched paths: {:?}",
                BPF_ELF_PATHS,
            )
        }

        /// Resolve a cgroup filesystem path to a cgroup ID (inode number).
        fn resolve_cgroup_id(cgroup_path: &str) -> anyhow::Result<u64> {
            let meta = std::fs::metadata(cgroup_path)
                .map_err(|e| anyhow::anyhow!("failed to stat cgroup path {cgroup_path}: {e}"))?;
            Ok(meta.ino())
        }

        /// Resolve a filesystem path to an (inode, dev_major, dev_minor) triple.
        /// Device numbers are decoded from the glibc st_dev encoding so they
        /// match what the BPF hooks decode from the kernel's `sb->s_dev`.
        fn resolve_inode(path: &str) -> anyhow::Result<(u64, u32, u32)> {
            let meta = std::fs::metadata(path)
                .map_err(|e| anyhow::anyhow!("failed to stat {path}: {e}"))?;
            let (dev_major, dev_minor) = super::decode_dev(meta.dev());
            Ok((meta.ino(), dev_major, dev_minor))
        }

        /// Resolve a *container-namespace* policy path to the inode triple
        /// the container's LSM hooks will observe.
        ///
        /// Policy paths (`policy.filesystem`, exec allowlists, secret ACLs)
        /// are what the containerized tool sees, so they must be resolved
        /// through `/proc/<init_pid>/root` — the container's mount
        /// namespace. Stat'ing the same string in the enforcer's namespace
        /// pins a *different* file for anything on the container's
        /// overlayfs (only bind-mounted host paths coincide). Mirrors the
        /// `/proc/<pid>/root` mechanism `inject_secrets` already uses.
        ///
        /// Falls back to the enforcer's own namespace when no init PID was
        /// supplied at registration (host-side callers).
        fn resolve_container_inode(
            &self,
            container_id: &str,
            path: &str,
        ) -> anyhow::Result<(u64, u32, u32)> {
            match self.container_pids.read().unwrap().get(container_id) {
                Some(&pid) => Self::resolve_inode(&format!("/proc/{pid}/root{path}")),
                None => {
                    warn!(
                        container_id,
                        path,
                        "no init PID registered; resolving policy path in the \
                         enforcer's own namespace (container-image paths will \
                         not match)"
                    );
                    Self::resolve_inode(path)
                }
            }
        }

        /// Remove entries belonging to `cgroup_id` from a hash map whose key
        /// struct embeds a cgroup_id (extracted via `key_cgroup`).
        fn cleanup_hash_entries<K: aya::Pod, V: aya::Pod>(
            bpf: &mut Ebpf,
            name: &str,
            cgroup_id: u64,
            key_cgroup: impl Fn(&K) -> u64,
        ) {
            let Some(map_data) = bpf.map_mut(name) else {
                return;
            };
            let Ok(mut map) = AyaHashMap::<_, K, V>::try_from(map_data) else {
                warn!(map = name, "failed to open map for per-cgroup cleanup");
                return;
            };
            let stale: Vec<K> = map
                .keys()
                .filter_map(|k| k.ok())
                .filter(|k| key_cgroup(k) == cgroup_id)
                .collect();
            for key in &stale {
                if let Err(e) = map.remove(key) {
                    warn!(map = name, cgroup_id, error = %e, "failed to remove stale entry");
                }
            }
            if !stale.is_empty() {
                info!(
                    map = name,
                    cgroup_id,
                    removed = stale.len(),
                    "cleaned per-cgroup entries"
                );
            }
        }

        /// Remove entries belonging to `cgroup_id` from a per-cgroup LPM trie
        /// (data payload begins with the 64-bit cgroup_id).
        fn cleanup_lpm_entries<K: aya::Pod>(
            bpf: &mut Ebpf,
            name: &str,
            cgroup_id: u64,
            key_cgroup: impl Fn(&K) -> u64,
        ) {
            let Some(map_data) = bpf.map_mut(name) else {
                return;
            };
            let Ok(mut map) = LpmTrie::<_, K, u8>::try_from(map_data) else {
                warn!(map = name, "failed to open map for per-cgroup cleanup");
                return;
            };
            let stale: Vec<LpmKey<K>> = map
                .keys()
                .filter_map(|k| k.ok())
                .filter(|k| key_cgroup(&k.data()) == cgroup_id)
                .collect();
            let removed = stale.len();
            for key in stale {
                if let Err(e) = map.remove(&key) {
                    warn!(map = name, cgroup_id, error = %e, "failed to remove stale entry");
                }
            }
            if removed > 0 {
                info!(map = name, cgroup_id, removed, "cleaned per-cgroup entries");
            }
        }

        /// Insert a policy host into TRACKED_DOMAINS for DNS observation.
        /// IP literals are skipped (they never appear in DNS questions).
        /// The hash matches the BPF DNS parser: SipHash-2-4 over the
        /// lowercased dotted name without a trailing dot.
        fn track_domain(
            bpf: &mut Ebpf,
            sip_key: &SipHashKey,
            cgroup_id: u64,
            host: &str,
        ) -> anyhow::Result<()> {
            if host.is_empty() || host.parse::<std::net::IpAddr>().is_ok() {
                return Ok(());
            }
            let canon = host.trim_end_matches('.').to_ascii_lowercase();
            let key = DomainKey {
                cgroup_id,
                hash: siphash128_bytes(sip_key, canon.as_bytes()),
            };
            let map_data = bpf
                .map_mut("TRACKED_DOMAINS")
                .ok_or_else(|| anyhow::anyhow!("BPF map TRACKED_DOMAINS not found"))?;
            let mut map: AyaHashMap<_, DomainKey, u8> = AyaHashMap::try_from(map_data)?;
            map.insert(key, 1, 0)?;
            info!(host = %canon, cgroup_id, "tracking domain for DNS observation");
            Ok(())
        }

        /// Remove the per-cgroup *network* policy entries for `cgroup_id` —
        /// the maps `apply_network` owns. Called both on unregister and at
        /// the top of every `apply_network` so a re-apply REPLACES the
        /// previous resolution instead of accumulating: without this, the
        /// 5-minute hostname refresh only ever adds, and the egress
        /// allowlist monotonically widens to every IP a CDN hostname ever
        /// resolved to.
        fn cleanup_network_entries(bpf: &mut Ebpf, cgroup_id: u64) {
            Self::cleanup_lpm_entries::<LpmDataV4>(bpf, "ALLOWED_V4", cgroup_id, |k| k.cgroup_id);
            Self::cleanup_lpm_entries::<LpmDataV6>(bpf, "ALLOWED_V6", cgroup_id, |k| k.cgroup_id);
            Self::cleanup_hash_entries::<PortKeyV4, u8>(bpf, "ALLOWED_PORTS", cgroup_id, |k| {
                k.cgroup_id
            });
            Self::cleanup_hash_entries::<DomainKey, u8>(bpf, "TRACKED_DOMAINS", cgroup_id, |k| {
                k.cgroup_id
            });
        }

        /// Remove all per-cgroup policy entries for `cgroup_id`.
        ///
        /// cgroup IDs are kernfs inode numbers and can be recycled after a
        /// container exits; a stale entry would hand the prior container's
        /// policy to whichever cgroup reuses the ID. With per-cgroup map
        /// keys this cleanup is mandatory, not best-effort.
        fn cleanup_cgroup_entries(bpf: &mut Ebpf, cgroup_id: u64) {
            Self::cleanup_network_entries(bpf, cgroup_id);
            Self::cleanup_lpm_entries::<LpmDataV4>(bpf, "BLOCKED_CIDRS_V4", cgroup_id, |k| {
                k.cgroup_id
            });
            Self::cleanup_lpm_entries::<LpmDataV6>(bpf, "BLOCKED_CIDRS_V6", cgroup_id, |k| {
                k.cgroup_id
            });
            Self::cleanup_hash_entries::<FsInodeKey, u8>(bpf, "ALLOWED_INODES", cgroup_id, |k| {
                k.cgroup_id
            });
            Self::cleanup_hash_entries::<FsInodeKey, u8>(bpf, "DENIED_INODES", cgroup_id, |k| {
                k.cgroup_id
            });
            Self::cleanup_hash_entries::<FsInodeKey, u8>(bpf, "ALLOWED_EXECS", cgroup_id, |k| {
                k.cgroup_id
            });
            Self::cleanup_hash_entries::<SecretAclKey, SecretAclValue>(
                bpf,
                "SECRET_ACLS",
                cgroup_id,
                |k| k.cgroup_id,
            );
        }
    }

    #[async_trait]
    impl PolicyManager for BpfPolicyManager {
        async fn register(
            &self,
            container_id: &str,
            cgroup_path: &str,
            init_pid: u32,
        ) -> anyhow::Result<ContainerHandle> {
            let cgroup_id = Self::resolve_cgroup_id(cgroup_path)?;
            info!(
                container_id,
                cgroup_id, cgroup_path, init_pid, "registering cgroup for BPF enforcement"
            );

            // Insert into ENFORCED_CGROUPS BPF map.
            {
                let mut bpf = self.programs.lock().unwrap();
                let mut map: AyaHashMap<_, u64, u8> = AyaHashMap::try_from(
                    bpf.map_mut("ENFORCED_CGROUPS")
                        .ok_or_else(|| anyhow::anyhow!("BPF map ENFORCED_CGROUPS not found"))?,
                )?;
                map.insert(cgroup_id, 1, 0)?;
            }

            // Track in registry for event correlation.
            self.registry
                .register_container(cgroup_id, container_id.to_string())
                .await;

            self.container_cgroups
                .write()
                .unwrap()
                .insert(container_id.to_string(), cgroup_id);
            if init_pid != 0 {
                self.container_pids
                    .write()
                    .unwrap()
                    .insert(container_id.to_string(), init_pid);
            }

            Ok(ContainerHandle {
                container_id: container_id.to_string(),
                cgroup_id,
            })
        }

        async fn unregister(&self, container_id: &str) -> anyhow::Result<()> {
            self.container_pids.write().unwrap().remove(container_id);
            let cgroup_id = self.container_cgroups.write().unwrap().remove(container_id);

            if let Some(cgroup_id) = cgroup_id {
                info!(
                    container_id,
                    cgroup_id, "unregistering cgroup from BPF enforcement"
                );

                {
                    let mut bpf = self.programs.lock().unwrap();

                    // Remove from ENFORCED_CGROUPS BPF map.
                    if let Some(map) = bpf.map_mut("ENFORCED_CGROUPS") {
                        if let Ok(mut map) = AyaHashMap::<_, u64, u8>::try_from(map) {
                            if let Err(e) = map.remove(&cgroup_id) {
                                warn!(cgroup_id, error = %e, "failed to remove cgroup from ENFORCED_CGROUPS");
                            }
                        }
                    }

                    // Clean up per-cgroup stats.
                    if let Some(map) = bpf.map_mut("CGROUP_STATS") {
                        if let Ok(mut map) = PerCpuHashMap::<_, u64, CgroupStats>::try_from(map) {
                            if let Err(e) = map.remove(&cgroup_id) {
                                warn!(cgroup_id, error = %e, "failed to remove cgroup from CGROUP_STATS");
                            }
                        }
                    }

                    self.correlations.write().unwrap().remove(&cgroup_id);

                    // Remove this cgroup's entries from every per-cgroup policy
                    // map (network LPM tries, ports, inodes, execs, secret ACLs)
                    // so a recycled cgroup ID cannot inherit stale policy.
                    Self::cleanup_cgroup_entries(&mut bpf, cgroup_id);
                } // MutexGuard dropped before await

                self.registry.unregister_container(cgroup_id).await;
            } else {
                warn!(container_id, "unregister called for unknown container");
            }

            Ok(())
        }

        async fn apply_network(
            &self,
            container_id: &str,
            policy: &NetworkPolicy,
        ) -> anyhow::Result<()> {
            let cgroup_id = self.lookup_cgroup(container_id)?;
            info!(container_id, cgroup_id, hosts = ?policy.allowed_hosts, "applying network policy to BPF maps");

            // Phase 1 — resolve every hostname BEFORE touching any map. DNS
            // can take seconds; the swap below must not leave the cgroup
            // swept (default-deny on previously-allowed destinations) while
            // lookups are in flight.
            let mut host_addrs: Vec<(&str, std::net::Ipv4Addr)> = Vec::new();
            for host in &policy.allowed_hosts {
                match tokio::net::lookup_host(format!("{host}:0")).await {
                    Ok(addrs) => {
                        for addr in addrs {
                            if let std::net::IpAddr::V4(ip) = addr.ip() {
                                host_addrs.push((host, ip));
                            }
                        }
                    }
                    Err(e) => {
                        warn!(host, error = %e, "DNS resolution failed for allowed host, skipping");
                    }
                }
            }
            let mut rule_addrs: Vec<(&crate::policy::EgressRule, std::net::Ipv4Addr, u8)> =
                Vec::new();
            for rule in &policy.egress_rules {
                let proto = match rule.protocol.to_lowercase().as_str() {
                    "tcp" => 6u8,
                    "udp" => 17u8,
                    _ => {
                        warn!(protocol = %rule.protocol, "unknown protocol in egress rule, skipping");
                        continue;
                    }
                };
                match tokio::net::lookup_host(format!("{}:0", rule.host)).await {
                    Ok(addrs) => {
                        for addr in addrs {
                            if let std::net::IpAddr::V4(ip) = addr.ip() {
                                rule_addrs.push((rule, ip, proto));
                            }
                        }
                    }
                    Err(e) => {
                        warn!(
                            host = %rule.host,
                            error = %e,
                            "DNS resolution failed for egress rule host, skipping"
                        );
                    }
                }
            }

            // Phase 2 — swap under one lock: sweep this cgroup's previous
            // network entries, then insert the fresh resolution. A re-apply
            // (the 5-minute hostname refresh) thereby REPLACES the prior IP
            // set; insert-only semantics would accumulate every IP a CDN
            // hostname ever resolved to, monotonically widening egress for
            // the whole session. The deny window is map-operation-sized.
            let mut bpf = self.programs.lock().unwrap();
            Self::cleanup_network_entries(&mut bpf, cgroup_id);

            // Track hostname-typed policy entries for DNS observation: the
            // BPF DNS parser only emits events for (cgroup_id, domain_hash)
            // pairs present in TRACKED_DOMAINS.
            let hosts = policy
                .allowed_hosts
                .iter()
                .chain(policy.egress_rules.iter().map(|r| &r.host));
            for host in hosts {
                if let Err(e) = Self::track_domain(&mut bpf, &self.siphash_key, cgroup_id, host) {
                    warn!(host, error = %e, "failed to add domain to TRACKED_DOMAINS");
                }
            }

            for (host, ip) in host_addrs {
                // Per-cgroup LPM key: prefix covers all 64 cgroup bits plus
                // the full /32 host address.
                let key = LpmKey::new(
                    LPM_CGROUP_PREFIX + 32,
                    LpmDataV4 {
                        cgroup_id,
                        addr: u32::from(ip).to_be(),
                        _pad: 0,
                    },
                );
                let map_data = bpf
                    .map_mut("ALLOWED_V4")
                    .ok_or_else(|| anyhow::anyhow!("BPF map ALLOWED_V4 not found"))?;
                let mut map: LpmTrie<_, LpmDataV4, u8> = LpmTrie::try_from(map_data)?;
                map.insert(&key, 1, 0)?;
                info!(host, ip = %ip, cgroup_id, "added IP to ALLOWED_V4");
            }

            for (rule, ip, proto) in rule_addrs {
                let key = PortKeyV4 {
                    cgroup_id,
                    ip: u32::from(ip).to_be(),
                    port: rule.port,
                    protocol: proto,
                    _pad: 0,
                };
                let map_data = bpf
                    .map_mut("ALLOWED_PORTS")
                    .ok_or_else(|| anyhow::anyhow!("BPF map ALLOWED_PORTS not found"))?;
                let mut map: AyaHashMap<_, PortKeyV4, u8> = AyaHashMap::try_from(map_data)?;
                map.insert(key, 1, 0)?;
                info!(
                    host = %rule.host,
                    ip = %ip,
                    port = rule.port,
                    protocol = %rule.protocol,
                    "added port rule to ALLOWED_PORTS"
                );
            }

            Ok(())
        }

        async fn apply_filesystem(
            &self,
            container_id: &str,
            policy: &FilesystemPolicy,
        ) -> anyhow::Result<()> {
            let cgroup_id = self.lookup_cgroup(container_id)?;
            info!(
                container_id,
                cgroup_id, "applying filesystem policy to BPF maps"
            );

            let mut bpf = self.programs.lock().unwrap();

            // Insert read-only paths.
            for path in &policy.read_paths {
                match self.resolve_container_inode(container_id, path) {
                    Ok((inode, dev_major, dev_minor)) => {
                        let key = FsInodeKey {
                            inode,
                            dev_major,
                            dev_minor,
                            cgroup_id,
                        };
                        let map_data = bpf
                            .map_mut("ALLOWED_INODES")
                            .ok_or_else(|| anyhow::anyhow!("BPF map ALLOWED_INODES not found"))?;
                        let mut map: AyaHashMap<_, FsInodeKey, u8> =
                            AyaHashMap::try_from(map_data)?;
                        map.insert(key, FS_PERM_READ, 0)?;
                        info!(path, inode, "added read-only inode to ALLOWED_INODES");
                    }
                    Err(e) => {
                        warn!(path, error = %e, "failed to resolve read path inode, skipping");
                    }
                }
            }

            // Insert read+write paths.
            for path in &policy.write_paths {
                match self.resolve_container_inode(container_id, path) {
                    Ok((inode, dev_major, dev_minor)) => {
                        let key = FsInodeKey {
                            inode,
                            dev_major,
                            dev_minor,
                            cgroup_id,
                        };
                        let map_data = bpf
                            .map_mut("ALLOWED_INODES")
                            .ok_or_else(|| anyhow::anyhow!("BPF map ALLOWED_INODES not found"))?;
                        let mut map: AyaHashMap<_, FsInodeKey, u8> =
                            AyaHashMap::try_from(map_data)?;
                        map.insert(key, FS_PERM_READ | FS_PERM_WRITE, 0)?;
                        info!(path, inode, "added read-write inode to ALLOWED_INODES");
                    }
                    Err(e) => {
                        warn!(path, error = %e, "failed to resolve write path inode, skipping");
                    }
                }
            }

            // Insert denied paths (checked by the LSM hook BEFORE the allow
            // list, so a deny entry overrides any allow for the same inode).
            for path in &policy.deny_paths {
                match self.resolve_container_inode(container_id, path) {
                    Ok((inode, dev_major, dev_minor)) => {
                        let key = FsInodeKey {
                            inode,
                            dev_major,
                            dev_minor,
                            cgroup_id,
                        };
                        let map_data = bpf
                            .map_mut("DENIED_INODES")
                            .ok_or_else(|| anyhow::anyhow!("BPF map DENIED_INODES not found"))?;
                        let mut map: AyaHashMap<_, FsInodeKey, u8> =
                            AyaHashMap::try_from(map_data)?;
                        map.insert(key, 1, 0)?;
                        info!(path, inode, "added denied inode to DENIED_INODES");
                    }
                    Err(e) => {
                        warn!(path, error = %e, "failed to resolve deny path inode, skipping");
                    }
                }
            }

            Ok(())
        }

        async fn apply_process(
            &self,
            container_id: &str,
            policy: &ProcessPolicy,
        ) -> anyhow::Result<()> {
            let cgroup_id = self.lookup_cgroup(container_id)?;
            info!(container_id, cgroup_id, binaries = ?policy.allowed_binaries, "applying process policy to BPF maps");

            let mut bpf = self.programs.lock().unwrap();

            for binary in &policy.allowed_binaries {
                match self.resolve_container_inode(container_id, binary) {
                    Ok((inode, dev_major, dev_minor)) => {
                        let key = FsInodeKey {
                            inode,
                            dev_major,
                            dev_minor,
                            cgroup_id,
                        };
                        let map_data = bpf
                            .map_mut("ALLOWED_EXECS")
                            .ok_or_else(|| anyhow::anyhow!("BPF map ALLOWED_EXECS not found"))?;
                        let mut map: AyaHashMap<_, FsInodeKey, u8> =
                            AyaHashMap::try_from(map_data)?;
                        map.insert(key, 1, 0)?;
                        info!(binary, inode, "added binary inode to ALLOWED_EXECS");
                    }
                    Err(e) => {
                        warn!(binary, error = %e, "failed to resolve binary inode, skipping");
                    }
                }
            }

            Ok(())
        }

        async fn apply_credential(
            &self,
            container_id: &str,
            policy: &CredentialPolicy,
        ) -> anyhow::Result<()> {
            let cgroup_id = self.lookup_cgroup(container_id)?;
            info!(
                container_id,
                cgroup_id,
                acls = policy.secret_acls.len(),
                "applying credential policy to BPF maps"
            );

            let mut bpf = self.programs.lock().unwrap();

            for acl in &policy.secret_acls {
                match self.resolve_container_inode(container_id, &acl.path) {
                    Ok((inode, dev_major, dev_minor)) => {
                        let key = SecretAclKey {
                            inode,
                            dev_major,
                            dev_minor,
                            cgroup_id,
                        };

                        let expires_at_ns = if acl.ttl_seconds > 0 {
                            // Use CLOCK_MONOTONIC to match BPF ktime_get_ns().
                            let mut ts = libc::timespec {
                                tv_sec: 0,
                                tv_nsec: 0,
                            };
                            unsafe {
                                libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
                            }
                            let now_ns = ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64;
                            now_ns + acl.ttl_seconds * 1_000_000_000
                        } else {
                            0 // No expiry.
                        };

                        let value = SecretAclValue {
                            expires_at_ns,
                            allowed_ops: FS_PERM_READ,
                            _pad: [0; 7],
                        };

                        let map_data = bpf
                            .map_mut("SECRET_ACLS")
                            .ok_or_else(|| anyhow::anyhow!("BPF map SECRET_ACLS not found"))?;
                        let mut map: AyaHashMap<_, SecretAclKey, SecretAclValue> =
                            AyaHashMap::try_from(map_data)?;
                        map.insert(key, value, 0)?;
                        info!(
                            path = %acl.path,
                            inode,
                            ttl = acl.ttl_seconds,
                            "added secret ACL to SECRET_ACLS"
                        );
                    }
                    Err(e) => {
                        warn!(
                            path = %acl.path,
                            error = %e,
                            "failed to resolve secret path inode, skipping"
                        );
                    }
                }
            }

            Ok(())
        }

        async fn get_stats(&self, container_id: &str) -> anyhow::Result<EnforcementStats> {
            let cgroup_id = self.lookup_cgroup(container_id)?;

            let bpf = self.programs.lock().unwrap();
            let map_data = bpf
                .map("CGROUP_STATS")
                .ok_or_else(|| anyhow::anyhow!("BPF map CGROUP_STATS not found"))?;
            let map: PerCpuHashMap<_, u64, CgroupStats> = PerCpuHashMap::try_from(map_data)?;

            match map.get(&cgroup_id, 0) {
                Ok(per_cpu_values) => {
                    // Sum counters across all CPUs.
                    let mut totals = EnforcementStats::default();
                    for cpu_stats in per_cpu_values.iter() {
                        totals.network_allowed += cpu_stats.network_allowed;
                        totals.network_blocked += cpu_stats.network_blocked;
                        totals.filesystem_allowed += cpu_stats.filesystem_allowed;
                        totals.filesystem_blocked += cpu_stats.filesystem_blocked;
                        totals.process_allowed += cpu_stats.process_allowed;
                        totals.process_blocked += cpu_stats.process_blocked;
                        totals.credential_allowed += cpu_stats.credential_allowed;
                        totals.credential_blocked += cpu_stats.credential_blocked;
                    }
                    Ok(totals)
                }
                Err(aya::maps::MapError::KeyNotFound) => {
                    // No stats yet for this cgroup (no enforcement decisions made).
                    Ok(EnforcementStats::default())
                }
                Err(e) => Err(anyhow::anyhow!(
                    "failed to read CGROUP_STATS for cgroup {cgroup_id}: {e}"
                )),
            }
        }

        async fn subscribe_events(
            &self,
            container_id: &str,
        ) -> anyhow::Result<tokio::sync::mpsc::Receiver<EnforcementEvent>> {
            Ok(self.event_bus.subscribe(container_id))
        }

        async fn prepare_tool_call(
            &self,
            container_id: &str,
            correlation_id: &str,
            _tool_name: &str,
        ) -> anyhow::Result<()> {
            let cgroup_id = self.lookup_cgroup(container_id)?;
            let mut windows = self.correlations.write().unwrap();
            windows.entry(cgroup_id).or_default().push(ToolWindow {
                correlation_id: correlation_id.to_string(),
                start_ns: monotonic_ns(),
                end_ns: None,
            });
            Ok(())
        }

        async fn complete_tool_call(
            &self,
            container_id: &str,
            correlation_id: &str,
        ) -> anyhow::Result<()> {
            let cgroup_id = self.lookup_cgroup(container_id)?;
            let mut windows = self.correlations.write().unwrap();
            if let Some(items) = windows.get_mut(&cgroup_id) {
                for w in items.iter_mut().rev() {
                    if w.correlation_id == correlation_id && w.end_ns.is_none() {
                        w.end_ns = Some(monotonic_ns());
                        break;
                    }
                }
            }
            Ok(())
        }
    }

    impl BpfPolicyManager {
        /// Look up the cgroup ID for a registered container.
        fn lookup_cgroup(&self, container_id: &str) -> anyhow::Result<u64> {
            self.container_cgroups
                .read()
                .unwrap()
                .get(container_id)
                .copied()
                .ok_or_else(|| {
                    anyhow::anyhow!("container {container_id} not registered — call register first")
                })
        }
    }
}

// ===========================================================================
// Non-Linux stub implementation
// ===========================================================================

#[cfg(not(target_os = "linux"))]
mod stub {
    use super::*;

    /// Stub BPF policy manager for non-Linux platforms (macOS, Windows).
    ///
    /// All operations log a warning and return `Ok(())`. This allows the
    /// enforcer binary to compile and run its gRPC server on macOS for
    /// development and testing, while actual BPF enforcement only happens
    /// on Linux.
    pub struct BpfPolicyManager {
        registry: ContainerRegistry,
        event_bus: EventBus,
        container_cgroups: RwLock<HashMap<String, u64>>,
        next_fake_id: RwLock<u64>,
        correlations: CorrelationWindows,
    }

    impl BpfPolicyManager {
        /// Create a stub BPF policy manager (no-op on non-Linux).
        pub fn new() -> anyhow::Result<Self> {
            warn!(
                "BPF enforcement unavailable on this platform — all policy operations are no-ops"
            );
            Ok(Self {
                registry: ContainerRegistry::new(),
                event_bus: EventBus::new(),
                container_cgroups: RwLock::new(HashMap::new()),
                next_fake_id: RwLock::new(1),
                correlations: std::sync::Arc::new(RwLock::new(HashMap::new())),
            })
        }
    }

    #[async_trait]
    impl PolicyManager for BpfPolicyManager {
        async fn register(
            &self,
            container_id: &str,
            cgroup_path: &str,
            _init_pid: u32,
        ) -> anyhow::Result<ContainerHandle> {
            let cgroup_id = {
                let mut id = self.next_fake_id.write().unwrap();
                let current = *id;
                *id += 1;
                current
            };
            warn!(
                container_id,
                cgroup_path, cgroup_id, "stub: register is a no-op (no BPF on this platform)"
            );

            self.registry
                .register_container(cgroup_id, container_id.to_string())
                .await;
            self.container_cgroups
                .write()
                .unwrap()
                .insert(container_id.to_string(), cgroup_id);

            Ok(ContainerHandle {
                container_id: container_id.to_string(),
                cgroup_id,
            })
        }

        async fn unregister(&self, container_id: &str) -> anyhow::Result<()> {
            warn!(container_id, "stub: unregister is a no-op");
            let cgroup_id = self.container_cgroups.write().unwrap().remove(container_id);
            if let Some(cgroup_id) = cgroup_id {
                self.registry.unregister_container(cgroup_id).await;
                self.correlations.write().unwrap().remove(&cgroup_id);
            }
            Ok(())
        }

        async fn apply_network(
            &self,
            container_id: &str,
            policy: &NetworkPolicy,
        ) -> anyhow::Result<()> {
            warn!(
                container_id,
                hosts = ?policy.allowed_hosts,
                rules = policy.egress_rules.len(),
                "stub: apply_network is a no-op"
            );
            Ok(())
        }

        async fn apply_filesystem(
            &self,
            container_id: &str,
            policy: &FilesystemPolicy,
        ) -> anyhow::Result<()> {
            warn!(
                container_id,
                read = policy.read_paths.len(),
                write = policy.write_paths.len(),
                deny = policy.deny_paths.len(),
                "stub: apply_filesystem is a no-op"
            );
            Ok(())
        }

        async fn apply_process(
            &self,
            container_id: &str,
            policy: &ProcessPolicy,
        ) -> anyhow::Result<()> {
            warn!(
                container_id,
                binaries = policy.allowed_binaries.len(),
                "stub: apply_process is a no-op"
            );
            Ok(())
        }

        async fn apply_credential(
            &self,
            container_id: &str,
            policy: &CredentialPolicy,
        ) -> anyhow::Result<()> {
            warn!(
                container_id,
                acls = policy.secret_acls.len(),
                "stub: apply_credential is a no-op"
            );
            Ok(())
        }

        async fn get_stats(&self, _container_id: &str) -> anyhow::Result<EnforcementStats> {
            Ok(EnforcementStats::default())
        }

        async fn subscribe_events(
            &self,
            container_id: &str,
        ) -> anyhow::Result<tokio::sync::mpsc::Receiver<EnforcementEvent>> {
            Ok(self.event_bus.subscribe(container_id))
        }

        async fn prepare_tool_call(
            &self,
            container_id: &str,
            correlation_id: &str,
            _tool_name: &str,
        ) -> anyhow::Result<()> {
            let cgroup_id = self.lookup_cgroup(container_id)?;
            self.correlations
                .write()
                .unwrap()
                .entry(cgroup_id)
                .or_default()
                .push(ToolWindow {
                    correlation_id: correlation_id.to_string(),
                    start_ns: monotonic_ns(),
                    end_ns: None,
                });
            Ok(())
        }

        async fn complete_tool_call(
            &self,
            container_id: &str,
            correlation_id: &str,
        ) -> anyhow::Result<()> {
            let cgroup_id = self.lookup_cgroup(container_id)?;
            if let Some(items) = self.correlations.write().unwrap().get_mut(&cgroup_id) {
                for w in items.iter_mut().rev() {
                    if w.correlation_id == correlation_id && w.end_ns.is_none() {
                        w.end_ns = Some(monotonic_ns());
                        break;
                    }
                }
            }
            Ok(())
        }
    }
}

// ===========================================================================
// Re-export the platform-appropriate implementation
// ===========================================================================

#[cfg(target_os = "linux")]
pub use linux::BpfPolicyManager;

#[cfg(not(target_os = "linux"))]
pub use stub::BpfPolicyManager;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PolicyManager;

    /// The userspace st_dev decode and the BPF-side s_dev decode
    /// (lsm/file_open.rs, lsm/bprm_check.rs: `(s_dev >> 20) & 0xfff`,
    /// `s_dev & 0xfffff`) must reduce to the same (major, minor) for the
    /// same device, or FsInodeKey/SecretAclKey lookups never match.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_decode_dev_matches_kernel_side() {
        // Includes minors > 0xff and majors > 0xff to exercise glibc's
        // split encoding — exactly where the old legacy decode broke.
        for &(major, minor) in &[
            (8u32, 1u32),
            (253, 3),
            (259, 0x1234),
            (0, 38),
            (4095, 0xfffff),
        ] {
            // Userspace view: glibc-encoded stat.st_dev.
            let st_dev = libc::makedev(major, minor);
            let user = decode_dev(st_dev);

            // Kernel view: sb->s_dev (MKDEV layout), decoded as the BPF
            // hooks do.
            let s_dev: u32 = (major << 20) | minor;
            let kernel = ((s_dev >> 20) & 0xfff, s_dev & 0xfffff);

            assert_eq!(user, kernel, "major={major} minor={minor}");
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn test_stub_register_unregister() {
        let mgr = BpfPolicyManager::new().unwrap();

        let handle = mgr
            .register("ctr-1", "/sys/fs/cgroup/test", 0)
            .await
            .unwrap();
        assert_eq!(handle.container_id, "ctr-1");
        assert!(handle.cgroup_id > 0);

        // Second register gets a different cgroup ID.
        let handle2 = mgr
            .register("ctr-2", "/sys/fs/cgroup/test2", 0)
            .await
            .unwrap();
        assert_ne!(handle.cgroup_id, handle2.cgroup_id);

        // Unregister should succeed.
        mgr.unregister("ctr-1").await.unwrap();

        // Double unregister should also succeed (idempotent).
        mgr.unregister("ctr-1").await.unwrap();
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn test_stub_apply_policies() {
        let mgr = BpfPolicyManager::new().unwrap();
        mgr.register("ctr-1", "/sys/fs/cgroup/test", 0)
            .await
            .unwrap();

        // All apply methods should succeed as no-ops.
        mgr.apply_network(
            "ctr-1",
            &NetworkPolicy {
                allowed_hosts: vec!["example.com".into()],
                egress_rules: vec![],
                dns_servers: vec![],
            },
        )
        .await
        .unwrap();

        mgr.apply_filesystem(
            "ctr-1",
            &FilesystemPolicy {
                read_paths: vec!["/etc".into()],
                write_paths: vec!["/tmp".into()],
                deny_paths: vec![],
            },
        )
        .await
        .unwrap();

        mgr.apply_process(
            "ctr-1",
            &ProcessPolicy {
                allowed_binaries: vec!["/bin/sh".into()],
            },
        )
        .await
        .unwrap();

        mgr.apply_credential(
            "ctr-1",
            &CredentialPolicy {
                secret_acls: vec![],
            },
        )
        .await
        .unwrap();
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn test_stub_get_stats_returns_defaults() {
        let mgr = BpfPolicyManager::new().unwrap();
        let stats = mgr.get_stats("ctr-1").await.unwrap();
        assert_eq!(stats.network_allowed, 0);
        assert_eq!(stats.network_blocked, 0);
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn test_stub_subscribe_events() {
        let mgr = BpfPolicyManager::new().unwrap();
        let _rx = mgr.subscribe_events("ctr-1").await.unwrap();
        // Receiver is valid; no events will come from stub.
    }
}
