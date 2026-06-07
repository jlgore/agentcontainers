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

/// How long a CLOSED window keeps matching after CompleteToolCall. Ring
/// buffer events are drained asynchronously: an event generated during call
/// N can be read after Complete(N), so closed windows must linger long
/// enough to catch the drain lag — then they are pruned, or a long session
/// accumulates one window per tool call forever.
const CLOSED_WINDOW_RETENTION_NS: u64 = 30 * 1_000_000_000;

/// How long an OPEN window (CompleteToolCall never arrived) keeps matching.
/// This bounds the blast radius of a lost Complete: without a horizon, one
/// failed RPC would attribute every subsequent kernel event for the cgroup
/// to that correlation ID for the rest of the session — misattribution the
/// spec calls worse than no attribution (§3.3). Generous enough for long
/// forensic tool runs; events past the horizon carry no correlation ID.
const OPEN_WINDOW_HORIZON_NS: u64 = 2 * 60 * 60 * 1_000_000_000;

/// How long a drained event is parked before correlation assignment.
///
/// Prepare-side race: `PrepareToolCall` captures the window's start
/// timestamp, then takes the write lock and inserts the window. An event
/// generated inside the window can be drained from the ring buffer during
/// that capture→insert gap — assigned immediately, it would find no window
/// and stay uncorrelated even though its kernel timestamp matches one.
/// Parking events for longer than any plausible lock-acquisition latency
/// lets the in-flight Prepare land first. Late assignment is safe precisely
/// because matching is by the event's kernel timestamp, not by when
/// assignment runs (the same property §3.3 uses on the Complete side).
const CORRELATION_ASSIGN_DELAY_NS: u64 = 100 * 1_000_000;

/// FIFO park bench for drained events awaiting correlation assignment.
/// Events become due `CORRELATION_ASSIGN_DELAY_NS` after their drain time;
/// drain order is preserved.
#[derive(Default)]
struct PendingEvents {
    queue: std::collections::VecDeque<(u64, EnforcementEvent)>,
}

impl PendingEvents {
    /// Park an event drained at `now`.
    fn park(&mut self, event: EnforcementEvent, now: u64) {
        self.queue
            .push_back((now.saturating_add(CORRELATION_ASSIGN_DELAY_NS), event));
    }

    /// Monotonic instant the oldest parked event becomes due, if any.
    fn next_due_ns(&self) -> Option<u64> {
        self.queue.front().map(|(due, _)| *due)
    }

    /// Remove and return every event due at `now` (drain order preserved).
    fn take_due(&mut self, now: u64) -> Vec<EnforcementEvent> {
        let mut due = Vec::new();
        while matches!(self.queue.front(), Some((d, _)) if *d <= now) {
            due.push(self.queue.pop_front().expect("front checked").1);
        }
        due
    }

    /// Remove and return everything regardless of due time (shutdown flush).
    fn take_all(&mut self) -> Vec<EnforcementEvent> {
        self.queue.drain(..).map(|(_, ev)| ev).collect()
    }
}

fn assign_correlation(event: &mut EnforcementEvent, windows: &CorrelationWindows) {
    let guard = windows.read().unwrap();
    let Some(items) = guard.get(&event.cgroup_id) else {
        return;
    };
    for w in items.iter().rev() {
        // An open window matches only up to its horizon — never the rest
        // of the session.
        let end = w
            .end_ns
            .unwrap_or_else(|| w.start_ns.saturating_add(OPEN_WINDOW_HORIZON_NS));
        if event.timestamp_ns >= w.start_ns && event.timestamp_ns <= end {
            event.correlation_id = w.correlation_id.clone();
            return;
        }
    }
}

/// Record the start of a tool-call window, pruning dead windows first (the
/// write lock is already held; prune amortizes to O(1) per call).
fn open_tool_window(windows: &CorrelationWindows, cgroup_id: u64, correlation_id: &str, now: u64) {
    let mut guard = windows.write().unwrap();
    let items = guard.entry(cgroup_id).or_default();
    prune_windows(items, now);
    items.push(ToolWindow {
        correlation_id: correlation_id.to_string(),
        start_ns: now,
        end_ns: None,
    });
}

/// Close the open window with this correlation ID. Returns false when no
/// such window exists (already completed, expired past the horizon, or
/// never prepared) — callers surface that, since a mismatched Complete is
/// an audit-relevant signal, not a no-op.
fn close_tool_window(
    windows: &CorrelationWindows,
    cgroup_id: u64,
    correlation_id: &str,
    now: u64,
) -> bool {
    let mut guard = windows.write().unwrap();
    let Some(items) = guard.get_mut(&cgroup_id) else {
        return false;
    };
    let mut found = false;
    for w in items.iter_mut().rev() {
        if w.correlation_id == correlation_id && w.end_ns.is_none() {
            w.end_ns = Some(now);
            found = true;
            break;
        }
    }
    prune_windows(items, now);
    found
}

/// Drop windows that can no longer match any event: closed ones past the
/// retention horizon, and open ones past the open-window horizon (their
/// CompleteToolCall is considered lost).
fn prune_windows(items: &mut Vec<ToolWindow>, now: u64) {
    items.retain(|w| match w.end_ns {
        Some(end) => now.saturating_sub(end) < CLOSED_WINDOW_RETENTION_NS,
        None => now.saturating_sub(w.start_ns) < OPEN_WINDOW_HORIZON_NS,
    });
}

// ===========================================================================
// Linux implementation — real BPF via aya
// ===========================================================================

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::events::{
        parse_cred_event, parse_dns_event, parse_exec_event, parse_fs_event, parse_network_event,
    };
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

    /// Cloud metadata endpoints blocked for every enforced cgroup on each
    /// `apply_network`, ahead of any allow entry (BLOCKED_CIDRS is checked
    /// first in the connect/sendmsg hooks). Mirrors the sandbox L7 proxy's
    /// default BlockCIDRs (internal/sandbox/policy.go).
    const METADATA_ENDPOINTS: &[&str] = &[
        "169.254.169.254/32", // AWS/GCP/Azure IMDS (v4)
        "fd00:ec2::254/128",  // AWS IMDS (v6)
    ];

    /// Convert an IPv6 address to the `[u32; 4]` layout the BPF hooks read
    /// from `user_ip6`: four words whose in-memory bytes are the address in
    /// network order (the LPM trie matches on raw key bytes).
    fn ipv6_words(ip: std::net::Ipv6Addr) -> [u32; 4] {
        let o = ip.octets();
        core::array::from_fn(|i| {
            u32::from_ne_bytes([o[4 * i], o[4 * i + 1], o[4 * i + 2], o[4 * i + 3]])
        })
    }

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

        /// Reverse map of policy-domain SipHash digests to the hostnames
        /// that produced them. The key is random per session, so a raw
        /// digest in a DNS observation event is opaque to the auditor —
        /// this map lets the event carry the human-readable domain.
        domain_names: DomainNames,
    }

    /// Digest → hostname reverse map shared with the DNS event reader.
    type DomainNames = std::sync::Arc<RwLock<HashMap<[u8; 16], String>>>;

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
                domain_names: std::sync::Arc::new(RwLock::new(HashMap::new())),
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
            let domain_names = self.domain_names.clone();

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
                                        // `move` so closure-typed parsers
                                        // (e.g. the DNS name enricher) are
                                        // owned by the task; plain fn-item
                                        // parsers are Copy and unaffected.
                                        handles.push(tokio::task::spawn_local(async move {
                                            Self::run_ring_buf_reader(
                                                ring_buf,
                                                b,
                                                r,
                                                c,
                                                move |data, cid| {
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
                        // DNS observations: enrich with the readable domain
                        // name — the SipHash key is random per session, so
                        // the raw digest is opaque to the auditor.
                        let parse_dns = move |raw: &bpf_events::DnsEvent, cid: &str| {
                            let mut ev = parse_dns_event(raw, cid);
                            if let Some(name) = domain_names.read().unwrap().get(&raw.domain_hash) {
                                ev.details.insert("domain".into(), name.clone());
                            }
                            ev
                        };
                        spawn_reader!("DNS_EVENTS", bpf_events::DnsEvent, parse_dns);

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

            // Drained events are parked briefly before correlation
            // assignment (see CORRELATION_ASSIGN_DELAY_NS): an event drained
            // in the gap between PrepareToolCall capturing its window-start
            // timestamp and inserting the window would otherwise be assigned
            // against a window set that does not yet contain its window.
            let mut pending = PendingEvents::default();

            'reader: loop {
                // Wait for ring buffer data — or for the oldest parked event
                // to come due, whichever is first.
                let readable = async_fd.readable();
                tokio::pin!(readable);
                let due_sleep = async {
                    match pending.next_due_ns() {
                        Some(due) => {
                            let now = monotonic_ns();
                            tokio::time::sleep(std::time::Duration::from_nanos(
                                due.saturating_sub(now),
                            ))
                            .await
                        }
                        // Nothing parked — only readability can wake us.
                        None => std::future::pending().await,
                    }
                };

                tokio::select! {
                    guard = &mut readable => {
                        let mut guard = match guard {
                            Ok(g) => g,
                            Err(e) => {
                                warn!(error = %e, "ring buffer readable() error, stopping reader");
                                break 'reader;
                            }
                        };

                        // Drain all available records into the park bench.
                        let now = monotonic_ns();
                        while let Some(item) = ring_buf.next() {
                            let data: &[u8] = &item;
                            if let Some(mut event) = parse(data, "") {
                                if let Some(container_id) = registry.lookup(event.cgroup_id).await {
                                    event.container_id = container_id;
                                }
                                pending.park(event, now);
                            }
                        }
                        guard.clear_ready();
                    }
                    _ = due_sleep => {}
                }

                // Publish whatever has aged past the assignment delay.
                for mut event in pending.take_due(monotonic_ns()) {
                    assign_correlation(&mut event, &correlations);
                    bus.publish(event);
                }
                let _ = online_cpus(); // suppress unused import warning
            }

            // Shutdown: flush parked events rather than dropping them — a
            // short assignment delay must never cost audit records.
            for mut event in pending.take_all() {
                assign_correlation(&mut event, &correlations);
                bus.publish(event);
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
        /// lowercased dotted name without a trailing dot. The digest →
        /// hostname mapping is recorded so observation events can carry
        /// the readable name.
        fn track_domain(
            bpf: &mut Ebpf,
            sip_key: &SipHashKey,
            names: &DomainNames,
            cgroup_id: u64,
            host: &str,
        ) -> anyhow::Result<()> {
            if host.is_empty() || host.parse::<std::net::IpAddr>().is_ok() {
                return Ok(());
            }
            let canon = host.trim_end_matches('.').to_ascii_lowercase();
            let hash = siphash128_bytes(sip_key, canon.as_bytes());
            let key = DomainKey { cgroup_id, hash };
            let map_data = bpf
                .map_mut("TRACKED_DOMAINS")
                .ok_or_else(|| anyhow::anyhow!("BPF map TRACKED_DOMAINS not found"))?;
            let mut map: AyaHashMap<_, DomainKey, u8> = AyaHashMap::try_from(map_data)?;
            map.insert(key, 1, 0)?;
            names.write().unwrap().insert(hash, canon.clone());
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
        ) -> anyhow::Result<crate::policy::NetworkApplyReport> {
            let cgroup_id = self.lookup_cgroup(container_id)?;
            info!(container_id, cgroup_id, hosts = ?policy.allowed_hosts, "applying network policy to BPF maps");

            // Hosts skipped because DNS failed — reported to the caller so a
            // partial application is distinguishable from a full one.
            let mut unresolved_hosts: Vec<String> = Vec::new();

            // Phase 1 — resolve every hostname BEFORE touching any map. DNS
            // can take seconds; the swap below must not leave the cgroup
            // swept (default-deny on previously-allowed destinations) while
            // lookups are in flight.
            let mut host_addrs: Vec<(&str, std::net::Ipv4Addr)> = Vec::new();
            let mut host_addrs_v6: Vec<(&str, std::net::Ipv6Addr)> = Vec::new();
            for host in &policy.allowed_hosts {
                match tokio::net::lookup_host(format!("{host}:0")).await {
                    Ok(addrs) => {
                        for addr in addrs {
                            match addr.ip() {
                                std::net::IpAddr::V4(ip) => host_addrs.push((host, ip)),
                                std::net::IpAddr::V6(ip) => host_addrs_v6.push((host, ip)),
                            }
                        }
                    }
                    Err(e) => {
                        warn!(host, error = %e, "DNS resolution failed for allowed host, skipping");
                        unresolved_hosts.push(host.clone());
                    }
                }
            }

            // Blocked CIDRs: policy entries plus the cloud metadata
            // endpoints, which are always denied for every enforced cgroup —
            // an allowed hostname under attacker-influenced DNS must not be
            // able to resolve its way to the instance credentials endpoint.
            let mut blocked_v4: Vec<(std::net::Ipv4Addr, u8)> = Vec::new();
            let mut blocked_v6: Vec<(std::net::Ipv6Addr, u8)> = Vec::new();
            let builtin = METADATA_ENDPOINTS.iter().map(|s| (*s, true));
            let declared = policy.blocked_cidrs.iter().map(|s| (s.as_str(), false));
            for (cidr, is_builtin) in builtin.chain(declared) {
                match crate::policy::parse_cidr(cidr) {
                    Some((std::net::IpAddr::V4(ip), prefix)) => blocked_v4.push((ip, prefix)),
                    Some((std::net::IpAddr::V6(ip), prefix)) => blocked_v6.push((ip, prefix)),
                    None => {
                        debug_assert!(!is_builtin, "builtin metadata CIDR must parse");
                        warn!(cidr, "malformed blocked CIDR in network policy, skipping");
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
                            match addr.ip() {
                                std::net::IpAddr::V4(ip) => rule_addrs.push((rule, ip, proto)),
                                std::net::IpAddr::V6(ip) => {
                                    // No per-port IPv6 map exists (ALLOWED_PORTS
                                    // is v4-keyed); widening the rule to a
                                    // host-wide v6 allow would exceed declared
                                    // policy, so the v6 address stays denied.
                                    warn!(
                                        host = %rule.host, ip = %ip,
                                        "egress rule resolved to IPv6 — port-scoped v6 enforcement unsupported, address remains denied"
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!(
                            host = %rule.host,
                            error = %e,
                            "DNS resolution failed for egress rule host, skipping"
                        );
                        unresolved_hosts.push(rule.host.clone());
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
                if let Err(e) = Self::track_domain(
                    &mut bpf,
                    &self.siphash_key,
                    &self.domain_names,
                    cgroup_id,
                    host,
                ) {
                    warn!(host, error = %e, "failed to add domain to TRACKED_DOMAINS");
                }
            }

            // Always-deny overrides go in first: BLOCKED_CIDRS_* is checked
            // before the allow maps in the hooks, so an IP covered here is
            // unreachable no matter what the allow inserts below contain.
            for (ip, prefix) in blocked_v4 {
                let key = LpmKey::new(
                    LPM_CGROUP_PREFIX + prefix as u32,
                    LpmDataV4 {
                        cgroup_id,
                        addr: u32::from(ip).to_be(),
                        _pad: 0,
                    },
                );
                let map_data = bpf
                    .map_mut("BLOCKED_CIDRS_V4")
                    .ok_or_else(|| anyhow::anyhow!("BPF map BLOCKED_CIDRS_V4 not found"))?;
                let mut map: LpmTrie<_, LpmDataV4, u8> = LpmTrie::try_from(map_data)?;
                map.insert(&key, 1, 0)?;
                info!(cidr = %format!("{ip}/{prefix}"), cgroup_id, "added CIDR to BLOCKED_CIDRS_V4");
            }
            for (ip, prefix) in blocked_v6 {
                let key = LpmKey::new(
                    LPM_CGROUP_PREFIX + prefix as u32,
                    LpmDataV6 {
                        cgroup_id,
                        addr: ipv6_words(ip),
                    },
                );
                let map_data = bpf
                    .map_mut("BLOCKED_CIDRS_V6")
                    .ok_or_else(|| anyhow::anyhow!("BPF map BLOCKED_CIDRS_V6 not found"))?;
                let mut map: LpmTrie<_, LpmDataV6, u8> = LpmTrie::try_from(map_data)?;
                map.insert(&key, 1, 0)?;
                info!(cidr = %format!("{ip}/{prefix}"), cgroup_id, "added CIDR to BLOCKED_CIDRS_V6");
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

            for (host, ip) in host_addrs_v6 {
                let key = LpmKey::new(
                    LPM_CGROUP_PREFIX + 128,
                    LpmDataV6 {
                        cgroup_id,
                        addr: ipv6_words(ip),
                    },
                );
                let map_data = bpf
                    .map_mut("ALLOWED_V6")
                    .ok_or_else(|| anyhow::anyhow!("BPF map ALLOWED_V6 not found"))?;
                let mut map: LpmTrie<_, LpmDataV6, u8> = LpmTrie::try_from(map_data)?;
                map.insert(&key, 1, 0)?;
                info!(host, ip = %ip, cgroup_id, "added IP to ALLOWED_V6");
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

            Ok(crate::policy::NetworkApplyReport { unresolved_hosts })
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
            open_tool_window(
                &self.correlations,
                cgroup_id,
                correlation_id,
                monotonic_ns(),
            );
            Ok(())
        }

        async fn complete_tool_call(
            &self,
            container_id: &str,
            correlation_id: &str,
        ) -> anyhow::Result<()> {
            let cgroup_id = self.lookup_cgroup(container_id)?;
            if !close_tool_window(
                &self.correlations,
                cgroup_id,
                correlation_id,
                monotonic_ns(),
            ) {
                warn!(
                    container_id,
                    correlation_id,
                    "CompleteToolCall matched no open window (already completed, expired past the horizon, or never prepared)"
                );
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
        ) -> anyhow::Result<crate::policy::NetworkApplyReport> {
            warn!(
                container_id,
                hosts = ?policy.allowed_hosts,
                rules = policy.egress_rules.len(),
                "stub: apply_network is a no-op"
            );
            Ok(crate::policy::NetworkApplyReport::default())
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
            open_tool_window(
                &self.correlations,
                cgroup_id,
                correlation_id,
                monotonic_ns(),
            );
            Ok(())
        }

        async fn complete_tool_call(
            &self,
            container_id: &str,
            correlation_id: &str,
        ) -> anyhow::Result<()> {
            let cgroup_id = self.lookup_cgroup(container_id)?;
            if !close_tool_window(
                &self.correlations,
                cgroup_id,
                correlation_id,
                monotonic_ns(),
            ) {
                warn!(
                    container_id,
                    correlation_id,
                    "CompleteToolCall matched no open window (already completed, expired past the horizon, or never prepared)"
                );
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

    fn test_event(cgroup_id: u64, timestamp_ns: u64) -> EnforcementEvent {
        EnforcementEvent {
            timestamp_ns,
            cgroup_id,
            correlation_id: String::new(),
            container_id: "ctr-1".into(),
            domain: crate::policy::EventDomain::Process,
            verdict: crate::policy::EventVerdict::Allow,
            pid: 1,
            comm: "find".into(),
            details: HashMap::new(),
        }
    }

    fn new_windows() -> CorrelationWindows {
        std::sync::Arc::new(RwLock::new(HashMap::new()))
    }

    fn correlate(windows: &CorrelationWindows, cgroup_id: u64, ts: u64) -> String {
        let mut ev = test_event(cgroup_id, ts);
        assign_correlation(&mut ev, windows);
        ev.correlation_id
    }

    #[test]
    fn test_window_open_matches_during_call() {
        let w = new_windows();
        open_tool_window(&w, 7, "call-1", 1_000);
        assert_eq!(correlate(&w, 7, 1_500), "call-1");
        // Different cgroup never matches.
        assert_eq!(correlate(&w, 8, 1_500), "");
        // Before the window opened: no match.
        assert_eq!(correlate(&w, 7, 500), "");
    }

    #[test]
    fn test_window_closed_matches_late_drain_within_retention() {
        let w = new_windows();
        open_tool_window(&w, 7, "call-1", 1_000);
        assert!(close_tool_window(&w, 7, "call-1", 2_000));
        // Event generated during the call but drained after Complete still
        // correlates by kernel timestamp (SPEC §3.3).
        assert_eq!(correlate(&w, 7, 1_500), "call-1");
        // Event after Complete: outside the window, no correlation.
        assert_eq!(correlate(&w, 7, 2_500), "");
    }

    #[test]
    fn test_window_gap_between_calls_is_uncorrelated() {
        let w = new_windows();
        open_tool_window(&w, 7, "call-1", 1_000);
        assert!(close_tool_window(&w, 7, "call-1", 2_000));
        open_tool_window(&w, 7, "call-2", 5_000);
        // Background activity between Complete(1) and Prepare(2) belongs to
        // neither call.
        assert_eq!(correlate(&w, 7, 3_000), "");
        assert_eq!(correlate(&w, 7, 5_500), "call-2");
        assert_eq!(correlate(&w, 7, 1_500), "call-1");
    }

    #[test]
    fn test_window_lost_complete_bounded_by_horizon() {
        let w = new_windows();
        open_tool_window(&w, 7, "call-1", 1_000);
        // CompleteToolCall never arrives. Events within the horizon still
        // correlate...
        assert_eq!(correlate(&w, 7, 1_000 + OPEN_WINDOW_HORIZON_NS), "call-1");
        // ...but the window must not claim the rest of the session.
        assert_eq!(correlate(&w, 7, 1_001 + OPEN_WINDOW_HORIZON_NS), "");
    }

    #[test]
    fn test_window_prune_drops_dead_windows() {
        let w = new_windows();
        for i in 0..100u64 {
            open_tool_window(&w, 7, &format!("call-{i}"), 1_000 + i);
            assert!(close_tool_window(&w, 7, &format!("call-{i}"), 2_000 + i));
        }
        // A prepare long after retention prunes all the closed windows.
        let later = 2_099 + CLOSED_WINDOW_RETENTION_NS;
        open_tool_window(&w, 7, "fresh", later);
        assert_eq!(w.read().unwrap().get(&7).unwrap().len(), 1);

        // An abandoned open window is pruned once past the horizon.
        let much_later = later + OPEN_WINDOW_HORIZON_NS;
        open_tool_window(&w, 7, "fresher", much_later);
        let items: Vec<String> = w
            .read()
            .unwrap()
            .get(&7)
            .unwrap()
            .iter()
            .map(|x| x.correlation_id.clone())
            .collect();
        assert_eq!(items, vec!["fresher".to_string()]);
    }

    #[test]
    fn test_window_close_unknown_correlation_reports_mismatch() {
        let w = new_windows();
        open_tool_window(&w, 7, "call-1", 1_000);
        assert!(!close_tool_window(&w, 7, "ghost", 2_000));
        assert!(!close_tool_window(&w, 99, "call-1", 2_000));
        // Double-complete is a mismatch too.
        assert!(close_tool_window(&w, 7, "call-1", 2_000));
        assert!(!close_tool_window(&w, 7, "call-1", 2_100));
    }

    #[test]
    fn test_window_overlapping_calls_newest_first() {
        let w = new_windows();
        open_tool_window(&w, 7, "call-1", 1_000);
        open_tool_window(&w, 7, "call-2", 2_000);
        // In the overlap, the most recent window wins (maxConcurrentTools>1
        // ambiguity is resolved deterministically).
        assert_eq!(correlate(&w, 7, 2_500), "call-2");
        // Before call-2 opened, only call-1 can match.
        assert_eq!(correlate(&w, 7, 1_500), "call-1");
    }

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

    // --- PendingEvents: deferred correlation assignment (#prepare-race) ---

    #[test]
    fn test_pending_events_due_only_after_delay() {
        let mut p = PendingEvents::default();
        p.park(test_event(7, 1_000), 1_000);
        // Not due before the delay elapses.
        assert!(p
            .take_due(1_000 + CORRELATION_ASSIGN_DELAY_NS - 1)
            .is_empty());
        // Due exactly at the boundary; drain order preserved.
        p.park(test_event(7, 2_000), 2_000);
        let due = p.take_due(1_000 + CORRELATION_ASSIGN_DELAY_NS);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].timestamp_ns, 1_000);
        assert_eq!(p.next_due_ns(), Some(2_000 + CORRELATION_ASSIGN_DELAY_NS));
    }

    #[test]
    fn test_pending_events_take_all_flushes_regardless_of_due() {
        let mut p = PendingEvents::default();
        p.park(test_event(7, 1_000), 1_000);
        p.park(test_event(7, 2_000), 2_000);
        let all = p.take_all();
        assert_eq!(all.len(), 2, "shutdown flush must not drop parked events");
        assert!(p.next_due_ns().is_none());
    }

    /// The prepare-side race end-to-end at the logic level: an event drained
    /// BEFORE its PrepareToolCall window is recorded must still correlate,
    /// because assignment happens only after the park delay — by which time
    /// the window exists and the kernel timestamp matches it.
    #[test]
    fn test_parked_event_correlates_with_window_recorded_after_drain() {
        let w = new_windows();
        let mut p = PendingEvents::default();

        // t=1_000: kernel event generated and immediately drained — its
        // window is not recorded yet (Prepare is mid-flight).
        p.park(test_event(7, 1_000), 1_000);

        // t=1_050: PrepareToolCall lands, window start backdates to 990
        // (its timestamp was captured before the insert).
        open_tool_window(&w, 7, "call-1", 990);

        // Assignment at due time finds the window.
        let mut due = p.take_due(1_000 + CORRELATION_ASSIGN_DELAY_NS);
        assert_eq!(due.len(), 1);
        assign_correlation(&mut due[0], &w);
        assert_eq!(due[0].correlation_id, "call-1");
    }
}
