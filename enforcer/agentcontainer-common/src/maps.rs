//! BPF map key and value types shared between kernel and userspace.
//!
//! These types must have a stable memory layout (`repr(C)`) and match exactly
//! between the BPF programs and the userspace map operations.

// --- Network map keys ---

/// Number of leading LPM prefix bits consumed by the cgroup_id in the
/// per-cgroup LPM data payloads below. Every insert and lookup MUST use
/// `prefix_len = LPM_CGROUP_PREFIX + cidr_bits` — a prefix shorter than
/// 64 would treat the cgroup bits as wildcards and match across cgroups.
pub const LPM_CGROUP_PREFIX: u32 = 64;

/// LPM trie data payload for IPv4, scoped per-cgroup.
///
/// `cgroup_id` MUST be the first field: longest-prefix matching consumes
/// all 64 cgroup bits before any address bits, so entries for different
/// cgroups can never cross-match. This is the `data` inside aya's
/// `Key<K>` wrapper (which supplies `prefix_len`), not the full key.
/// Size = 16 bytes (`_pad` makes the u64-alignment tail padding explicit
/// and zeroed; it sits beyond the max 96-bit prefix and never matches).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LpmDataV4 {
    pub cgroup_id: u64,
    pub addr: u32,
    pub _pad: u32,
}

/// LPM trie data payload for IPv6, scoped per-cgroup.
/// Size = 24 bytes, no padding. Max prefix = 64 + 128 = 192.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LpmDataV6 {
    pub cgroup_id: u64,
    pub addr: [u32; 4],
}

/// Key for the allowed ports hash map (IPv4), scoped per-cgroup.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PortKeyV4 {
    pub cgroup_id: u64,
    pub ip: u32,
    pub port: u16,
    pub protocol: u8,
    pub _pad: u8,
}

/// Key for the transient-egress hash map (IPv6), scoped per-cgroup. The IPv6
/// analogue of `PortKeyV4` for URI-scoped egress (G4). `addr` is the 128-bit
/// destination in the same `[u32; 4]` network-byte-order representation the
/// connect6 hook reads from `user_ip6` (and that `LpmDataV6` uses).
///
/// Size = 32 bytes. ALL padding is explicit (`_pad`/`_pad2`) and MUST be zeroed
/// by every producer: the BPF hash map keys on the full 32 bytes, so an
/// uninitialized pad byte on either side would make a lookup miss. There is no
/// implicit padding (8 + 16 + 2 + 1 + 1 + 4 = 32, u64-aligned).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PortKeyV6 {
    pub cgroup_id: u64,
    pub addr: [u32; 4],
    pub port: u16,
    pub protocol: u8,
    pub _pad: u8,
    pub _pad2: u32,
}

/// Key for the tracked-domains DNS observation map, scoped per-cgroup.
/// `hash` is the SipHash-2-4 128-bit digest of the lowercased dotted
/// domain name (see `siphash::DomainHasher`). Size = 24 bytes, no padding.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DomainKey {
    pub cgroup_id: u64,
    pub hash: [u8; 16],
}

// --- Filesystem map keys ---

/// Key for the filesystem inode allow/deny maps, scoped per-cgroup.
/// Field order matches `SecretAclKey` (cgroup_id last) — both are
/// 24 bytes with identical layout.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FsInodeKey {
    pub inode: u64,
    pub dev_major: u32,
    pub dev_minor: u32,
    pub cgroup_id: u64,
}

// --- Credential map keys ---

/// Key for credential/secret ACL enforcement.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecretAclKey {
    pub inode: u64,
    pub dev_major: u32,
    pub dev_minor: u32,
    pub cgroup_id: u64,
}

/// Value for credential/secret ACL entries.
///
/// `restricted` is 1 when the secret declares a non-empty allowed-tools list:
/// the file_open hook then additionally requires an active, allowed tool-call
/// window (see `SecretToolKey` / the `ACTIVE_TOOL` map). When 0 the secret is
/// container-wide (any code in the cgroup may read it, subject to TTL/write).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecretAclValue {
    pub expires_at_ns: u64,
    pub allowed_ops: u8,
    pub restricted: u8,
    pub _pad: [u8; 6],
}

/// Key for the per-secret allowed-tool set (`SECRET_TOOL_ACLS`). Presence of an
/// entry means the tool identified by `tool_id` may read the secret identified
/// by the embedded `SecretAclKey` fields while that tool's call window is active.
/// The leading fields mirror `SecretAclKey` exactly so a secret's tool entries
/// share its `(inode, dev, cgroup)` identity.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecretToolKey {
    pub inode: u64,
    pub dev_major: u32,
    pub dev_minor: u32,
    pub cgroup_id: u64,
    pub tool_id: u64,
}

/// Value for the `ACTIVE_TOOL` map: the tool identity currently executing in a
/// cgroup, plus a monotonic-clock (`CLOCK_MONOTONIC` / `bpf_ktime_get_ns`)
/// expiry. The expiry bounds the blast radius of a lost CompleteToolCall — past
/// it, file_open treats the tool-call window as closed and denies the secret.
/// `expires_at_ns == 0` means no expiry.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActiveTool {
    pub tool_id: u64,
    pub expires_at_ns: u64,
}

/// A stable 64-bit identity for an MCP tool name. The enforcer derives both the
/// allowed-tool entries (from a secret's allowed-tools list) and the active-tool
/// value (from PrepareToolCall's tool name) with [`tool_identity`], so equal
/// names always yield equal identities within the process.
pub type ToolId = u64;

/// Fixed SipHash key for deriving tool identities. The value is irrelevant as
/// long as it is constant: identities are only ever compared against other
/// identities produced by the same call in the same enforcer process.
const TOOL_ID_KEY: crate::siphash::SipHashKey = crate::siphash::SipHashKey {
    k0: 0x7361_6665_5f74_6f6f, // "safe_too"
    k1: 0x6c5f_6964_656e_7469, // "l_identi"
};

/// Derive the stable [`ToolId`] for an MCP tool name.
pub fn tool_identity(name: &str) -> ToolId {
    crate::siphash::siphash128(&TOOL_ID_KEY, name.as_bytes()) as u64
}

// --- Permission constants ---

pub const FS_PERM_READ: u8 = 0x01;
pub const FS_PERM_WRITE: u8 = 0x02;

// --- ENFORCED_CGROUPS flags ---
//
// The value of each `ENFORCED_CGROUPS` entry is a bitmask of which enforcement
// domains apply to that cgroup. Mere presence in the map (the `ENFORCED` bit)
// activates the always-on hooks (network egress, filesystem deny-list). The
// `EXEC_ENFORCED` bit is OPT-IN: it is set only when a NON-EMPTY exec allowlist
// is applied to the cgroup, so the bprm_check allowlist gates execs only for
// cgroups that asked for it. Proxy-launched tool-runner backends (which never
// receive an exec allowlist) are left ungated and can spawn their own
// sub-processes; network/filesystem/readonly-rootfs/cap-drop still confine them.

/// The cgroup is enforced (registered) — network + filesystem hooks apply.
pub const CGROUP_FLAG_ENFORCED: u8 = 0x01;
/// The cgroup has a non-empty exec allowlist; bprm_check authorizes its execs.
pub const CGROUP_FLAG_EXEC_ENFORCED: u8 = 0x02;

// --- Per-cgroup statistics ---

/// Per-cgroup enforcement statistics tracked in BPF per-CPU hash maps.
///
/// Each enforced cgroup gets one entry in the `CGROUP_STATS` per-CPU hash map.
/// BPF programs increment the relevant counter on each enforcement decision.
/// Userspace sums across CPUs to get totals.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CgroupStats {
    pub network_allowed: u64,
    pub network_blocked: u64,
    pub filesystem_allowed: u64,
    pub filesystem_blocked: u64,
    pub process_allowed: u64,
    pub process_blocked: u64,
    pub credential_allowed: u64,
    pub credential_blocked: u64,
}

// --- Verdicts ---

pub const VERDICT_ALLOW: i32 = 1;
pub const VERDICT_BLOCK: i32 = 0;

// --- LSM verdicts ---

pub const LSM_ALLOW: i32 = 0;
pub const LSM_DENY: i32 = -13; // -EACCES

// --- Procfs ---

pub const PROC_SUPER_MAGIC: u64 = 0x9fa0;
pub const DENTRY_NAME_LEN: usize = 32;

// --- Kernel struct field offsets (CO-RE substitute) ---

/// Byte offsets of the kernel struct fields the LSM hooks walk, resolved from
/// the running kernel's BTF in userspace at startup and published to the eBPF
/// programs via the single-entry `KERNEL_OFFSETS` array map.
///
/// The Rust eBPF toolchain emits no CO-RE field relocations (aya-ebpf 0.1.x),
/// so hardcoded `#[repr(C)]` mirror offsets silently break across kernel
/// versions — e.g. `linux_binprm`'s first field is `vma`, not `file`, on 6.x.
/// Resolving offsets from BTF and reading `base + offset` is portable across
/// 5.15–6.x. All values are byte offsets.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct KernelOffsets {
    pub binprm_file: u32,   // linux_binprm.file       (*file)
    pub file_f_inode: u32,  // file.f_inode            (*inode)  — stable since v3.9
    pub file_f_path: u32,   // file.f_path             (struct path, embedded)
    pub file_f_flags: u32,  // file.f_flags            (u32)
    pub path_dentry: u32,   // path.dentry             (*dentry)
    pub dentry_d_name: u32, // dentry.d_name          (struct qstr, embedded)
    pub qstr_name: u32,     // qstr.name               (*u8)
    pub inode_i_ino: u32,   // inode.i_ino             (unsigned long)
    pub inode_i_sb: u32,    // inode.i_sb              (*super_block)
    pub sb_s_dev: u32,      // super_block.s_dev       (dev_t / u32)
    pub sb_s_magic: u32,    // super_block.s_magic     (unsigned long)
}

// --- aya Pod impls (userspace only) ---

// SAFETY: All types are #[repr(C)], Copy, and 'static — they satisfy Pod requirements.
// Pod is needed for aya's userspace HashMap/LpmTrie map operations.
#[cfg(target_os = "linux")]
mod pod_impls {
    unsafe impl aya::Pod for super::PortKeyV4 {}
    unsafe impl aya::Pod for super::PortKeyV6 {}
    unsafe impl aya::Pod for super::FsInodeKey {}
    unsafe impl aya::Pod for super::SecretAclKey {}
    unsafe impl aya::Pod for super::SecretAclValue {}
    unsafe impl aya::Pod for super::SecretToolKey {}
    unsafe impl aya::Pod for super::ActiveTool {}
    unsafe impl aya::Pod for super::LpmDataV4 {}
    unsafe impl aya::Pod for super::LpmDataV6 {}
    unsafe impl aya::Pod for super::DomainKey {}
    unsafe impl aya::Pod for super::CgroupStats {}
    unsafe impl aya::Pod for super::KernelOffsets {}
    unsafe impl aya::Pod for crate::siphash::SipHashKey {}
}

#[cfg(test)]
mod tests {
    use super::tool_identity;

    #[test]
    fn tool_identity_is_deterministic() {
        assert_eq!(tool_identity("run_command"), tool_identity("run_command"));
        assert_eq!(
            tool_identity("mcp__sift__run_command"),
            tool_identity("mcp__sift__run_command")
        );
    }

    #[test]
    fn tool_identity_distinguishes_names() {
        assert_ne!(tool_identity("read_file"), tool_identity("write_file"));
        assert_ne!(tool_identity("run_command"), tool_identity("run_command "));
        assert_ne!(tool_identity(""), tool_identity("x"));
    }
}
