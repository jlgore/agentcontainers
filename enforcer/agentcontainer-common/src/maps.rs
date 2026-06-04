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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortKeyV4 {
    pub cgroup_id: u64,
    pub ip: u32,
    pub port: u16,
    pub protocol: u8,
    pub _pad: u8,
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
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecretAclValue {
    pub expires_at_ns: u64,
    pub allowed_ops: u8,
    pub _pad: [u8; 7],
}

// --- Permission constants ---

pub const FS_PERM_READ: u8 = 0x01;
pub const FS_PERM_WRITE: u8 = 0x02;

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

// --- aya Pod impls (userspace only) ---

// SAFETY: All types are #[repr(C)], Copy, and 'static — they satisfy Pod requirements.
// Pod is needed for aya's userspace HashMap/LpmTrie map operations.
#[cfg(target_os = "linux")]
mod pod_impls {
    unsafe impl aya::Pod for super::PortKeyV4 {}
    unsafe impl aya::Pod for super::FsInodeKey {}
    unsafe impl aya::Pod for super::SecretAclKey {}
    unsafe impl aya::Pod for super::SecretAclValue {}
    unsafe impl aya::Pod for super::LpmDataV4 {}
    unsafe impl aya::Pod for super::LpmDataV6 {}
    unsafe impl aya::Pod for super::CgroupStats {}
}
