use agentcontainer_common::maps::*;
use core::mem;

#[test]
fn test_lpm_cgroup_prefix() {
    // Every per-cgroup LPM insert/lookup uses prefix_len = 64 + cidr_bits.
    assert_eq!(LPM_CGROUP_PREFIX, 64);
}

#[test]
fn test_lpm_data_v4_layout() {
    // u64 cgroup_id + u32 addr + u32 explicit pad — 16 bytes.
    assert_eq!(mem::size_of::<LpmDataV4>(), 16);
    // cgroup_id MUST occupy the first 8 bytes so the 64-bit LPM prefix
    // covers it entirely before any address bits.
    assert_eq!(mem::offset_of!(LpmDataV4, cgroup_id), 0);
    assert_eq!(mem::offset_of!(LpmDataV4, addr), 8);
    assert_eq!(mem::offset_of!(LpmDataV4, _pad), 12);
}

#[test]
fn test_lpm_data_v6_layout() {
    // u64 cgroup_id + [u32; 4] addr — 24 bytes, no padding.
    assert_eq!(mem::size_of::<LpmDataV6>(), 24);
    assert_eq!(mem::offset_of!(LpmDataV6, cgroup_id), 0);
    assert_eq!(mem::offset_of!(LpmDataV6, addr), 8);
}

#[test]
fn test_lpm_data_cgroup_id_is_prefix() {
    // The first 8 bytes of the LPM data must be exactly the cgroup_id —
    // this is what makes the 64-bit prefix isolate cgroups from each other.
    let data = LpmDataV4 {
        cgroup_id: 0x1122_3344_5566_7788,
        addr: 0xAABB_CCDD,
        _pad: 0,
    };
    let bytes: [u8; 16] = unsafe { mem::transmute(data) };
    assert_eq!(
        u64::from_ne_bytes(bytes[..8].try_into().unwrap()),
        0x1122_3344_5566_7788
    );
    assert_eq!(
        u32::from_ne_bytes(bytes[8..12].try_into().unwrap()),
        0xAABB_CCDD
    );
}

#[test]
fn test_port_key_v4_layout() {
    // u64 cgroup_id + u32 ip + u16 port + u8 proto + u8 pad — 16 bytes.
    assert_eq!(mem::size_of::<PortKeyV4>(), 16);
    assert_eq!(mem::offset_of!(PortKeyV4, cgroup_id), 0);
    assert_eq!(mem::offset_of!(PortKeyV4, ip), 8);
    assert_eq!(mem::offset_of!(PortKeyV4, port), 12);
    assert_eq!(mem::offset_of!(PortKeyV4, protocol), 14);
    assert_eq!(mem::offset_of!(PortKeyV4, _pad), 15);
}

#[test]
fn test_fs_inode_key_layout() {
    // u64 inode + u32 major + u32 minor + u64 cgroup_id — 24 bytes,
    // byte-identical to SecretAclKey (intentional).
    assert_eq!(mem::size_of::<FsInodeKey>(), 24);
    assert_eq!(mem::offset_of!(FsInodeKey, inode), 0);
    assert_eq!(mem::offset_of!(FsInodeKey, dev_major), 8);
    assert_eq!(mem::offset_of!(FsInodeKey, dev_minor), 12);
    assert_eq!(mem::offset_of!(FsInodeKey, cgroup_id), 16);
    assert_eq!(mem::size_of::<FsInodeKey>(), mem::size_of::<SecretAclKey>());
    assert_eq!(
        mem::offset_of!(FsInodeKey, cgroup_id),
        mem::offset_of!(SecretAclKey, cgroup_id)
    );
}

#[test]
fn test_secret_acl_key_layout() {
    assert_eq!(mem::size_of::<SecretAclKey>(), 24);
}

#[test]
fn test_domain_key_layout() {
    // u64 cgroup_id + [u8; 16] hash — 24 bytes, no padding.
    assert_eq!(mem::size_of::<DomainKey>(), 24);
    assert_eq!(mem::offset_of!(DomainKey, cgroup_id), 0);
    assert_eq!(mem::offset_of!(DomainKey, hash), 8);
}

#[test]
fn test_domain_key_hash_matches_dns_parser() {
    // The userspace hash (siphash128_bytes over the lowercased dotted name)
    // must equal the BPF DNS parser's incremental label hashing.
    use agentcontainer_common::siphash::{DomainHasher, SipHashKey};
    let key = SipHashKey {
        k0: 0x0123_4567_89AB_CDEF,
        k1: 0xFEDC_BA98_7654_3210,
    };

    // Incremental, as the BPF parser feeds it: labels + dots, lowercased.
    let mut h = DomainHasher::new(&key);
    h.dot();
    for b in b"www" {
        h.write_byte(*b);
    }
    h.dot();
    for b in b"example" {
        h.write_byte(*b);
    }
    h.dot();
    for b in b"com" {
        h.write_byte(*b);
    }
    let incremental = h.finish128_bytes();

    // One-shot, as track_domain hashes policy hosts.
    use agentcontainer_common::siphash::siphash128_bytes;
    let oneshot = siphash128_bytes(&key, b"www.example.com");

    assert_eq!(incremental, oneshot);
}

#[test]
fn test_secret_acl_value_layout() {
    assert_eq!(mem::size_of::<SecretAclValue>(), 16);
}

#[test]
fn test_permission_constants() {
    assert_eq!(FS_PERM_READ, 0x01);
    assert_eq!(FS_PERM_WRITE, 0x02);
}

#[test]
fn test_verdict_constants() {
    assert_eq!(VERDICT_ALLOW, 1);
    assert_eq!(VERDICT_BLOCK, 0);
    assert_eq!(LSM_ALLOW, 0);
    assert_eq!(LSM_DENY, -13);
}
