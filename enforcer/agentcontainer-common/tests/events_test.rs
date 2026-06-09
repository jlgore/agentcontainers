use agentcontainer_common::events::*;

#[test]
fn test_event_type_values() {
    assert_eq!(EventType::NetworkConnect as u32, 1);
    assert_eq!(EventType::DnsResponse as u32, 2);
    assert_eq!(EventType::FsOpen as u32, 3);
    assert_eq!(EventType::ProcessExec as u32, 4);
    assert_eq!(EventType::CredentialAccess as u32, 5);
}

#[test]
fn test_verdict_values() {
    assert_eq!(Verdict::Allow as u32, 0);
    assert_eq!(Verdict::Block as u32, 1);
}

#[test]
fn test_dns_event_carries_qname() {
    let mut qname = [0u8; DNS_QNAME_MAX];
    // wire format for "example.com": 7 'example' 3 'com'
    let wire = b"\x07example\x03com";
    qname[..wire.len()].copy_from_slice(wire);
    let evt = DnsEvent {
        timestamp_ns: 1,
        pid: 2,
        uid: 3,
        event_type: 0,
        ttl: 60,
        cgroup_id: 99,
        addr_v4: [93, 184, 216, 34],
        addr_v6: [0; 16],
        record_type: 1,
        qname_len: wire.len() as u8,
        _pad: [0; 2],
        qname,
    };
    assert_eq!(&evt.qname[..evt.qname_len as usize], wire);

    // DnsEvent layout: u64-aligned, qname dominates the size.
    let size = core::mem::size_of::<DnsEvent>();
    assert_eq!(
        size, 184,
        "DnsEvent should be exactly 184 bytes, got {}",
        size
    );
}

#[test]
fn test_exec_event_has_binary_path() {
    assert_eq!(PATH_MAX, 256);
    let evt = ExecEvent {
        timestamp_ns: 0,
        pid: 0,
        uid: 0,
        event_type: EventType::ProcessExec as u32,
        verdict: Verdict::Block as u32,
        cgroup_id: 42,
        inode: 42,
        comm: [0u8; COMM_MAX],
        binary: [0u8; PATH_MAX],
    };
    assert_eq!(evt.inode, 42);
}

#[test]
fn test_stat_key_values() {
    assert_eq!(STAT_NET_ALLOWED, 0);
    assert_eq!(STAT_NET_BLOCKED, 1);
    assert_eq!(STAT_FS_ALLOWED, 2);
    assert_eq!(STAT_FS_BLOCKED, 3);
    assert_eq!(STAT_PROC_ALLOWED, 4);
    assert_eq!(STAT_PROC_BLOCKED, 5);
}

#[test]
fn test_dns_constants() {
    assert_eq!(DNS_PORT, 53);
    assert_eq!(DNS_HEADER_SIZE, 12);
    assert_eq!(DNS_TYPE_A, 1);
    assert_eq!(DNS_TYPE_AAAA, 28);
    assert_eq!(DNS_CLASS_IN, 1);
    assert_eq!(DNS_FLAG_QR, 0x8000);
    assert_eq!(MAX_COMPRESSION_JUMPS, 8);
}
