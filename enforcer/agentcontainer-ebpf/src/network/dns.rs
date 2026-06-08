//! cgroup_skb/ingress hook for DNS response parsing.
//!
//! Intercepts inbound packets, identifies DNS responses (UDP port 53),
//! parses answer records, and emits events containing a SipHash-2-4 128-bit
//! digest of the domain name plus the resolved IP addresses.
//!
//! Gated by ENFORCED_CGROUPS like every other hook: the program is attached
//! at the cgroup root, so without the gate it would parse and SipHash every
//! DNS reply on the host. Packets whose socket cgroup is not enforced are
//! ignored before any parsing.
//!
//! Only emits events for domains present in the TRACKED_DOMAINS map — all
//! other DNS traffic is silently ignored, minimizing ring buffer bandwidth.
//!
//! Verifier design — the parser copies the DNS message into a per-CPU
//! scratch buffer with ONE bpf_skb_load_bytes call and parses from memory
//! with mask-bounded indices. Per-byte parsing through helper calls
//! (bpf_skb_load_bytes per byte, each a call plus error branch) multiplied
//! verifier states past the 1M processed-instruction budget — the program
//! never loaded on a real kernel. Replies longer than the scratch buffer
//! (512 bytes — classic UDP DNS; ample for A/AAAA answers) are parsed up
//! to the truncation point.
//!
//! Security properties:
//! - Keyed SipHash-128: negligible collision risk (birthday bound ~2^64).
//!   Replaces the old FNV-1a 32-bit approach (M2 fix).
//! - Compression pointers in the question name are rejected outright (the
//!   question is the first name in a message and cannot legally point
//!   anywhere); answer names are hopped, never followed (H1 fix).
//! - Observation-only: always returns 1 (allow). Never blocks DNS traffic.

use core::hash::Hasher;
use siphasher::sip128::{Hasher128, SipHasher24};

use aya_ebpf::macros::cgroup_skb;
use aya_ebpf::programs::SkBuffContext;

use agentcontainer_common::events::{
    DnsEvent, EventType, DNS_CLASS_IN, DNS_FLAG_QR, DNS_HEADER_SIZE, DNS_PORT, DNS_TYPE_A,
    DNS_TYPE_AAAA,
};
use agentcontainer_common::maps::DomainKey;

use crate::maps::{
    DNS_EVENTS, DNS_SCRATCH, DNS_SCRATCH_SIZE, ENFORCED_CGROUPS, SIPHASH_KEY, TRACKED_DOMAINS,
};

// ---------------------------------------------------------------------------
// IP protocol constants.
// ---------------------------------------------------------------------------
const IPPROTO_UDP: u8 = 17;
const IP_HEADER_MIN_SIZE: usize = 20;
const IP6_HEADER_SIZE: usize = 40;
const UDP_HEADER_SIZE: usize = 8;

// Bounded loop limits for BPF verifier compliance. Parsing runs against the
// in-memory scratch buffer (cheap per iteration), but the unrolled totals
// still count — keep these proportionate.
/// Question-name walk budget (bytes traversed). The RFC ceiling is 255,
/// but every traversed byte multiplies verifier exploration — at 255 the
/// program exceeds the 1M processed-instruction budget and cannot load.
/// 120 covers all realistic policy hostnames (Kubernetes FQDNs and cloud
/// LB names run ~60-70 octets); longer names abort parsing (no event).
const MAX_NAME_BYTES: usize = 120;
/// Fixed width of the buffer the question name is hashed over. The name is
/// copied in and the remainder stays zero, and SipHash always runs over
/// exactly this many bytes — a COMPILE-TIME-CONSTANT length, which is what
/// makes the digest viable in BPF: a runtime-length `hasher.write` emits
/// SipHash's data-dependent 0..7-byte tail handling, whose branch product
/// blew the verifier's 8192-jump limit. A constant length unrolls to a
/// fixed sequence of 8-byte reads with no tail branch. Userspace
/// (track_domain) hashes the identical zero-padded fixed-width buffer.
const HASH_NAME_LEN: usize = 128;
const MAX_LABEL_BYTES: usize = 63;
/// Labels per name in the answer-section skip walk (one iteration per
/// label). Real hostnames have well under 16 labels; names exceeding this
/// abort parsing (no event).
const MAX_SKIP_LABELS: usize = 16;
/// Answer records examined per response — the first 8 resolved addresses
/// are ample for egress observation of a tracked domain.
const MAX_ANSWERS: usize = 8;

// ---------------------------------------------------------------------------
// Scratch buffer access. `n` is the number of valid bytes copied from the
// packet; every read is double-bounded — a constant compare for the
// verifier, the `n` compare for parsing correctness.
// ---------------------------------------------------------------------------

// The asm masks below hard-code the buffer sizes; keep them in lockstep.
const _: () = assert!(DNS_SCRATCH_SIZE == 512);
const _: () = assert!(HASH_NAME_LEN == 128);

/// Branch-free scratch read. The buffer is zero-filled before the packet
/// copy, so reads past the message see zeros (which self-terminate name
/// walks and fail record checks) — no per-byte length compare needed. A
/// length compare per read forked verifier state at every access and blew
/// the 1M processed-instruction budget; a plain Rust mask gets deleted by
/// LLVM as provably redundant. The inline-asm mask is opaque to LLVM but
/// hands the verifier a hard constant bound on the exact load register.
#[inline(always)]
fn bget(buf: &[u8; DNS_SCRATCH_SIZE], i: usize) -> u8 {
    let mut idx = i;
    unsafe {
        core::arch::asm!("{idx} &= 511", idx = inout(reg) idx);
        *buf.as_ptr().add(idx)
    }
}

#[inline(always)]
fn bget_u16(buf: &[u8; DNS_SCRATCH_SIZE], i: usize) -> u16 {
    ((bget(buf, i) as u16) << 8) | bget(buf, i + 1) as u16
}

#[inline(always)]
fn bget_u32(buf: &[u8; DNS_SCRATCH_SIZE], i: usize) -> u32 {
    ((bget(buf, i) as u32) << 24)
        | ((bget(buf, i + 1) as u32) << 16)
        | ((bget(buf, i + 2) as u32) << 8)
        | bget(buf, i + 3) as u32
}

/// Masked write into the fixed-width hash buffer — the write mirror of
/// `bget`. The loop counter is provably < MAX_NAME_BYTES (120) < 128, but
/// the verifier loses that bound across LLVM's index arithmetic and rejects
/// the store; the opaque asm mask restores a hard constant bound (128 is a
/// power of two so the mask is a logical no-op for in-range indices).
#[inline(always)]
fn bset_name(buf: &mut [u8; HASH_NAME_LEN], i: usize, v: u8) {
    let mut idx = i;
    unsafe {
        core::arch::asm!("{idx} &= 127", idx = inout(reg) idx);
        *buf.as_mut_ptr().add(idx) = v;
    }
}

/// Load one byte straight from the skb. Used only for the fixed-offset
/// IP/UDP header fields ahead of the scratch copy.
#[inline(always)]
fn load_byte(ctx: &SkBuffContext, offset: usize) -> Option<u8> {
    ctx.load::<u8>(offset).ok()
}

#[inline(always)]
fn load_u16_be(ctx: &SkBuffContext, offset: usize) -> Option<u16> {
    let hi = ctx.load::<u8>(offset).ok()? as u16;
    let lo = ctx.load::<u8>(offset + 1).ok()? as u16;
    Some((hi << 8) | lo)
}

// ---------------------------------------------------------------------------
// DNS name handling against the scratch buffer. Offsets are DNS-message
// relative, which is exactly what compression pointers encode — no
// translation needed.
// ---------------------------------------------------------------------------

struct DnsHashResult {
    end_offset: usize,
    hash: [u8; 16],
}

/// Hash the QUESTION name. Two phases, both with single-counter loops —
/// the verifier-friendly shape. Phase 1 hops label-to-label to find the
/// name's end (16 hops max, tiny state). Phase 2 copies the raw wire-format
/// bytes (length-prefixed labels), lowercased, into a stack buffer and
/// SipHashes it once.
///
/// The digest is over the RAW WIRE FORMAT, not a dotted string — userspace
/// track_domain encodes policy hostnames the same way. Hashing wire bytes
/// is what makes a single copy loop possible: a dotted-string walk needs
/// per-byte label bookkeeping whose (offset, label_remaining, name_len)
/// state product blew the verifier's 1M-instruction budget at every size
/// we tried.
///
/// Compression pointers are rejected, not followed: the question is the
/// FIRST name in a DNS message, so there is nothing earlier for it to
/// point at — a pointer here is malformed (or adversarial) traffic.
#[inline(always)]
fn hash_dns_name(
    buf: &[u8; DNS_SCRATCH_SIZE],
    start_offset: usize,
    k0: u64,
    k1: u64,
) -> Option<DnsHashResult> {
    // Phase 1: hop labels to find the terminator.
    let mut offset = start_offset;
    let mut end: usize = 0;
    for _i in 0..MAX_SKIP_LABELS {
        if offset >= DNS_SCRATCH_SIZE {
            return None;
        }
        let label_len = bget(buf, offset);
        if label_len == 0 {
            end = offset; // terminator (root byte) excluded from the hash
            break;
        }
        if (label_len & 0xC0) == 0xC0 {
            return None; // pointer in a question name: malformed
        }
        if label_len as usize > MAX_LABEL_BYTES {
            return None;
        }
        offset += 1 + label_len as usize;
    }
    if end == 0 || end <= start_offset {
        return None;
    }

    let total = end - start_offset;
    if total > MAX_NAME_BYTES {
        return None;
    }

    // Phase 2: copy + lowercase into a FIXED-width zero-padded buffer, then
    // hash the whole buffer at a compile-time-constant length (see
    // HASH_NAME_LEN). Label-length prefix bytes are <= 63 and ASCII letters
    // start at 65, so blanket lowercasing can never corrupt a length byte.
    let mut name_buf = [0u8; HASH_NAME_LEN];
    for k in 0..MAX_NAME_BYTES {
        if k >= total {
            break;
        }
        let ch = bget(buf, start_offset + k);
        bset_name(
            &mut name_buf,
            k,
            if ch.is_ascii_uppercase() { ch + 32 } else { ch },
        );
    }

    let mut hasher = SipHasher24::new_with_keys(k0, k1);
    hasher.write(&name_buf);
    let hash = hasher.finish128().as_u128().to_ne_bytes();
    Some(DnsHashResult {
        end_offset: end + 1,
        hash,
    })
}

/// Skip a DNS name without hashing. Used for answer-record name fields —
/// the domain hash already comes from the question.
#[inline(always)]
fn skip_dns_name(buf: &[u8; DNS_SCRATCH_SIZE], start_offset: usize) -> Option<usize> {
    let mut offset = start_offset;
    let mut end_offset: usize = 0;

    // One iteration per LABEL (the loop advances by 1 + len), so the bound
    // is a label count, not a byte count — this loop runs once per answer
    // record and its unrolled size multiplies accordingly.
    for _i in 0..MAX_SKIP_LABELS {
        if offset >= DNS_SCRATCH_SIZE {
            return None;
        }
        let label_len = bget(buf, offset);

        if label_len == 0 {
            if end_offset == 0 {
                end_offset = offset + 1;
            }
            break;
        }

        if (label_len & 0xC0) == 0xC0 {
            if end_offset == 0 {
                end_offset = offset + 2;
            }
            break;
        }

        let len = label_len as usize;
        if len > MAX_LABEL_BYTES {
            return None;
        }
        offset += 1 + len;
    }

    if end_offset == 0 {
        return None;
    }

    Some(end_offset)
}

// ---------------------------------------------------------------------------
// Entry point.
// ---------------------------------------------------------------------------

#[cgroup_skb(ingress)]
pub fn ac_dns_ingress(ctx: SkBuffContext) -> i32 {
    match try_parse_dns(&ctx) {
        Ok(_) => 1,  // Always allow
        Err(_) => 1, // Always allow — DNS ingress is observation only
    }
}

#[inline(always)]
fn try_parse_dns(ctx: &SkBuffContext) -> Result<(), ()> {
    // 0. Cgroup scoping: the hook is attached at the cgroup root, so it
    //    sees every socket on the host. Bail before any parsing unless the
    //    packet belongs to an enforced container — parsing + SipHashing
    //    every DNS reply host-wide is both wasted cycles and observation
    //    of traffic the enforcer has no business looking at.
    //    cgroup_skb runs in softirq context, so the *current task* cgroup
    //    is unrelated — use the skb's socket cgroup instead.
    let cgroup_id = unsafe { aya_ebpf::helpers::bpf_skb_cgroup_id(ctx.skb.skb) };
    if unsafe { ENFORCED_CGROUPS.get(&cgroup_id) }.is_none() {
        return Ok(());
    }

    let pkt_len = ctx.len() as usize;

    // Load SipHash key from BPF map. If not set, skip DNS processing.
    let key = unsafe { SIPHASH_KEY.get(0).ok_or(())? };

    // Determine IP version from the first nibble.
    let ver_byte = load_byte(ctx, 0).ok_or(())?;
    let ip_version = (ver_byte >> 4) & 0xF;

    let udp_offset: usize;

    if ip_version == 4 {
        if pkt_len < IP_HEADER_MIN_SIZE + UDP_HEADER_SIZE + DNS_HEADER_SIZE {
            return Err(());
        }
        let ihl = ((ver_byte & 0x0F) as usize) * 4;
        if ihl < IP_HEADER_MIN_SIZE || ihl > 60 {
            return Err(());
        }
        let ip_proto = load_byte(ctx, 9).ok_or(())?;
        if ip_proto != IPPROTO_UDP {
            return Err(());
        }
        udp_offset = ihl;
    } else if ip_version == 6 {
        if pkt_len < IP6_HEADER_SIZE + UDP_HEADER_SIZE + DNS_HEADER_SIZE {
            return Err(());
        }
        let ip_proto = load_byte(ctx, 6).ok_or(())?;
        if ip_proto != IPPROTO_UDP {
            return Err(());
        }
        udp_offset = IP6_HEADER_SIZE;
    } else {
        return Err(());
    }

    // Check source port == 53 (DNS response).
    let src_port = load_u16_be(ctx, udp_offset).ok_or(())?;
    if src_port != DNS_PORT {
        return Err(());
    }

    let dns_offset = udp_offset + UDP_HEADER_SIZE;
    if pkt_len < dns_offset + DNS_HEADER_SIZE {
        return Err(());
    }

    // Copy the DNS message into the per-CPU scratch buffer in ONE helper
    // call; everything below parses from memory. Zero-fill first: bytes
    // past the message read as zeros (self-terminating for name walks,
    // failing for record checks), which is what lets the accessors skip a
    // per-read length compare — stale bytes from a previous packet must
    // never influence parsing.
    let avail = pkt_len - dns_offset;
    let n = if avail > DNS_SCRATCH_SIZE {
        DNS_SCRATCH_SIZE
    } else {
        avail
    };
    let scratch = unsafe { DNS_SCRATCH.get_ptr_mut(0).ok_or(())? };
    let buf = unsafe { &mut (*scratch).data };
    // Zero in u64 strides — the byte-wise memset lowering costs the
    // verifier 8x the iterations for the same effect.
    let words = buf.as_mut_ptr() as *mut u64;
    for w in 0..(DNS_SCRATCH_SIZE / 8) {
        unsafe { words.add(w).write(0) };
    }
    let rc = unsafe {
        aya_ebpf::helpers::gen::bpf_skb_load_bytes(
            ctx.skb.skb as *const core::ffi::c_void,
            dns_offset as u32,
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            n as u32,
        )
    };
    if rc != 0 {
        return Err(());
    }
    let buf: &[u8; DNS_SCRATCH_SIZE] = buf;

    // DNS header: flags, qdcount, ancount (message-relative offsets).
    let flags = bget_u16(buf, 2);
    if (flags & DNS_FLAG_QR) == 0 {
        return Err(()); // Not a response
    }

    let qdcount = bget_u16(buf, 4);
    let ancount = bget_u16(buf, 6);

    // Single-question responses only — which is every response a real
    // resolver produces (multi-question queries are unsupported by
    // mainstream servers). Skipping extra questions cost a per-question
    // name walk whose unrolled size pushed the program over the
    // verifier's branch budget.
    if qdcount != 1 {
        return Err(());
    }

    // Hash the question's domain name with SipHash-2-4 128-bit.
    let hash_result = hash_dns_name(buf, DNS_HEADER_SIZE, key.k0, key.k1).ok_or(())?;
    let domain_hash: [u8; 16] = hash_result.hash;

    // Skip past QTYPE + QCLASS (end_offset is already past the name's
    // terminator).
    let mut pos = hash_result.end_offset + 4;

    // Check if this domain is tracked for the cgroup that owns this socket
    // (resolved at the top of the function).
    let tracked_key = DomainKey {
        cgroup_id,
        hash: domain_hash,
    };
    let tracked = unsafe { TRACKED_DOMAINS.get(&tracked_key) };
    if tracked.is_none() {
        return Ok(()); // Not a tracked domain for this cgroup, silently ignore
    }

    // Parse answer section for A and AAAA records.
    for a in 0..MAX_ANSWERS {
        if a >= ancount as usize {
            break;
        }
        if pos >= DNS_SCRATCH_SIZE {
            break;
        }

        let name_end = skip_dns_name(buf, pos).ok_or(())?;
        pos = name_end;

        // TYPE (2) + CLASS (2) + TTL (4) + RDLENGTH (2) = 10 bytes.
        let rtype = bget_u16(buf, pos);
        let rclass = bget_u16(buf, pos + 2);
        let ttl = bget_u32(buf, pos + 4);
        let rdlength = bget_u16(buf, pos + 8);
        pos += 10;

        if rclass != DNS_CLASS_IN {
            pos += rdlength as usize;
            continue;
        }

        if rtype == DNS_TYPE_A && rdlength == 4 {
            if let Some(mut entry) = DNS_EVENTS.reserve::<DnsEvent>(0) {
                let ev = entry.as_mut_ptr();
                unsafe {
                    zero_dns_event(ev);
                    (*ev).event_type = EventType::DnsResponse as u32;
                    (*ev).ttl = ttl;
                    (*ev).cgroup_id = cgroup_id;
                    (*ev).record_type = DNS_TYPE_A as u8;
                    (*ev).domain_hash = domain_hash;

                    for k in 0..4 {
                        (*ev).addr_v4[k] = bget(buf, pos + k);
                    }
                    entry.submit(0);
                }
            }
        } else if rtype == DNS_TYPE_AAAA && rdlength == 16 {
            if let Some(mut entry) = DNS_EVENTS.reserve::<DnsEvent>(0) {
                let ev = entry.as_mut_ptr();
                unsafe {
                    zero_dns_event(ev);
                    (*ev).event_type = EventType::DnsResponse as u32;
                    (*ev).ttl = ttl;
                    (*ev).cgroup_id = cgroup_id;
                    (*ev).record_type = DNS_TYPE_AAAA as u8;
                    (*ev).domain_hash = domain_hash;

                    for k in 0..16 {
                        (*ev).addr_v6[k] = bget(buf, pos + k);
                    }
                    entry.submit(0);
                }
            }
        }

        pos += rdlength as usize;
    }

    Ok(())
}

/// Zero-initialize a DnsEvent at a raw pointer (ring buffer memory).
#[inline(always)]
unsafe fn zero_dns_event(ev: *mut DnsEvent) {
    (*ev).timestamp_ns = 0;
    (*ev).pid = 0;
    (*ev).uid = 0;
    (*ev).event_type = 0;
    (*ev).ttl = 0;
    (*ev).domain_hash = [0u8; 16];
    (*ev).record_type = 0;
    (*ev)._pad = [0; 3];
    for i in 0..4 {
        (*ev).addr_v4[i] = 0;
    }
    for i in 0..16 {
        (*ev).addr_v6[i] = 0;
    }
}
