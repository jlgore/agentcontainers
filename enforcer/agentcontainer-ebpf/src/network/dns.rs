//! cgroup_skb/ingress hook for DNS response parsing.
//!
//! Intercepts inbound packets, identifies DNS responses (UDP port 53), and
//! emits one event per A/AAAA answer record carrying the resolved address
//! plus the question name in raw DNS wire format.
//!
//! Gated by ENFORCED_CGROUPS: the program is attached at the cgroup root,
//! so it sees every socket on the host. Packets whose socket cgroup is not
//! enforced are dropped before any parsing. Within an enforced cgroup every
//! DNS response is emitted — userspace matches the question name against
//! its per-cgroup tracked-domain set and discards the rest. Domain
//! identification (and any hashing) lives in userspace: an in-kernel
//! SipHash over a variable-length name exceeded the BPF verifier's
//! complexity budget, so the kernel does only a bounded copy.
//!
//! Verifier design — the parser copies the DNS message into a per-CPU
//! scratch buffer with ONE bpf_skb_load_bytes call and parses from memory
//! with mask-bounded indices. Per-byte skb helper loads (a call plus error
//! branch each) multiplied verifier states past the budget. Replies longer
//! than the scratch buffer (512 bytes — classic UDP DNS) are parsed up to
//! the truncation point.

use aya_ebpf::macros::cgroup_skb;
use aya_ebpf::programs::SkBuffContext;

use agentcontainer_common::events::{
    DnsEvent, EventType, DNS_CLASS_IN, DNS_FLAG_QR, DNS_HEADER_SIZE, DNS_PORT, DNS_QNAME_MAX,
    DNS_TYPE_A, DNS_TYPE_AAAA,
};

use crate::maps::{DNS_EVENTS, DNS_SCRATCH, DNS_SCRATCH_SIZE, ENFORCED_CGROUPS};

// ---------------------------------------------------------------------------
// IP protocol constants.
// ---------------------------------------------------------------------------
const IPPROTO_UDP: u8 = 17;
const IP_HEADER_MIN_SIZE: usize = 20;
const IP6_HEADER_SIZE: usize = 40;
const UDP_HEADER_SIZE: usize = 8;

// Bounded loop limits. Parsing runs against the in-memory scratch buffer
// (cheap per iteration), but unrolled totals still count.
const MAX_LABEL_BYTES: usize = 63;
/// Labels in the question name (copy_qname). Walked once per reply, so a
/// generous budget is cheap; covers deep subdomains without dropping the event.
const MAX_QNAME_LABELS: usize = 16;
/// Labels per answer-record name walk (skip_dns_name). Kept small: real answer
/// names are 2-byte compression pointers, the walk runs once per answer record,
/// and each label iteration forks verifier states (cost scales with MAX_ANSWERS).
const MAX_SKIP_LABELS: usize = 8;
/// Answer records examined per response. Even with clamp_off normalizing the
/// parse offset each iteration, each answer's name walk + record parse is a
/// sizable chunk of the verifier's 1M-insn budget: 4 loads with margin, 6 blows
/// the budget. Bounded here at 4 (covers a CNAME plus a few A/AAAA records);
/// longer answer sections are parsed up to this many records, and the userspace
/// filtering resolver (SPEC §14) is the compensating control for the remainder.
const MAX_ANSWERS: usize = 4;

// The asm masks below hard-code the buffer sizes; keep them in lockstep.
const _: () = assert!(DNS_SCRATCH_SIZE == 512);
const _: () = assert!(DNS_QNAME_MAX == 128);

// ---------------------------------------------------------------------------
// Scratch buffer access. The buffer is zero-filled before the packet copy,
// so reads past the message see zeros (self-terminating for name walks,
// failing record checks) — no per-read length compare needed. The inline-asm
// mask, not any Rust bound, is what the verifier trusts: reg-reg bounds are
// lost across LLVM spill/reload, but a constant mask on the access register
// is a hard bound (power-of-two mask) it cannot lose.
// ---------------------------------------------------------------------------

/// AND `i` down to `[0, mask]` (mask a power-of-two-minus-one) with a mask the
/// optimizer cannot remove. A plain `i & mask` in Rust is elided by LLVM the
/// moment a surrounding guard (e.g. `if pos >= LEN break`) makes it provably
/// redundant — but the verifier loses that guard across a spill/reload of the
/// index and then sees the *unmasked* value, rejecting the access ("invalid
/// access to map value ... R1 max value is outside of the allowed memory
/// range"). Emitting the AND through inline asm keeps it in the program text,
/// so the verifier always reads a hard power-of-two `var_off` bound on the
/// access register, spill/reload notwithstanding.
#[inline(always)]
fn mask_idx(i: usize, mask: usize) -> usize {
    #[cfg(target_arch = "bpf")]
    unsafe {
        let mut x = i;
        core::arch::asm!(
            "{x} &= {m}",
            x = inout(reg) x,
            m = in(reg) mask,
        );
        x
    }
    #[cfg(not(target_arch = "bpf"))]
    {
        i & mask
    }
}

#[inline(always)]
fn bget(buf: &[u8; DNS_SCRATCH_SIZE], i: usize) -> u8 {
    // `get_unchecked` (not `buf[..]`) so no Rust bounds-check/panic path is
    // emitted: the asm AND below — opaque to LLVM, transparent to the verifier
    // — is the sole, non-elidable bound.
    unsafe { *buf.get_unchecked(mask_idx(i, DNS_SCRATCH_SIZE - 1)) }
}

/// Normalize a running parse offset to a clean `[0, DNS_SCRATCH_SIZE]` scalar.
///
/// `pos` grows by variable, attacker-influenced amounts inside the answer loop
/// (`pos += rdlength`, rdlength up to 65535). Left alone its tracked range
/// widens without bound, so each unrolled iteration enters with a distinct
/// abstract value and the verifier cannot prune equivalent states — the
/// program explodes past the 1M-insn complexity budget. Laundering `pos`
/// through black_box drops LLVM's knowledge of the range (so it keeps the cap
/// branch) and the verifier re-derives a bounded `[0, 512]` scalar, identical
/// at every iteration boundary. Offsets at/after the scratch end read zeros
/// (the buffer is zero-filled) and fail the record checks, so clamping the
/// out-of-range case to the end rather than wrapping is safe.
#[inline(always)]
fn clamp_off(pos: usize) -> usize {
    let mut p = core::hint::black_box(pos);
    if p > DNS_SCRATCH_SIZE {
        p = DNS_SCRATCH_SIZE;
    }
    p
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

/// Masked write into the fixed-width qname buffer (the write mirror of
/// `bget`): the non-elidable asm AND keeps the store provably in bounds.
#[inline(always)]
fn qset(buf: &mut [u8; DNS_QNAME_MAX], i: usize, v: u8) {
    unsafe { *buf.get_unchecked_mut(mask_idx(i, DNS_QNAME_MAX - 1)) = v };
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

/// Copy the question name (length-prefixed labels, lowercased, terminator
/// excluded) into `out`, returning (qname_len, offset_past_terminator).
/// Compression pointers are rejected: the question is the first name in the
/// message and cannot legally point earlier. Length-prefix bytes are <= 63
/// and ASCII letters start at 65, so blanket lowercasing never corrupts a
/// length byte.
#[inline(always)]
fn copy_qname(
    buf: &[u8; DNS_SCRATCH_SIZE],
    start_offset: usize,
    out: &mut [u8; DNS_QNAME_MAX],
) -> Option<(usize, usize)> {
    // Phase 1: hop labels to find the terminator.
    let mut offset = start_offset;
    let mut end: usize = 0;
    for _i in 0..MAX_QNAME_LABELS {
        if offset >= DNS_SCRATCH_SIZE {
            return None;
        }
        let label_len = bget(buf, offset);
        if label_len == 0 {
            end = offset; // terminator excluded
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
    if total > DNS_QNAME_MAX {
        return None;
    }

    // Phase 2: copy + lowercase, single const-bounded counter.
    for k in 0..DNS_QNAME_MAX {
        if k >= total {
            break;
        }
        let ch = bget(buf, start_offset + k);
        qset(out, k, if ch.is_ascii_uppercase() { ch + 32 } else { ch });
    }

    Some((total, end + 1))
}

/// Skip a DNS name without copying. Used for answer-record name fields.
#[inline(always)]
fn skip_dns_name(buf: &[u8; DNS_SCRATCH_SIZE], start_offset: usize) -> Option<usize> {
    let mut offset = start_offset;
    let mut end_offset: usize = 0;
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
        if label_len as usize > MAX_LABEL_BYTES {
            return None;
        }
        offset += 1 + label_len as usize;
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
    // 0. Cgroup scoping. cgroup_skb runs in softirq context, so the current
    //    task cgroup is unrelated — use the skb's socket cgroup.
    let cgroup_id = unsafe { aya_ebpf::helpers::bpf_skb_cgroup_id(ctx.skb.skb) };
    if unsafe { ENFORCED_CGROUPS.get(&cgroup_id) }.is_none() {
        return Ok(());
    }

    let pkt_len = ctx.len() as usize;

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
        if load_byte(ctx, 9).ok_or(())? != IPPROTO_UDP {
            return Err(());
        }
        udp_offset = ihl;
    } else if ip_version == 6 {
        if pkt_len < IP6_HEADER_SIZE + UDP_HEADER_SIZE + DNS_HEADER_SIZE {
            return Err(());
        }
        if load_byte(ctx, 6).ok_or(())? != IPPROTO_UDP {
            return Err(());
        }
        udp_offset = IP6_HEADER_SIZE;
    } else {
        return Err(());
    }

    // Source port == 53 (DNS response).
    if load_u16_be(ctx, udp_offset).ok_or(())? != DNS_PORT {
        return Err(());
    }

    let dns_offset = udp_offset + UDP_HEADER_SIZE;
    if pkt_len < dns_offset + DNS_HEADER_SIZE {
        return Err(());
    }

    // Copy the DNS message into per-CPU scratch in ONE helper call, then
    // parse from memory. Zero-fill first so bytes past the message read as
    // zeros (which lets the accessors skip a per-read length compare) and
    // stale bytes from a previous packet never influence parsing.
    let avail = pkt_len - dns_offset;
    let scratch = unsafe { DNS_SCRATCH.get_ptr_mut(0).ok_or(())? };
    let buf = unsafe { &mut (*scratch).data };
    let words = buf.as_mut_ptr() as *mut u64;
    for w in 0..(DNS_SCRATCH_SIZE / 8) {
        unsafe { words.add(w).write(0) };
    }
    // Clamp the copy length to [DNS_HEADER_SIZE, DNS_SCRATCH_SIZE] right before
    // the call. `avail >= DNS_HEADER_SIZE` already holds, but bpf_skb_load_bytes
    // rejects a possibly-zero length and the verifier loses the lower bound
    // across `avail`'s spill/reload (it sees [0, ..]). A plain guard is no use:
    // LLVM proves it redundant and deletes it. Laundering `avail` through
    // black_box makes both bounds opaque to LLVM, so it keeps the refining
    // branches — and the verifier, walking them, derives n ∈ [12, 512].
    let mut n = core::hint::black_box(avail);
    if n < DNS_HEADER_SIZE {
        return Err(());
    }
    if n > DNS_SCRATCH_SIZE {
        n = DNS_SCRATCH_SIZE;
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

    // Header (message-relative offsets).
    if (bget_u16(buf, 2) & DNS_FLAG_QR) == 0 {
        return Err(()); // not a response
    }
    let qdcount = bget_u16(buf, 4);
    let ancount = bget_u16(buf, 6);
    // Single-question responses only — every response a real resolver
    // produces. Extra questions cost a per-question name walk that pushes
    // the program over the verifier's budget.
    if qdcount != 1 {
        return Err(());
    }

    // Copy the question name into a local wire-format buffer.
    let mut qname = [0u8; DNS_QNAME_MAX];
    let (qname_len, mut pos) = copy_qname(buf, DNS_HEADER_SIZE, &mut qname).ok_or(())?;
    pos += 4; // skip QTYPE + QCLASS

    // Answer section: emit one event per A/AAAA record.
    for a in 0..MAX_ANSWERS {
        if a >= ancount as usize {
            break;
        }
        // Re-normalize the offset to a clean [0, 512] scalar at every iteration
        // boundary so the verifier can prune equivalent states (see clamp_off).
        pos = clamp_off(pos);
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
            emit(
                buf,
                cgroup_id,
                ttl,
                DNS_TYPE_A as u8,
                &qname,
                qname_len,
                pos,
            );
        } else if rtype == DNS_TYPE_AAAA && rdlength == 16 {
            emit(
                buf,
                cgroup_id,
                ttl,
                DNS_TYPE_AAAA as u8,
                &qname,
                qname_len,
                pos,
            );
        }

        pos += rdlength as usize;
    }

    Ok(())
}

/// Reserve a DnsEvent, fill the common fields plus the address bytes from
/// the record data at `rdata_pos`, and submit.
#[inline(always)]
fn emit(
    buf: &[u8; DNS_SCRATCH_SIZE],
    cgroup_id: u64,
    ttl: u32,
    record_type: u8,
    qname: &[u8; DNS_QNAME_MAX],
    qname_len: usize,
    rdata_pos: usize,
) {
    if let Some(mut entry) = DNS_EVENTS.reserve::<DnsEvent>(0) {
        let ev = entry.as_mut_ptr();
        unsafe {
            (*ev).timestamp_ns = 0;
            (*ev).pid = 0;
            (*ev).uid = 0;
            (*ev).event_type = EventType::DnsResponse as u32;
            (*ev).ttl = ttl;
            (*ev).cgroup_id = cgroup_id;
            (*ev).addr_v4 = [0; 4];
            (*ev).addr_v6 = [0; 16];
            (*ev).record_type = record_type;
            (*ev).qname_len = qname_len as u8;
            (*ev)._pad = [0; 2];
            (*ev).qname = *qname;

            if record_type == DNS_TYPE_A as u8 {
                for k in 0..4 {
                    (*ev).addr_v4[k] = bget(buf, rdata_pos + k);
                }
            } else {
                for k in 0..16 {
                    (*ev).addr_v6[k] = bget(buf, rdata_pos + k);
                }
            }
        }
        entry.submit(0);
    }
}
