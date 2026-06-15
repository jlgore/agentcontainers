//! LSM bprm_check_security hook for process execution enforcement.
//!
//! Intercepts execve() and authorizes the executable's *identity* (device +
//! inode) against a per-cgroup allowlist:
//! 0. Check cgroup scoping -- skip non-enforced cgroups.
//! 1. Read executable inode from linux_binprm->file->f_path.dentry->d_inode.
//! 2. Allow only if (device, inode, cgroup) is present in ALLOWED_EXECS.
//! 3. Otherwise deny (-EACCES). Both allowed and denied attempts are audited.
//!
//! This layer authorizes *which binary* may run. It does not inspect command
//! arguments — that is the guard layer's responsibility. Once a process is
//! confirmed to belong to an enforced cgroup, any failure to read or look up
//! its executable identity is treated as a denial (fail-closed).

use aya_ebpf::helpers::{
    bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
    bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_kernel,
};
use aya_ebpf::macros::lsm;
use aya_ebpf::programs::LsmContext;

use agentcontainer_common::events::{ExecEvent, STAT_PROC_ALLOWED, STAT_PROC_BLOCKED};
use agentcontainer_common::maps::{FsInodeKey, CGROUP_FLAG_EXEC_ENFORCED, LSM_ALLOW, LSM_DENY};

use crate::maps::{
    bump_cgroup_stat, ALLOWED_EXECS, CGROUP_STAT_PROC_ALLOWED, CGROUP_STAT_PROC_BLOCKED,
    ENFORCED_CGROUPS, PROC_EVENTS, PROC_STATS,
};

// ---------------------------------------------------------------------------
// Kernel struct definitions for reading linux_binprm fields via bpf_probe_read_kernel.
// These must match the kernel's in-memory layout.
// ---------------------------------------------------------------------------

#[repr(C)]
struct LinuxBinprm {
    file: *const File,
}

#[repr(C)]
struct File {
    f_path: Path,
}

#[repr(C)]
struct Path {
    mnt: *const u8,
    dentry: *const Dentry,
}

#[repr(C)]
struct Dentry {
    d_inode: *const Inode,
}

#[repr(C)]
struct Inode {
    i_ino: u64,
    i_sb: *const SuperBlock,
}

#[repr(C)]
struct SuperBlock {
    s_dev: u32,
}

// ---------------------------------------------------------------------------
// Inline helpers
// ---------------------------------------------------------------------------

/// Bump a per-CPU stats counter by index.
#[inline(always)]
fn bump_stat(idx: u32) {
    unsafe {
        if let Some(val) = PROC_STATS.get_ptr_mut(idx) {
            *val += 1;
        }
    }
}

/// Emit a process execution event to the PROC_EVENTS ring buffer.
/// `verdict` follows `events::Verdict`: 0 = allow, 1 = block.
#[inline(always)]
fn emit_exec_event(cgroup_id: u64, ino: u64, verdict: u32) {
    if let Some(mut entry) = PROC_EVENTS.reserve::<ExecEvent>(0) {
        let ev = entry.as_mut_ptr();
        unsafe {
            (*ev).timestamp_ns = bpf_ktime_get_ns();

            let pid_tgid = bpf_get_current_pid_tgid();
            (*ev).pid = (pid_tgid >> 32) as u32;

            let uid_gid = bpf_get_current_uid_gid();
            (*ev).uid = uid_gid as u32;

            (*ev).event_type = 4; // EventType::ProcessExec
            (*ev).verdict = verdict;
            (*ev).cgroup_id = cgroup_id;

            (*ev).inode = ino;

            // Zero out variable-length fields before populating.
            (*ev).binary = [0u8; 256];

            (*ev).comm = match bpf_get_current_comm() {
                Ok(c) => c,
                Err(_) => [0u8; 16],
            };
        }
        entry.submit(0);
    }
}

/// Record a denied execution: bump block stats, audit it, and return LSM_DENY.
/// `ino` is 0 when the inode could not be read (the identity is unverifiable,
/// which is itself a denial).
#[inline(always)]
fn deny_exec(cgroup_id: u64, ino: u64) -> i32 {
    bump_stat(STAT_PROC_BLOCKED);
    bump_cgroup_stat(cgroup_id, CGROUP_STAT_PROC_BLOCKED);
    emit_exec_event(cgroup_id, ino, 1 /* Verdict::Block */);
    LSM_DENY
}

// ---------------------------------------------------------------------------
// lsm/bprm_check_security -- intercepts process execution (execve).
// ---------------------------------------------------------------------------

#[lsm(hook = "bprm_check_security")]
pub fn ac_bprm_check(ctx: LsmContext) -> i32 {
    match try_bprm_check(&ctx) {
        Ok(ret) => ret,
        // Fail closed: try_bprm_check only returns Err after the process is
        // confirmed to belong to an enforced cgroup, so a read failure is an
        // unverifiable execution and must be denied, not allowed.
        Err(_) => LSM_DENY,
    }
}

fn try_bprm_check(ctx: &LsmContext) -> Result<i32, i64> {
    // 0. Cgroup scoping: only enforce for processes in target containers.
    //    LSM hooks are system-wide; skip all non-container processes.
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let flags = match unsafe { ENFORCED_CGROUPS.get(&cgroup_id) } {
        Some(&f) => f,
        None => return Ok(LSM_ALLOW),
    };

    // Exec-allowlist enforcement is OPT-IN: only cgroups that had a non-empty
    // exec allowlist applied (the EXEC_ENFORCED flag) are gated here. Tool-runner
    // backends — e.g. the SIFT gateway, which must spawn its own MCP sub-servers
    // and forensic binaries — receive no allowlist and run execs freely; their
    // network/filesystem/readonly-rootfs/cap-drop confinement still applies.
    if flags & CGROUP_FLAG_EXEC_ENFORCED == 0 {
        return Ok(LSM_ALLOW);
    }

    // Read the linux_binprm pointer from the LSM hook's first argument.
    let bprm_ptr: *const LinuxBinprm = unsafe { ctx.arg(0) };

    // Read the executable file pointer from linux_binprm. A missing file or
    // dentry/inode/superblock means the executable identity cannot be verified;
    // for an enforced process that is a denial, not an allowance.
    let file_ptr: *const File =
        unsafe { bpf_probe_read_kernel(&(*bprm_ptr).file as *const _ as *const _).map_err(|e| e)? };
    if file_ptr.is_null() {
        return Ok(deny_exec(cgroup_id, 0));
    }

    // Read the dentry pointer from file->f_path.dentry.
    let dentry_ptr: *const Dentry = unsafe {
        bpf_probe_read_kernel(&(*file_ptr).f_path.dentry as *const _ as *const _).map_err(|e| e)?
    };
    if dentry_ptr.is_null() {
        return Ok(deny_exec(cgroup_id, 0));
    }

    // Read the inode pointer from dentry->d_inode.
    let inode_ptr: *const Inode = unsafe {
        bpf_probe_read_kernel(&(*dentry_ptr).d_inode as *const _ as *const _).map_err(|e| e)?
    };
    if inode_ptr.is_null() {
        return Ok(deny_exec(cgroup_id, 0));
    }

    // Read the inode number.
    let ino: u64 = unsafe {
        bpf_probe_read_kernel(&(*inode_ptr).i_ino as *const _ as *const _).map_err(|e| e)?
    };

    // Read the superblock pointer to get the device number.
    let sb_ptr: *const SuperBlock = unsafe {
        bpf_probe_read_kernel(&(*inode_ptr).i_sb as *const _ as *const _).map_err(|e| e)?
    };
    if sb_ptr.is_null() {
        return Ok(deny_exec(cgroup_id, ino));
    }

    let s_dev: u32 =
        unsafe { bpf_probe_read_kernel(&(*sb_ptr).s_dev as *const _ as *const _).map_err(|e| e)? };

    // Build lookup key with device major/minor numbers.
    // Linux dev_t: MAJOR = (dev >> 20) & 0xfff, MINOR = dev & 0xfffff.
    let key = FsInodeKey {
        inode: ino,
        dev_major: (s_dev >> 20) & 0xfff,
        dev_minor: s_dev & 0xfffff,
        cgroup_id,
    };

    // Allowlist enforcement: an execution is permitted only when its
    // (device, inode, cgroup) identity is present in ALLOWED_EXECS. Userspace
    // resolves each configured executable — including PATH-resolved bare names
    // and shebang interpreters — to its container-namespace inode before the
    // container is unpaused, so the allowlist reflects the real on-disk files.
    // Anything else (including an empty allowlist) is denied. Both outcomes are
    // audited for the forensic exec trail.
    if unsafe { ALLOWED_EXECS.get(&key) }.is_some() {
        bump_stat(STAT_PROC_ALLOWED);
        bump_cgroup_stat(cgroup_id, CGROUP_STAT_PROC_ALLOWED);
        emit_exec_event(cgroup_id, ino, 0 /* Verdict::Allow */);
        Ok(LSM_ALLOW)
    } else {
        Ok(deny_exec(cgroup_id, ino))
    }
}
