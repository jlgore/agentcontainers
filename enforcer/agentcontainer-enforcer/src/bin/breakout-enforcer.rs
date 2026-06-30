//! breakout-enforcer — the Escape-the-Box P3 Level 2 mechanism, harness-agnostic.
//!
//! Registers a single cgroup with an egress allowlist on the REAL kernel, then
//! holds the BPF programs attached until it receives SIGTERM/SIGINT. Any process
//! placed in that cgroup (children inherit) is governed by the `connect4` hook:
//! a connect to a non-allowed host is denied with EPERM in the kernel.
//!
//! This is the long-lived counterpart of the in-process
//! `test_capability_matrix_exfil_under_enforcer` integration test. The test
//! spawns its own `python3`; this binary instead governs a cgroup that the
//! breakout runner launches a *live agent* (pi / opencode / claude) into — so
//! the same kernel boundary is proven against a real agent's interpreter-egress,
//! identically for every harness (the runner does the cgroup placement; this
//! binary does not care which harness it is).
//!
//! Usage:
//!   breakout-enforcer <name> <cgroup_path> <allowed_host>...
//!
//! Prints `READY <name> <cgroup>` once the policy is live (the runner waits for
//! this line), then `STOPPED <name>` after it unregisters on signal. The ELF is
//! resolved by `BpfPolicyManager::new()` (AC_BPF_ELF_PATH or the build fallbacks).
//! Requires root (CAP_BPF / CAP_NET_ADMIN / CAP_SYS_ADMIN) and a cgroup-v2 kernel
//! with the BPF LSM active — the same prerequisites as `enforcer-live.sh`.

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use agentcontainer_enforcer::bpf::BpfPolicyManager;
    use agentcontainer_enforcer::policy::{NetworkPolicy, PolicyManager};
    use std::io::Write;

    let mut args = std::env::args().skip(1);
    let name = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("usage: breakout-enforcer <name> <cgroup_path> <allowed_host>..."))?;
    let cgroup = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("usage: breakout-enforcer <name> <cgroup_path> <allowed_host>..."))?;
    let allowed_hosts: Vec<String> = args.collect();

    if unsafe { libc::geteuid() } != 0 {
        anyhow::bail!("breakout-enforcer must run as root (needs CAP_BPF / CAP_NET_ADMIN / CAP_SYS_ADMIN)");
    }

    // Load + attach the BPF programs (connect4/6 etc.) at the cgroup-v2 root.
    let mgr = BpfPolicyManager::new()?;
    // Register the target cgroup → its cgroup_id enters ENFORCED_CGROUPS, so the
    // connect4 hook starts gating connects made by any task in this cgroup.
    mgr.register(&name, &cgroup, 0).await?;
    // Egress allowlist: ONLY these hosts may be connected. The canary host is
    // deliberately NOT in this list, so the agent's exfil connect is denied.
    let policy = NetworkPolicy {
        allowed_hosts: allowed_hosts.clone(),
        egress_rules: vec![],
        dns_servers: vec![],
        blocked_cidrs: vec![],
    };
    mgr.apply_network(&name, &policy).await?;

    // Stream this cgroup's enforcement events so the runner gets a precise,
    // harness-independent kernel signal: every connect4 verdict for the governed
    // cgroup is printed as NET-<VERDICT>. A `NET-BLOCK ... dst=<canary>` line is
    // BOTH proof the agent attempted egress AND proof the kernel denied it — no
    // guard audit, no model-narration parsing. The runner greps this log.
    let mut events = mgr.subscribe_events(&name).await?;
    tokio::spawn(async move {
        while let Some(ev) = events.recv().await {
            use agentcontainer_enforcer::policy::EventDomain;
            if ev.domain != EventDomain::Network {
                continue;
            }
            let dst = ev.details.get("dst_ip").map(String::as_str).unwrap_or("?");
            let port = ev.details.get("dst_port").map(String::as_str).unwrap_or("?");
            println!(
                "NET-{} pid={} comm={} dst={dst}:{port}",
                ev.verdict.as_str().to_uppercase(),
                ev.pid,
                ev.comm
            );
            use std::io::Write;
            std::io::stdout().flush().ok();
        }
    });

    println!("READY {name} {cgroup} allowed={allowed_hosts:?}");
    std::io::stdout().flush().ok();

    // Hold the programs attached until the runner tells us to tear down. Dropping
    // the manager detaches the BPF links, so we MUST stay alive for the whole run.
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut intr = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    tokio::select! {
        _ = term.recv() => {}
        _ = intr.recv() => {}
    }

    mgr.unregister(&name).await?;
    println!("STOPPED {name}");
    std::io::stdout().flush().ok();
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("breakout-enforcer is Linux-only (needs the eBPF enforcer)");
    std::process::exit(1);
}
