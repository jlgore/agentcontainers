//! Policy manager trait — the contract between the gRPC service and BPF enforcement.
//!
//! On Linux, this is implemented by [`BpfPolicyManager`] which translates high-level
//! policy requests into BPF map operations via aya. On other platforms (and in tests),
//! a [`StubPolicyManager`] returns success without doing anything.
//!
//! Policy data types (NetworkPolicy, EgressRule, etc.) are defined in `agentcontainer-common`
//! and re-exported here to avoid duplication.

use std::collections::HashMap;

use tonic::async_trait;

// Re-export policy data types from agentcontainer-common (the single source of truth).
pub use agentcontainer_common::policy::{
    CredentialPolicy, EgressRule, FilesystemPolicy, NetworkPolicy, ProcessPolicy, SecretAcl,
};

/// Per-container enforcement context returned by [`PolicyManager::register`].
#[derive(Debug, Clone)]
pub struct ContainerHandle {
    pub container_id: String,
    pub cgroup_id: u64,
}

/// Parse a CIDR string (`"10.0.0.0/8"`, `"fd00:ec2::254/128"`) or a bare IP
/// (treated as a host route: /32 or /128) into address + prefix length.
/// Returns `None` for anything malformed — callers warn-and-skip so one bad
/// entry cannot abort policy application.
pub fn parse_cidr(s: &str) -> Option<(std::net::IpAddr, u8)> {
    let (addr_str, prefix_str) = match s.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (s, None),
    };
    let addr: std::net::IpAddr = addr_str.trim().parse().ok()?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix_str {
        Some(p) => p.trim().parse::<u8>().ok()?,
        None => max,
    };
    if prefix > max {
        return None;
    }
    Some((addr, prefix))
}

/// Enforcement statistics for a container.
#[derive(Debug, Clone, Default)]
pub struct EnforcementStats {
    pub network_allowed: u64,
    pub network_blocked: u64,
    pub filesystem_allowed: u64,
    pub filesystem_blocked: u64,
    pub process_allowed: u64,
    pub process_blocked: u64,
    pub credential_allowed: u64,
    pub credential_blocked: u64,
}

/// Enforcement event emitted from BPF ring buffers.
#[derive(Debug, Clone)]
pub struct EnforcementEvent {
    pub timestamp_ns: u64,
    pub cgroup_id: u64,
    pub correlation_id: String,
    pub container_id: String,
    pub domain: EventDomain,
    pub verdict: EventVerdict,
    pub pid: u32,
    pub comm: String,
    pub details: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventDomain {
    Network,
    Filesystem,
    Process,
    Credential,
    /// Synthetic marker about the event stream itself (e.g. a backpressure
    /// gap on the event bus) — not a kernel enforcement event.
    Stream,
}

impl EventDomain {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Network => "network",
            Self::Filesystem => "filesystem",
            Self::Process => "process",
            Self::Credential => "credential",
            Self::Stream => "stream",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventVerdict {
    Allow,
    Block,
}

impl EventVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Block => "block",
        }
    }
}

/// The core abstraction between the gRPC service and BPF enforcement.
///
/// All methods are async and fallible. On Linux, the real implementation
/// translates these calls into BPF map operations. On macOS/tests, the
/// stub returns success.
#[async_trait]
pub trait PolicyManager: Send + Sync + 'static {
    /// Register a container for enforcement. Resolves the cgroup path to an ID
    /// and inserts it into the ENFORCED_CGROUPS map.
    ///
    /// `init_pid` is the container's init process PID; when non-zero,
    /// filesystem/process/credential policy paths are resolved through
    /// `/proc/<init_pid>/root` (the container's mount namespace) so the
    /// pinned inodes are the ones its LSM hooks actually observe. Zero
    /// falls back to resolving in the enforcer's own namespace (host-side
    /// callers).
    async fn register(
        &self,
        container_id: &str,
        cgroup_path: &str,
        init_pid: u32,
    ) -> anyhow::Result<ContainerHandle>;

    /// Unregister a container. Removes all map entries for this cgroup.
    async fn unregister(&self, container_id: &str) -> anyhow::Result<()>;

    /// Apply network enforcement policy for a container.
    async fn apply_network(&self, container_id: &str, policy: &NetworkPolicy)
        -> anyhow::Result<()>;

    /// Apply filesystem enforcement policy for a container.
    async fn apply_filesystem(
        &self,
        container_id: &str,
        policy: &FilesystemPolicy,
    ) -> anyhow::Result<()>;

    /// Apply process enforcement policy for a container.
    async fn apply_process(&self, container_id: &str, policy: &ProcessPolicy)
        -> anyhow::Result<()>;

    /// Apply credential enforcement policy (Phase 6).
    async fn apply_credential(
        &self,
        container_id: &str,
        policy: &CredentialPolicy,
    ) -> anyhow::Result<()>;

    /// Get enforcement stats for a container (empty string = aggregate).
    async fn get_stats(&self, container_id: &str) -> anyhow::Result<EnforcementStats>;

    /// Subscribe to enforcement events. Returns a receiver that yields events
    /// for the given container (empty string = all containers).
    async fn subscribe_events(
        &self,
        container_id: &str,
    ) -> anyhow::Result<tokio::sync::mpsc::Receiver<EnforcementEvent>>;

    /// Mark the start of a proxied MCP tool call for event correlation.
    async fn prepare_tool_call(
        &self,
        container_id: &str,
        correlation_id: &str,
        tool_name: &str,
    ) -> anyhow::Result<()>;

    /// Mark the end of a proxied MCP tool call for event correlation.
    async fn complete_tool_call(
        &self,
        container_id: &str,
        correlation_id: &str,
    ) -> anyhow::Result<()>;
}

/// Stub policy manager for macOS and tests. All operations succeed as no-ops.
pub struct StubPolicyManager;

#[async_trait]
impl PolicyManager for StubPolicyManager {
    async fn register(
        &self,
        container_id: &str,
        _cgroup_path: &str,
        _init_pid: u32,
    ) -> anyhow::Result<ContainerHandle> {
        tracing::warn!("stub policy manager: register is a no-op");
        Ok(ContainerHandle {
            container_id: container_id.to_string(),
            cgroup_id: 0,
        })
    }

    async fn unregister(&self, _container_id: &str) -> anyhow::Result<()> {
        Ok(())
    }

    async fn apply_network(
        &self,
        _container_id: &str,
        _policy: &NetworkPolicy,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    async fn apply_filesystem(
        &self,
        _container_id: &str,
        _policy: &FilesystemPolicy,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    async fn apply_process(
        &self,
        _container_id: &str,
        _policy: &ProcessPolicy,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    async fn apply_credential(
        &self,
        _container_id: &str,
        _policy: &CredentialPolicy,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    async fn get_stats(&self, _container_id: &str) -> anyhow::Result<EnforcementStats> {
        Ok(EnforcementStats::default())
    }

    /// Returns a receiver whose sender is immediately dropped, causing the stream to
    /// end immediately. This is intentional for the stub — no events are ever produced.
    /// A real implementation would hold the sender and feed events from BPF ring buffers.
    async fn subscribe_events(
        &self,
        _container_id: &str,
    ) -> anyhow::Result<tokio::sync::mpsc::Receiver<EnforcementEvent>> {
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        Ok(rx)
    }

    async fn prepare_tool_call(
        &self,
        _container_id: &str,
        _correlation_id: &str,
        _tool_name: &str,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    async fn complete_tool_call(
        &self,
        _container_id: &str,
        _correlation_id: &str,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::parse_cidr;
    use std::net::IpAddr;

    #[test]
    fn parse_cidr_v4_with_prefix() {
        let (addr, prefix) = parse_cidr("10.0.0.0/8").unwrap();
        assert_eq!(addr, "10.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(prefix, 8);
    }

    #[test]
    fn parse_cidr_bare_v4_is_host_route() {
        let (addr, prefix) = parse_cidr("169.254.169.254").unwrap();
        assert_eq!(addr, "169.254.169.254".parse::<IpAddr>().unwrap());
        assert_eq!(prefix, 32);
    }

    #[test]
    fn parse_cidr_v6_with_prefix() {
        let (addr, prefix) = parse_cidr("fd00:ec2::254/128").unwrap();
        assert_eq!(addr, "fd00:ec2::254".parse::<IpAddr>().unwrap());
        assert_eq!(prefix, 128);
    }

    #[test]
    fn parse_cidr_bare_v6_is_host_route() {
        let (_, prefix) = parse_cidr("2001:db8::1").unwrap();
        assert_eq!(prefix, 128);
    }

    #[test]
    fn parse_cidr_rejects_malformed() {
        // Prefix beyond the family maximum, garbage, empty, hostname.
        assert!(parse_cidr("10.0.0.0/33").is_none());
        assert!(parse_cidr("2001:db8::/129").is_none());
        assert!(parse_cidr("not-an-ip/8").is_none());
        assert!(parse_cidr("").is_none());
        assert!(parse_cidr("example.com").is_none());
        assert!(parse_cidr("10.0.0.0/abc").is_none());
    }
}
