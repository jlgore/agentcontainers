import Foundation

// Wire models. These mirror internal/sandbox/types.go field-for-field (JSON
// keys included) so ac-applevmd is a drop-in for sandboxd from the Go client's
// point of view. Keep them in sync with that file.

struct HealthResponse: Codable {
    var status: String
    var version: String
    var vms: Int
}

struct SandboxMount: Codable {
    var source: String
    var target: String?
    var readonly: Bool?
}

struct ServiceAuthConfig: Codable {
    var header_name: String
}

struct CredentialSource: Codable {
    var source: String
    var path: String?
}

struct PolicyConfig: Codable {
    var `default`: String?
}

struct VMCreateRequest: Codable {
    var agent_name: String
    var workspace_dir: String
    var vm_name: String?
    var existing_workspace: Bool?
    var mounts: [SandboxMount]?
    var service_domains: [String: String]?
    var service_auth_config: [String: ServiceAuthConfig]?
    var credential_sources: [String: CredentialSource]?
    var policy: PolicyConfig?
}

struct VMConfig: Codable {
    var socketPath: String?
}

struct VMCreateResponse: Codable {
    var vm_id: String
    var vm_config: VMConfig
    var ca_cert_path: String?
    var ca_cert_data: String?
    var proxy_env_vars: [String: String]?
    var started: Bool
}

struct VMListEntry: Codable {
    var vm_id: String
    var vm_name: String
    var agent: String
    var workspace_dir: String
    var created_at: String
    var active: Bool
    var status: String
    var vm_config: VMConfig
}

struct VMInspectResponse: Codable {
    var vm_id: String
    var vm_name: String
    var agent: String
    var workspace_dir: String
    var registered_at: String
    var last_seen: String
    var ip_addresses: [String]
    var subnets: [String]
    var credential_count: Int
    var vm_config: VMConfig
}

struct ProxyConfigRequest: Codable {
    var vm_name: String
    var allow_hosts: [String]?
    var block_hosts: [String]?
    var bypass_hosts: [String]?
    var allow_cidrs: [String]?
    var block_cidrs: [String]?
    var bypass_cidrs: [String]?
    var policy: String
}

struct MessageResponse: Codable {
    var message: String
}
