import Foundation
import Containerization

// VMManager owns the lifecycle of Apple containerization microVMs and the
// host-side socket bridges that expose each VM's private Docker daemon.
//
// One VM == one microVM running a docker-in-docker image. dockerd inside the VM
// listens on TCP :2375 (bound to the VM's vmnet interface). For each VM we open
// a host unix socket and proxy every connection to <vm-ip>:2375, so the Go
// client can talk to a normal `unix://` Docker endpoint exactly as it does with
// sandboxd. (A more locked-down alternative is to keep dockerd on a vsock port
// and bridge via LinuxContainer.dialVsock(port:) — see README; left as a
// follow-up.)
//
// NOTE: This is the initial spike. Lines marked `// VERIFY:` use containerization
// API surface that must be checked against the installed library version on a
// Mac (the exact initializer/method names have moved between releases).
actor VMManager {
    struct VMRecord {
        let id: String
        let name: String
        let agent: String
        let workspaceDir: String
        let createdAt: Date
        var ipAddresses: [String]
        let hostSocketPath: String
        var status: String
        let container: LinuxContainer
        let bridge: SocketBridge
    }

    private var vms: [String: VMRecord] = [:]  // keyed by vm_name
    private let kernelPath: String
    private let dindImage: String
    private let stateDir: URL

    init(kernelPath: String, dindImage: String, stateDir: URL) {
        self.kernelPath = kernelPath
        self.dindImage = dindImage
        self.stateDir = stateDir
    }

    var count: Int { vms.count }

    // MARK: - Lifecycle

    func createVM(_ req: VMCreateRequest) async throws -> VMCreateResponse {
        let name = req.vm_name ?? "acvm-\(UUID().uuidString.prefix(8))"
        if vms[name] != nil {
            throw DaemonError.conflict("VM \(name) already exists")
        }

        // VERIFY: Kernel + ContainerManager construction. Per the containerization
        // docs/cctl, the high-level path is roughly:
        //   let kernel = Kernel(path: URL(fileURLWithPath: kernelPath), platform: .linuxArm)
        //   let manager = try await ContainerManager(kernel: kernel,
        //                       initfsReference: "vminit:latest", network: ..., rosetta: false)
        //   let container = try await manager.create(name, reference: dindImage,
        //                       rootfsSizeInBytes: ..., networking: true) { config in
        //       config.process.arguments = ["/usr/local/bin/dockerd",
        //                                    "-H", "tcp://0.0.0.0:2375",
        //                                    "-H", "unix:///var/run/docker.sock"]
        //       config.process.workingDirectory = "/"
        //   }
        //   try await container.create()
        //   try await container.start()
        let kernel = Kernel(path: URL(fileURLWithPath: kernelPath), platform: .linuxArm)  // VERIFY
        let manager = try await ContainerManager(                                          // VERIFY
            kernel: kernel,
            initfsReference: "vminit:latest",
            rosetta: false
        )
        let container = try await manager.create(                                          // VERIFY
            name,
            reference: workloadImage(for: req),
            networking: true
        ) { config in
            config.process.arguments = [
                "/usr/local/bin/dockerd",
                "-H", "tcp://0.0.0.0:2375",
                "-H", "unix:///var/run/docker.sock",
            ]
            config.process.workingDirectory = "/"
        }
        try await container.create()  // VERIFY
        try await container.start()   // VERIFY

        // VERIFY: how to read the VM's vmnet IP. Per docs LinuxContainer carries
        // `interfaces: [any Interface]`; resolve the IPv4 address from there.
        let ips = try await resolveIPAddresses(container)
        guard let vmIP = ips.first else {
            try? await container.stop()
            throw DaemonError.internalError("VM \(name) came up with no IP address")
        }

        // Wait for dockerd to accept connections before handing the socket back.
        try await waitForDockerd(host: vmIP, port: 2375, timeout: 30)

        // Stand up the host unix socket -> <vmIP>:2375 proxy.
        let sockPath = stateDir.appendingPathComponent("\(name)/docker.sock").path
        try FileManager.default.createDirectory(
            atPath: (sockPath as NSString).deletingLastPathComponent,
            withIntermediateDirectories: true
        )
        let bridge = SocketBridge(hostSocketPath: sockPath, targetHost: vmIP, targetPort: 2375)
        try bridge.start()

        let record = VMRecord(
            id: "avm-\(UUID().uuidString.prefix(12))",
            name: name,
            agent: req.agent_name,
            workspaceDir: req.workspace_dir,
            createdAt: Date(),
            ipAddresses: ips,
            hostSocketPath: sockPath,
            status: "running",
            container: container,
            bridge: bridge
        )
        vms[name] = record

        // NOTE (parity gap vs sandboxd): no MITM egress proxy yet, so no CA cert
        // and no proxy env vars. The Go side treats empty ca_cert_data as
        // "skip CA injection". credential_sources / service_auth_config are
        // accepted on the request but not yet enforced. See README.
        return VMCreateResponse(
            vm_id: record.id,
            vm_config: VMConfig(socketPath: sockPath),
            ca_cert_path: nil,
            ca_cert_data: "",
            proxy_env_vars: [:],
            started: true
        )
    }

    func list() -> [VMListEntry] {
        let iso = ISO8601DateFormatter()
        return vms.values.map { r in
            VMListEntry(
                vm_id: r.id,
                vm_name: r.name,
                agent: r.agent,
                workspace_dir: r.workspaceDir,
                created_at: iso.string(from: r.createdAt),
                active: r.status == "running",
                status: r.status,
                vm_config: VMConfig(socketPath: r.hostSocketPath)
            )
        }
    }

    func inspect(_ name: String) throws -> VMInspectResponse {
        guard let r = vms[name] else { throw DaemonError.notFound("VM \(name) not found") }
        let iso = ISO8601DateFormatter()
        let ts = iso.string(from: r.createdAt)
        return VMInspectResponse(
            vm_id: r.id,
            vm_name: r.name,
            agent: r.agent,
            workspace_dir: r.workspaceDir,
            registered_at: ts,
            last_seen: ts,
            ip_addresses: r.ipAddresses,
            subnets: [],
            credential_count: 0,
            vm_config: VMConfig(socketPath: r.hostSocketPath)
        )
    }

    func stop(_ name: String) async throws {
        guard var r = vms[name] else { throw DaemonError.notFound("VM \(name) not found") }
        try? await r.container.stop()  // VERIFY
        r.status = "stopped"
        vms[name] = r
    }

    func delete(_ name: String) async throws {
        guard let r = vms[name] else { throw DaemonError.notFound("VM \(name) not found") }
        r.bridge.stop()
        try? await r.container.stop()  // VERIFY
        try? FileManager.default.removeItem(atPath: r.hostSocketPath)
        vms.removeValue(forKey: name)
    }

    func keepalive(_ name: String) throws {
        // Idle-timeout management is a follow-up; accept and no-op for now.
        guard vms[name] != nil else { throw DaemonError.notFound("VM \(name) not found") }
    }

    func updateProxyConfig(_ req: ProxyConfigRequest) throws {
        // MVP: no MITM egress proxy. Accept and log; network policy enforcement
        // is a documented follow-up (see README). Validate the VM exists so the
        // contract matches sandboxd's behaviour.
        guard vms[req.vm_name] != nil else {
            throw DaemonError.notFound("VM \(req.vm_name) not found")
        }
        FileHandle.standardError.write(
            Data("[ac-applevmd] proxyconfig for \(req.vm_name) accepted (no-op in MVP)\n".utf8)
        )
    }

    // MARK: - Helpers

    private func workloadImage(for req: VMCreateRequest) -> String {
        // The Go side passes cfg.Image as the workload; if it omitted one it
        // defaults to docker:dind. We don't see cfg.Image here (the Go runtime
        // creates the agent container itself via the bridged Docker socket), so
        // the VM workload is always the dind image.
        _ = req
        return dindImage
    }

    private func resolveIPAddresses(_ container: LinuxContainer) async throws -> [String] {
        // VERIFY: pull IPv4 addresses off container.interfaces. Shape depends on
        // the Interface protocol in the installed version.
        // Example sketch:
        //   container.interfaces.compactMap { $0.address?.ipv4String }
        return []  // VERIFY: implement against real API
    }

    private func waitForDockerd(host: String, port: Int, timeout: TimeInterval) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if SocketBridge.canConnect(host: host, port: port) { return }
            try await Task.sleep(nanoseconds: 500_000_000)
        }
        throw DaemonError.internalError("dockerd did not become reachable at \(host):\(port)")
    }
}

enum DaemonError: Error {
    case notFound(String)
    case conflict(String)
    case badRequest(String)
    case internalError(String)
}
