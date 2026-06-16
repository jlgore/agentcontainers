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
// The boot sequence mirrors the canonical example in the containerization
// package's `cctl` RunCommand: Kernel + VmnetNetwork -> ContainerManager ->
// manager.create(reference:) which pulls the image and builds the rootfs ->
// container.create()/start(). dockerd is the container's PID 1 process.
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
    private var managers: [String: ContainerManager] = [:]  // keyed by vm_name (for delete)
    private let kernelPath: String
    private let dindImage: String
    private let rootfsSizeMiB: UInt64
    private let stateDir: URL

    init(kernelPath: String, dindImage: String, rootfsSizeMiB: UInt64 = 8192, stateDir: URL) {
        self.kernelPath = kernelPath
        self.dindImage = dindImage
        self.rootfsSizeMiB = rootfsSizeMiB
        self.stateDir = stateDir
    }

    var count: Int { vms.count }

    // MARK: - Lifecycle

    func createVM(_ req: VMCreateRequest) async throws -> VMCreateResponse {
        let name = req.vm_name ?? "acvm-\(UUID().uuidString.prefix(8))"
        if vms[name] != nil {
            throw DaemonError.conflict("VM \(name) already exists")
        }

        let kernel = Kernel(path: URL(fileURLWithPath: kernelPath), platform: .linuxArm)
        let network: Network = try VmnetNetwork()
        var manager = try await ContainerManager(
            kernel: kernel,
            initfsReference: "vminit:latest",
            network: network,
            rosetta: false
        )

        let container = try await manager.create(
            name,
            reference: dindImage,
            rootfsSizeInBytes: rootfsSizeMiB * 1024 * 1024,
            readOnly: false,
            networking: true
        ) { config in
            // dockerd as PID 1. Use the dind image's entrypoint so it performs
            // the usual cgroup/iptables setup, then expose the API over TCP (for
            // the host bridge) and the conventional unix socket (in-VM use).
            config.process.arguments = [
                "dockerd-entrypoint.sh",
                "dockerd",
                "-H", "tcp://0.0.0.0:2375",
                "-H", "unix:///var/run/docker.sock",
            ]
            // DOCKER_TLS_CERTDIR="" disables docker:dind's default auto-TLS so
            // dockerd serves plain HTTP on :2375 (what the host bridge speaks).
            config.process.environmentVariables = [
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "DOCKER_TLS_CERTDIR=",
            ]
            config.process.workingDirectory = "/"
            config.process.capabilities = .allCapabilities
        }

        try await container.create()
        try await container.start()

        managers[name] = manager

        let ips = container.interfaces.map { $0.ipv4Address.address.description }
        guard let vmIP = ips.first else {
            try? await container.stop()
            managers.removeValue(forKey: name)
            throw DaemonError.internalError("VM \(name) came up with no IP address")
        }

        // Wait for dockerd to accept connections before handing the socket back.
        try await waitForDockerd(host: vmIP, port: 2375, timeout: 60)

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
        try? await r.container.stop()
        r.status = "stopped"
        vms[name] = r
    }

    func delete(_ name: String) async throws {
        guard let r = vms[name] else { throw DaemonError.notFound("VM \(name) not found") }
        r.bridge.stop()
        try? await r.container.stop()
        if var manager = managers[name] {
            try? manager.delete(name)
            managers.removeValue(forKey: name)
        }
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
