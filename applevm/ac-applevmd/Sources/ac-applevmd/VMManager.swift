import Foundation
import Containerization

// VMManager owns the lifecycle of Apple containerization microVMs and the
// host-side socket bridges that expose each VM's private Docker daemon.
//
// One VM == one microVM running a docker-in-docker image. dockerd inside the VM
// listens only on its unix socket; an in-VM relay fronts it on a fixed vsock
// port. For each VM we open a host unix socket and proxy every connection over
// vsock (LinuxContainer.dialVsock), so the Go client can talk to a normal
// `unix://` Docker endpoint exactly as it does with sandboxd. vsock is mediated
// by the hypervisor — no IP, no routing, unreachable by any other host process,
// unlike the previous TCP-on-vmnet exposure.
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
        // The name flows into a filesystem path (stateDir/<name>/docker.sock) and
        // is the VM dictionary key. Reject anything that could traverse out of
        // stateDir or collide with shell/path semantics. The auto-generated
        // acvm-XXXXXXXX names already satisfy this.
        let namePattern = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/
        guard name.wholeMatch(of: namePattern) != nil else {
            throw DaemonError.badRequest(
                "invalid vm_name: must be 1-64 characters of [A-Za-z0-9._-], starting alphanumeric")
        }
        if vms[name] != nil {
            throw DaemonError.conflict("VM \(name) already exists")
        }

        // Captured into the @Sendable create closure (plain String/struct values
        // are Sendable). SandboxMount is Codable + value-typed, so the array is
        // safe to capture.
        let workspaceDir = req.workspace_dir
        let extraMounts = req.mounts ?? []

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
            // the usual cgroup/iptables setup. dockerd listens ONLY on the
            // conventional unix socket; the host reaches it over vsock via the
            // in-VM relay (see dind-enforcer/dockerd-entrypoint.sh). No TCP
            // listener on vmnet — that was a root-equivalent unauth exposure.
            config.process.arguments = [
                "dockerd-entrypoint.sh",
                "dockerd",
                "-H", "unix:///var/run/docker.sock",
            ]
            // Keep DOCKER_TLS_CERTDIR="" set: docker:dind defaults it to /certs
            // when UNSET, which makes its entrypoint auto-add a
            // `-H tcp://0.0.0.0:2376 --tlsverify` listener on vmnet. Setting it
            // empty disables that auto-listener so dockerd stays unix-only.
            config.process.environmentVariables = [
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "DOCKER_TLS_CERTDIR=",
            ]
            config.process.workingDirectory = "/"
            config.process.capabilities = .allCapabilities

            // Share the host workspace into the VM at the same path so the
            // in-VM dockerd can bind-mount it into the agent container (the Go
            // runtime binds workspacePath:workspacePath). Without this the bind
            // fails with "bind source path does not exist" inside the VM. The
            // workspace is the agent's working dir, so it stays read-write.
            if !workspaceDir.isEmpty {
                config.mounts.append(
                    Containerization.Mount.share(source: workspaceDir, destination: workspaceDir)
                )
            }

            // Share any additional host mounts (e.g. read-only evidence dirs)
            // into the VM at the SAME host path (identity), honoring the
            // read-only flag. The share destination must equal the host source
            // because the Go runtime then bind-mounts source->target into the
            // agent container, and the in-VM dockerd resolves that bind source
            // against the VM filesystem. The container-level remap to `target`
            // happens on the Go side, not here. Read-only is enforced at the
            // virtiofs share via options:["ro"] (Mount.readonly checks
            // options.contains("ro")).
            for m in extraMounts {
                config.mounts.append(
                    Containerization.Mount.share(
                        source: m.source,
                        destination: m.source,
                        options: (m.readonly ?? false) ? ["ro"] : []
                    )
                )
            }
        }

        try await container.create()
        try await container.start()
        managers[name] = manager

        // The VM is now running but not yet tracked. Any failure between here
        // and committing the record must tear the VM down, or we orphan a
        // running microVM and leak manager state. (On a SocketBridge.start()
        // failure the bridge already closes its own fd; nothing after a
        // successful bridge.start() can throw, so the catch need not stop it.)
        let record: VMRecord
        do {
            // vmnet IPs are recorded for container networking/introspection, but
            // the Docker control channel no longer depends on them — vsock is
            // available as soon as the VM boots, before vmnet assigns an IP.
            let ips = container.interfaces.map { $0.ipv4Address.address.description }

            // Wait for the in-VM vsock relay (and dockerd behind it) to accept
            // connections before handing the socket back. The relay starts only
            // after `docker info` succeeds inside the VM, so a successful dial
            // means dockerd is ready.
            try await waitForDockerd(container: container, port: dockerdVsockPort, timeout: 60)

            // Stand up the host unix socket -> guest vsock proxy.
            let sockPath = stateDir.appendingPathComponent("\(name)/docker.sock").path
            try FileManager.default.createDirectory(
                atPath: (sockPath as NSString).deletingLastPathComponent,
                withIntermediateDirectories: true
            )
            let bridge = SocketBridge(
                hostSocketPath: sockPath, container: container, vsockPort: dockerdVsockPort)
            try bridge.start()

            record = VMRecord(
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
        } catch {
            try? await container.stop()
            if var m = managers[name] { try? m.delete(name) }
            managers.removeValue(forKey: name)
            throw error
        }
        vms[name] = record

        // NOTE (parity gap vs sandboxd): no MITM egress proxy yet, so no CA cert
        // and no proxy env vars. The Go side treats empty ca_cert_data as
        // "skip CA injection". credential_sources / service_auth_config are
        // accepted on the request but not yet enforced. See README.
        return VMCreateResponse(
            vm_id: record.id,
            vm_config: VMConfig(socketPath: record.hostSocketPath),
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

    private func waitForDockerd(
        container: LinuxContainer, port: UInt32, timeout: TimeInterval) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if let fh = try? await container.dialVsock(port: port) {
                try? fh.close()
                return
            }
            try await Task.sleep(nanoseconds: 500_000_000)
        }
        throw DaemonError.internalError(
            "dockerd did not become reachable over vsock port \(port)")
    }
}

enum DaemonError: Error {
    case notFound(String)
    case conflict(String)
    case badRequest(String)
    case internalError(String)
}
