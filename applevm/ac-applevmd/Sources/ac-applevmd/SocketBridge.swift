import Foundation
import Containerization
#if canImport(Darwin)
import Darwin
#endif

// SocketBridge accepts connections on a host unix domain socket and proxies each
// one to a guest **vsock** port (the in-VM relay fronting dockerd's
// /var/run/docker.sock). It is a thin, dependency-free byte pump: one accept
// loop, two relay directions per connection.
//
// This exists because the Go client expects a `unix://` Docker endpoint
// (SandboxRuntime dials `unix://<socketPath>`), while dockerd inside the VM is
// reachable only over the hypervisor-mediated vsock channel — never over TCP on
// vmnet. vsock is point-to-point between this host process (which owns the
// VZVirtualMachine) and the guest kernel: no IP, no routing, no other host
// process can reach it. The upstream dial uses
// LinuxContainer.dialVsock(port:), which returns a connected FileHandle.
final class SocketBridge: @unchecked Sendable {
    private let hostSocketPath: String
    private let container: LinuxContainer
    private let vsockPort: UInt32
    private var listenFD: Int32 = -1
    private var running = false
    private let queue = DispatchQueue(label: "ac-applevmd.bridge", attributes: .concurrent)

    init(hostSocketPath: String, container: LinuxContainer, vsockPort: UInt32) {
        self.hostSocketPath = hostSocketPath
        self.container = container
        self.vsockPort = vsockPort
    }

    func start() throws {
        var addr = sockaddr_un()
        let capacity = MemoryLayout.size(ofValue: addr.sun_path) // sun_path bytes (incl. NUL)
        let pathBytes = Array(hostSocketPath.utf8)
        // Fail loudly rather than binding a silently truncated path — a truncated
        // socket would bind somewhere unexpected and the Go client could never
        // dial the path we returned to it.
        guard pathBytes.count < capacity else {
            throw DaemonError.internalError(
                "socket path too long (\(pathBytes.count) bytes, max \(capacity - 1)): \(hostSocketPath)")
        }

        unlink(hostSocketPath)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw DaemonError.internalError("socket(AF_UNIX) failed") }

        addr.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            let dst = raw.bindMemory(to: CChar.self)
            for i in 0..<pathBytes.count { dst[i] = CChar(bitPattern: pathBytes[i]) }
            dst[pathBytes.count] = 0
        }
        let len = socklen_t(MemoryLayout<sockaddr_un>.size)
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, len) }
        }
        guard bound == 0 else {
            close(fd)
            throw DaemonError.internalError("bind(\(hostSocketPath)) failed")
        }
        // Restrict the per-VM docker socket to the daemon's user. It is a
        // root-equivalent Docker control channel; anyone who can connect gets
        // full API access, so deny group/other.
        chmod(hostSocketPath, 0o600)
        guard listen(fd, 64) == 0 else {
            close(fd)
            throw DaemonError.internalError("listen() failed")
        }
        listenFD = fd
        running = true
        queue.async { [weak self] in self?.acceptLoop() }
    }

    func stop() {
        running = false
        if listenFD >= 0 { close(listenFD); listenFD = -1 }
        unlink(hostSocketPath)
    }

    private func acceptLoop() {
        while running {
            let clientFD = accept(listenFD, nil, nil)
            if clientFD < 0 {
                if running { continue }
                break
            }
            handle(clientFD: clientFD)
        }
    }

    private func handle(clientFD: Int32) {
        // dialVsock is async; hop onto a Task to open the guest connection, then
        // pump bytes on the concurrent queue. The FileHandle owns the connected
        // fd and is kept alive until both relay directions finish — closing it
        // (not a bare close()) tears the vsock connection down exactly once.
        let container = self.container
        let port = self.vsockPort
        let queue = self.queue
        Task {
            let upstream: FileHandle
            do {
                upstream = try await container.dialVsock(port: port)
            } catch {
                close(clientFD)
                return
            }
            let upstreamFD = upstream.fileDescriptor
            let group = DispatchGroup()
            queue.async(group: group) { SocketBridge.relay(from: clientFD, to: upstreamFD) }
            queue.async(group: group) { SocketBridge.relay(from: upstreamFD, to: clientFD) }
            group.notify(queue: queue) {
                close(clientFD)
                // Closing the FileHandle closes upstreamFD; do NOT close(upstreamFD)
                // separately or we double-close. Capturing `upstream` here is what
                // keeps it (and its fd) alive for the connection's lifetime.
                try? upstream.close()
            }
        }
    }

    private static func relay(from: Int32, to: Int32) {
        let bufSize = 32 * 1024
        let buf = UnsafeMutableRawPointer.allocate(byteCount: bufSize, alignment: 1)
        defer {
            buf.deallocate()
            // Unblock the paired relay reading the other direction so the
            // connection tears down promptly instead of hanging on read().
            shutdown(from, Int32(SHUT_RD))
            shutdown(to, Int32(SHUT_WR))
        }
        while true {
            let n = read(from, buf, bufSize)
            if n <= 0 { break }
            var off = 0
            while off < n {
                let w = write(to, buf + off, n - off)
                if w <= 0 { return }
                off += w
            }
        }
    }
}
