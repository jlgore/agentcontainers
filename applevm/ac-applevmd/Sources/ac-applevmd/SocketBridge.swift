import Foundation
#if canImport(Darwin)
import Darwin
#endif

// SocketBridge accepts connections on a host unix domain socket and proxies each
// one to a TCP endpoint (the in-VM dockerd at <vm-ip>:2375). It is a thin,
// dependency-free byte pump: one accept loop, two relay threads per connection.
//
// This exists because the Go client expects a `unix://` Docker endpoint
// (SandboxRuntime dials `unix://<socketPath>`), while dockerd inside the VM is
// reachable over TCP on the vmnet interface.
final class SocketBridge: @unchecked Sendable {
    private let hostSocketPath: String
    private let targetHost: String
    private let targetPort: Int
    private var listenFD: Int32 = -1
    private var running = false
    private let queue = DispatchQueue(label: "ac-applevmd.bridge", attributes: .concurrent)

    init(hostSocketPath: String, targetHost: String, targetPort: Int) {
        self.hostSocketPath = hostSocketPath
        self.targetHost = targetHost
        self.targetPort = targetPort
    }

    func start() throws {
        unlink(hostSocketPath)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw DaemonError.internalError("socket(AF_UNIX) failed") }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        hostSocketPath.withCString { ptr in
            withUnsafeMutablePointer(to: &addr.sun_path) {
                $0.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: addr.sun_path)) { dst in
                    strncpy(dst, ptr, MemoryLayout.size(ofValue: addr.sun_path) - 1)
                }
            }
        }
        let len = socklen_t(MemoryLayout<sockaddr_un>.size)
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, len) }
        }
        guard bound == 0 else {
            close(fd)
            throw DaemonError.internalError("bind(\(hostSocketPath)) failed")
        }
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
            queue.async { [weak self] in self?.handle(clientFD: clientFD) }
        }
    }

    private func handle(clientFD: Int32) {
        guard let upstreamFD = SocketBridge.dialTCP(host: targetHost, port: targetPort) else {
            close(clientFD)
            return
        }
        // Relay both directions; when either side closes, tear both down.
        let group = DispatchGroup()
        queue.async(group: group) { SocketBridge.relay(from: clientFD, to: upstreamFD) }
        queue.async(group: group) { SocketBridge.relay(from: upstreamFD, to: clientFD) }
        group.notify(queue: queue) {
            close(clientFD)
            close(upstreamFD)
        }
    }

    private static func relay(from: Int32, to: Int32) {
        var buf = [UInt8](repeating: 0, count: 32 * 1024)
        while true {
            let n = read(from, &buf, buf.count)
            if n <= 0 { break }
            var off = 0
            while off < n {
                let w = write(to, &buf[off], n - off)
                if w <= 0 { return }
                off += w
            }
        }
    }

    static func dialTCP(host: String, port: Int) -> Int32? {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &res) == 0, let info = res else { return nil }
        defer { freeaddrinfo(res) }
        var ai: UnsafeMutablePointer<addrinfo>? = info
        while let cur = ai {
            let fd = socket(cur.pointee.ai_family, cur.pointee.ai_socktype, cur.pointee.ai_protocol)
            if fd >= 0 {
                if connect(fd, cur.pointee.ai_addr, cur.pointee.ai_addrlen) == 0 {
                    return fd
                }
                close(fd)
            }
            ai = cur.pointee.ai_next
        }
        return nil
    }

    static func canConnect(host: String, port: Int) -> Bool {
        if let fd = dialTCP(host: host, port: port) {
            close(fd)
            return true
        }
        return false
    }
}
