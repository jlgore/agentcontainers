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
