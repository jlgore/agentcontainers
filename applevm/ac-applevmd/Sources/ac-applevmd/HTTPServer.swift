import Foundation
import NIOCore
import NIOPosix
import NIOHTTP1
#if canImport(Darwin)
import Darwin
#endif

// HTTPServer serves the sandboxd-shaped control API over a unix domain socket
// using SwiftNIO. Routes are dispatched to VMManager. Responses are JSON.
//
// Routes (mirrors internal/sandbox/client.go):
//   GET    /health
//   POST   /vm
//   GET    /vm
//   GET    /vm/{name}
//   POST   /vm/{name}/stop
//   DELETE /vm/{name}
//   POST   /vm/{name}/keepalive
//   POST   /network/proxyconfig
final class HTTPServer {
    private let manager: VMManager
    private let version: String
    private let socketPath: String

    init(manager: VMManager, version: String, socketPath: String) {
        self.manager = manager
        self.version = version
        self.socketPath = socketPath
    }

    func run() throws {
        unlinkExisting()
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 2)
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.backlog, value: 64)
            .childChannelInitializer { channel in
                channel.pipeline.configureHTTPServerPipeline().flatMap {
                    channel.pipeline.addHandler(RequestHandler(manager: self.manager, version: self.version))
                }
            }
        let channel = try bootstrap.bind(unixDomainSocketPath: socketPath).wait()
        // The control socket can create/stop/delete VMs as root. Restrict it to
        // the daemon's user so no other local account can drive it.
        chmod(socketPath, 0o600)
        FileHandle.standardError.write(Data("[ac-applevmd] listening on \(socketPath)\n".utf8))
        try channel.closeFuture.wait()
    }

    private func unlinkExisting() {
        // Refuse to follow a symlink planted at the socket path — removing it
        // would delete the link's target, and binding through it is a TOCTOU
        // vector. Combined with the 0700 parent dir below, the race is closed.
        let attrs = try? FileManager.default.attributesOfItem(atPath: socketPath)
        if let type = attrs?[.type] as? FileAttributeType, type == .typeSymbolicLink {
            FileHandle.standardError.write(
                Data("[ac-applevmd] refusing to unlink symlink at \(socketPath)\n".utf8))
            exit(1)
        }
        try? FileManager.default.removeItem(atPath: socketPath)
        let parent = (socketPath as NSString).deletingLastPathComponent
        try? FileManager.default.createDirectory(
            atPath: parent, withIntermediateDirectories: true)
        // Restrict the socket directory to the daemon's user.
        chmod(parent, 0o700)
    }
}

private final class RequestHandler: ChannelInboundHandler {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    // Cap accumulated request bodies so a malicious or buggy client can't OOM
    // the daemon by streaming an unbounded POST.
    private static let maxBodySize = 1_048_576  // 1 MiB

    private let manager: VMManager
    private let version: String
    private var head: HTTPRequestHead?
    private var body: ByteBuffer?
    private var rejected = false

    init(manager: VMManager, version: String) {
        self.manager = manager
        self.version = version
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head(let h):
            head = h
            body = context.channel.allocator.buffer(capacity: 0)
            rejected = false
        case .body(var chunk):
            if rejected { return }
            body?.writeBuffer(&chunk)
            if let b = body, b.readableBytes > RequestHandler.maxBodySize {
                rejected = true
                body = nil
                RequestHandler.write(channel: context.channel, status: .payloadTooLarge,
                    json: Data("{\"error\":\"request body too large\"}".utf8))
                context.close(promise: nil)
            }
        case .end:
            if rejected { rejected = false; return }
            guard let head else { return }
            let bodyData = body.flatMap { $0.getData(at: $0.readerIndex, length: $0.readableBytes) } ?? Data()
            let channel = context.channel
            let router = Router(manager: manager, version: version)
            // Bridge NIO -> async actor work, then write the response back on the loop.
            Task {
                let result = await router.route(method: head.method, uri: head.uri, body: bodyData)
                channel.eventLoop.execute {
                    RequestHandler.write(channel: channel, status: result.status, json: result.body)
                }
            }
        }
    }

    static func write(channel: Channel, status: HTTPResponseStatus, json: Data) {
        var headers = HTTPHeaders()
        headers.add(name: "Content-Type", value: "application/json")
        headers.add(name: "Content-Length", value: String(json.count))
        let head = HTTPResponseHead(version: .http1_1, status: status, headers: headers)
        _ = channel.write(NIOAny(HTTPServerResponsePart.head(head)))
        var buf = channel.allocator.buffer(capacity: json.count)
        buf.writeBytes(json)
        _ = channel.write(NIOAny(HTTPServerResponsePart.body(.byteBuffer(buf))))
        _ = channel.writeAndFlush(NIOAny(HTTPServerResponsePart.end(nil)))
    }
}
