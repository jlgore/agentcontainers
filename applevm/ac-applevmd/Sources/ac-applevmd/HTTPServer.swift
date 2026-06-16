import Foundation
import NIOCore
import NIOPosix
import NIOHTTP1

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
        FileHandle.standardError.write(Data("[ac-applevmd] listening on \(socketPath)\n".utf8))
        try channel.closeFuture.wait()
    }

    private func unlinkExisting() {
        try? FileManager.default.removeItem(atPath: socketPath)
        try? FileManager.default.createDirectory(
            atPath: (socketPath as NSString).deletingLastPathComponent,
            withIntermediateDirectories: true
        )
    }
}

private final class RequestHandler: ChannelInboundHandler {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    private let manager: VMManager
    private let version: String
    private var head: HTTPRequestHead?
    private var body: ByteBuffer?

    init(manager: VMManager, version: String) {
        self.manager = manager
        self.version = version
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head(let h):
            head = h
            body = context.channel.allocator.buffer(capacity: 0)
        case .body(var chunk):
            body?.writeBuffer(&chunk)
        case .end:
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
