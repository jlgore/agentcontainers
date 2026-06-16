import Foundation
import NIOHTTP1

// Router maps HTTP method+path to VMManager operations and encodes JSON
// responses. Kept transport-agnostic (takes raw method/uri/body) so it is easy
// to unit-test without standing up a socket.
struct Router {
    let manager: VMManager
    let version: String

    struct Result {
        let status: HTTPResponseStatus
        let body: Data
    }

    func route(method: HTTPMethod, uri: String, body: Data) async -> Result {
        // Strip any query string.
        let path = String(uri.split(separator: "?", maxSplits: 1).first ?? "")
        let parts = path.split(separator: "/").map(String.init)

        // Swift patterns can't bind inside array literals, so match on
        // (method, segment count) with `where` guards and index into `parts`.
        do {
            switch (method, parts.count) {
            case (.GET, 1) where parts[0] == "health":
                let h = HealthResponse(status: "healthy", version: version, vms: await manager.count)
                return ok(h)

            case (.POST, 1) where parts[0] == "vm":
                let req = try decode(VMCreateRequest.self, body)
                let resp = try await manager.createVM(req)
                return ok(resp)

            case (.GET, 1) where parts[0] == "vm":
                return ok(await manager.list())

            case (.GET, 2) where parts[0] == "vm":
                return ok(try await manager.inspect(parts[1]))

            case (.POST, 3) where parts[0] == "vm" && parts[2] == "stop":
                try await manager.stop(parts[1])
                return ok(MessageResponse(message: "VM stopped"))

            case (.DELETE, 2) where parts[0] == "vm":
                try await manager.delete(parts[1])
                return Result(status: .noContent, body: Data())

            case (.POST, 3) where parts[0] == "vm" && parts[2] == "keepalive":
                try await manager.keepalive(parts[1])
                return ok(MessageResponse(message: "keepalive received"))

            case (.POST, 2) where parts[0] == "network" && parts[1] == "proxyconfig":
                let req = try decode(ProxyConfigRequest.self, body)
                try await manager.updateProxyConfig(req)
                return ok(MessageResponse(message: "proxy config accepted"))

            default:
                return error(.notFound, "no route for \(method.rawValue) \(path)")
            }
        } catch let e as DaemonError {
            return mapError(e)
        } catch {
            return self.error(.internalServerError, "\(error)")
        }
    }

    // MARK: - Encoding helpers

    private func ok<T: Encodable>(_ value: T) -> Result {
        do {
            return Result(status: .ok, body: try JSONEncoder().encode(value))
        } catch {
            return self.error(.internalServerError, "encode: \(error)")
        }
    }

    private func decode<T: Decodable>(_ type: T.Type, _ data: Data) throws -> T {
        do {
            return try JSONDecoder().decode(type, from: data)
        } catch {
            throw DaemonError.badRequest("invalid request body: \(error)")
        }
    }

    private func error(_ status: HTTPResponseStatus, _ message: String) -> Result {
        let body = (try? JSONEncoder().encode(["error": message])) ?? Data("{}".utf8)
        return Result(status: status, body: body)
    }

    private func mapError(_ e: DaemonError) -> Result {
        switch e {
        case .notFound(let m): return error(.notFound, m)
        case .conflict(let m): return error(.conflict, m)
        case .badRequest(let m): return error(.badRequest, m)
        case .internalError(let m): return error(.internalServerError, m)
        }
    }
}
