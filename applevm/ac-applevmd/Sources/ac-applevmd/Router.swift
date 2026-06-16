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

        do {
            switch (method, parts) {
            case (.GET, ["health"]):
                let h = HealthResponse(status: "healthy", version: version, vms: await manager.count)
                return ok(h)

            case (.POST, ["vm"]):
                let req = try decode(VMCreateRequest.self, body)
                let resp = try await manager.createVM(req)
                return ok(resp)

            case (.GET, ["vm"]):
                return ok(await manager.list())

            case (.GET, ["vm", let name]):
                return ok(try await manager.inspect(name))

            case (.POST, ["vm", let name, "stop"]):
                try await manager.stop(name)
                return ok(MessageResponse(message: "VM stopped"))

            case (.DELETE, ["vm", let name]):
                try await manager.delete(name)
                return Result(status: .noContent, body: Data())

            case (.POST, ["vm", let name, "keepalive"]):
                try await manager.keepalive(name)
                return ok(MessageResponse(message: "keepalive received"))

            case (.POST, ["network", "proxyconfig"]):
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
