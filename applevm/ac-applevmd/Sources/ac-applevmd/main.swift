import Foundation

// ac-applevmd entry point.
//
// Configuration via environment (all optional):
//   AC_APPLEVM_API     control socket path
//                      (default ~/.agentcontainers/applevm/applevmd.sock)
//   AC_APPLEVM_KERNEL  path to the Linux kernel image for the microVMs
//                      (default ~/.agentcontainers/applevm/kernel)
//   AC_APPLEVM_DIND_IMAGE  docker-in-docker workload image (default docker:dind)
//   AC_APPLEVM_STATE   directory for per-VM host sockets
//                      (default ~/.agentcontainers/applevm/vms)

let version = "0.1.0"

func env(_ key: String) -> String? {
    let v = ProcessInfo.processInfo.environment[key]
    return (v?.isEmpty ?? true) ? nil : v
}

let home = FileManager.default.homeDirectoryForCurrentUser
let base = home.appendingPathComponent(".agentcontainers/applevm")

let socketPath = env("AC_APPLEVM_API") ?? base.appendingPathComponent("applevmd.sock").path
let kernelPath = env("AC_APPLEVM_KERNEL") ?? base.appendingPathComponent("kernel").path
let dindImage = env("AC_APPLEVM_DIND_IMAGE") ?? "docker:dind"
let stateDir = URL(fileURLWithPath: env("AC_APPLEVM_STATE") ?? base.appendingPathComponent("vms").path)

let manager = VMManager(kernelPath: kernelPath, dindImage: dindImage, stateDir: stateDir)
let server = HTTPServer(manager: manager, version: version, socketPath: socketPath)

FileHandle.standardError.write(Data("[ac-applevmd] v\(version) starting (kernel=\(kernelPath), dind=\(dindImage))\n".utf8))

do {
    try server.run()
} catch {
    FileHandle.standardError.write(Data("[ac-applevmd] fatal: \(error)\n".utf8))
    exit(1)
}
