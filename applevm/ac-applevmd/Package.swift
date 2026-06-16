// swift-tools-version: 6.2
import PackageDescription

// ac-applevmd — a helper daemon that boots Linux microVMs via Apple's
// open-source containerization library and runs a private Docker daemon inside
// each one, exposing its socket back to the host. It speaks the same
// HTTP-over-unix-socket contract as Docker Desktop's sandboxd so the Go
// agentcontainers CLI can drive it via the existing sandbox runtime
// (see internal/container/applevm.go, internal/applevm).
//
// Requirements: macOS 26+ on Apple silicon, Xcode 26. See README.md.
let package = Package(
    name: "ac-applevmd",
    platforms: [
        .macOS("26.0")
    ],
    dependencies: [
        // Apple containerization: the microVM + OCI runtime library.
        // Pinned to a specific revision for reproducible builds. This is the
        // commit the daemon is built and API-verified against (dialVsock,
        // Mount.share(options:)). Bump deliberately, not implicitly via `main`.
        // NB: this is the *library* pin and is independent of the kernel
        // base-config ref in .github/workflows/applevm-kernel.yml.
        .package(url: "https://github.com/apple/containerization.git",
                 revision: "1437c67f5a07cb39e8f5e79d0b5aeac0327932bd"),
        // SwiftNIO: robust HTTP/1 server over a unix domain socket.
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.65.0"),
    ],
    targets: [
        .executableTarget(
            name: "ac-applevmd",
            dependencies: [
                .product(name: "Containerization", package: "containerization"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOFoundationCompat", package: "swift-nio"),
            ]
        )
    ]
)
