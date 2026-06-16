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
        // Pin to a tag once you settle on a version; main is used here for the
        // initial spike.
        .package(url: "https://github.com/apple/containerization.git", branch: "main"),
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
