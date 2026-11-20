// swift-tools-version:5.10
// Spikes: privileged helper via SMAppService + XPC, and (since the MCP SDK spike) `farrier-spike mcp`.
// The MCP SDK itself declares swift-tools-version 6.1, so building needs a Swift 6.1+ toolchain (Xcode 16.3+).
import PackageDescription

let package = Package(
    name: "farrier-spike",
    platforms: [.macOS(.v14)],
    dependencies: [
        // Pinned exactly: the spike documents the behaviour of this version. 0.12.1 supports MCP protocol
        // versions up to 2025-11-25 (not 2026-07-28), and has no Tasks extension.
        .package(url: "https://github.com/modelcontextprotocol/swift-sdk.git", exact: "0.12.1"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.5.0"),
    ],
    targets: [
        // Shared by client and helper: constants, the XPC protocol, the approval payload format, the TCC probe.
        .target(name: "SpikeShared", path: "Sources/SpikeShared"),
        // The user-side CLI and MCP server. It is the app bundle's main executable.
        .executableTarget(
            name: "farrier-spike",
            dependencies: [
                "SpikeShared",
                .product(name: "MCP", package: "swift-sdk"),
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Sources/farrier-spike"
        ),
        // The root LaunchDaemon, started on demand by launchd. No MCP dependency.
        .executableTarget(name: "farrier-spike-helper", dependencies: ["SpikeShared"], path: "Sources/farrier-spike-helper"),
    ],
    swiftLanguageVersions: [.v5]
)
