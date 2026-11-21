// swift-tools-version:6.1
// Farrier: see README.md and docs/ARCHITECTURE.md.
//
// FarrierCore is platform-independent (rule packs, posture, collectors and parsers) and tested on Linux in CI.
// FarrierHelperKit and farrier-helper are the privileged helper's shared code and daemon: their macOS parts are
// behind `#if os(macOS)`, so the whole package still builds on Linux. They use the Swift 5 language mode because
// NSXPC and its reply blocks predate Swift 6 strict concurrency; FarrierCore and the CLI use Swift 6.
import PackageDescription

let package = Package(
    name: "Farrier",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "farrier", targets: ["farrier"]),
        .library(name: "FarrierCore", targets: ["FarrierCore"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.5.0"),
        .package(url: "https://github.com/jpsim/Yams.git", from: "6.0.0"),
        // SHA-256 and P-256 on Linux (CI tests the approval and journal code there). On macOS, CryptoKit is used.
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
        // The MCP server (`farrier mcp`). Pinned: the MCP SDK spike validated exactly this version with Claude Code
        // (protocol 2025-11-25). swift-log is needed for the transport wrapper's logger.
        .package(url: "https://github.com/modelcontextprotocol/swift-sdk.git", exact: "0.12.1"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.5.0"),
    ],
    targets: [
        .target(
            name: "FarrierCore",
            dependencies: [
                .product(name: "Yams", package: "Yams"),
                .product(name: "Crypto", package: "swift-crypto", condition: .when(platforms: [.linux])),
            ]
        ),
        .target(
            name: "FarrierHelperKit",
            dependencies: ["FarrierCore"],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        // What the CLI and the MCP server share (fact collection, posture, plans, apply), and the MCP server.
        .target(
            name: "FarrierMCP",
            dependencies: [
                "FarrierCore",
                "FarrierHelperKit",
                .product(name: "MCP", package: "swift-sdk"),
                .product(name: "Logging", package: "swift-log"),
            ],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .executableTarget(
            name: "farrier",
            dependencies: [
                "FarrierCore",
                "FarrierHelperKit",
                "FarrierMCP",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ]
        ),
        .executableTarget(
            name: "farrier-helper",
            dependencies: ["FarrierCore", "FarrierHelperKit"],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .testTarget(
            name: "FarrierCoreTests",
            dependencies: [
                "FarrierCore",
                "FarrierHelperKit",
                "FarrierMCP",
                .product(name: "MCP", package: "swift-sdk"),
                .product(name: "Crypto", package: "swift-crypto", condition: .when(platforms: [.linux])),
            ]
        ),
    ],
    swiftLanguageModes: [.v6]
)
