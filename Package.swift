// swift-tools-version:6.1
// Farrier: see README.md and docs/ARCHITECTURE.md.
//
// v0.1 foundation: the platform-independent core (rule packs, linting, posture evaluation) and the CLI.
// macOS collectors, the privileged helper and the MCP server come in later PRs as separate targets, so
// FarrierCore stays buildable and testable on Linux in CI.
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
    ],
    targets: [
        .target(
            name: "FarrierCore",
            dependencies: [.product(name: "Yams", package: "Yams")]
        ),
        .executableTarget(
            name: "farrier",
            dependencies: [
                "FarrierCore",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ]
        ),
        .testTarget(
            name: "FarrierCoreTests",
            dependencies: ["FarrierCore"]
        ),
    ],
    swiftLanguageModes: [.v6]
)
