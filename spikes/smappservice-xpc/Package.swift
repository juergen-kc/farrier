// swift-tools-version:5.10
// Spike: privileged helper via SMAppService + XPC (see README.md). No dependencies.
import PackageDescription

let package = Package(
    name: "farrier-spike",
    platforms: [.macOS(.v14)],
    targets: [
        // Shared by client and helper: constants, the XPC protocol, the approval payload format.
        .target(name: "SpikeShared", path: "Sources/SpikeShared"),
        // The user-side CLI. It is the app bundle's main executable.
        .executableTarget(name: "farrier-spike", dependencies: ["SpikeShared"], path: "Sources/farrier-spike"),
        // The root LaunchDaemon, started on demand by launchd.
        .executableTarget(name: "farrier-spike-helper", dependencies: ["SpikeShared"], path: "Sources/farrier-spike-helper"),
    ],
    swiftLanguageVersions: [.v5]
)
