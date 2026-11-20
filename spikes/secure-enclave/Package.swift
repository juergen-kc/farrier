// swift-tools-version:5.10
// Spike: approval with a Secure Enclave key gated by user presence (see README.md).
// No dependencies, so it builds offline with Xcode or the Command Line Tools.
import PackageDescription

let package = Package(
    name: "se-spike",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(
            name: "se-spike",
            path: "Sources/se-spike",
            linkerSettings: [
                .linkedFramework("CryptoKit"),
                .linkedFramework("LocalAuthentication"),
                .linkedFramework("Security"),
            ]
        )
    ],
    swiftLanguageVersions: [.v5]
)
