import Foundation

/// The user's standing approval to delete quarantined items once their 7 days are over, without asking each time
/// (docs/ARCHITECTURE.md, Quarantine: "a T3 plan that the user pre-approved"). It's signed with the approval key
/// (Touch ID or password) and checked against the key the helper has enrolled, so neither a rewritten file nor an
/// MCP client can turn automatic deletion on; after the key's monthly rotation it no longer matches and needs
/// approving again.
public struct AutoExpiryPolicy: Codable, Sendable, Equatable {
    public static let currentFormat = 1
    public static let domain = "farrier-auto-expiry-v1"

    public let format: Int
    public let retentionDays: Int
    public let approvedAt: Int64
    /// The Mac's hardware UUID: a copied policy doesn't apply elsewhere.
    public let host: String
    /// The approval key's public key (DER, base64), and its signature over `payload` (DER, base64).
    public let publicKey: String
    public let signature: String

    /// `"farrier-auto-expiry-v1" 0x00 | retentionDays | approvedAt | host`, newline-separated after the domain.
    public static func payload(retentionDays: Int, approvedAt: Int64, host: String) -> Data {
        var d = Data(domain.utf8)
        d.append(0)
        d.append(Data("\(retentionDays)\n\(approvedAt)\n\(host)".utf8))
        return d
    }

    public init(retentionDays: Int, approvedAt: Int64, host: String, publicKey: Data, signature: Data) {
        self.format = Self.currentFormat
        self.retentionDays = retentionDays
        self.approvedAt = approvedAt
        self.host = host
        self.publicKey = publicKey.base64EncodedString()
        self.signature = signature.base64EncodedString()
    }

    /// Why the policy can't be acted on, or nil when it can. `enrolledFingerprint` is the SHA-256 (hex) of the
    /// public key the helper has enrolled; nil when it can't be read, which also stops the run.
    public func problem(enrolledFingerprint: String?, host currentHost: String) -> String? {
        guard format == Self.currentFormat else { return "the approval was saved by another Farrier version; turn it on again" }
        guard retentionDays == Int(Quarantine.retention / 86_400) else {
            return "it was approved for \(retentionDays) days, but the quarantine keeps items \(Quarantine.retention / 86_400); turn it on again"
        }
        guard host == currentHost else { return "it was approved on another Mac" }
        guard let key = Data(base64Encoded: publicKey), let sig = Data(base64Encoded: signature) else {
            return "the saved approval can't be read; turn it on again"
        }
        guard let enrolledFingerprint else { return "the enrolled approval key can't be checked (is the helper running?)" }
        guard FarrierCrypto.sha256(key).hexString == enrolledFingerprint else {
            return "it was approved with an earlier approval key (keys are replaced every 30 days); approve it again with "
                + "`farrier quarantine auto-expire on`"
        }
        guard FarrierCrypto.isValidSignature(sig, for: Self.payload(retentionDays: retentionDays, approvedAt: approvedAt, host: host),
                                             publicKeyDER: key) else {
            return "the saved approval's signature doesn't verify; turn it on again"
        }
        return nil
    }
}

/// `~/Library/Application Support/Farrier/auto-expiry.json` (0600).
public struct AutoExpiryStore: Sendable {
    public let path: String

    public init(path: String) { self.path = path }

    public static var `default`: AutoExpiryStore {
        AutoExpiryStore(path: FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Farrier/auto-expiry.json").path)
    }

    public func load() -> AutoExpiryPolicy? {
        guard let data = FileManager.default.contents(atPath: path) else { return nil }
        return try? JSONDecoder().decode(AutoExpiryPolicy.self, from: data)
    }

    public var exists: Bool { FileManager.default.fileExists(atPath: path) }

    public func save(_ policy: AutoExpiryPolicy) throws {
        let dir = (path as NSString).deletingLastPathComponent
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: NSNumber(value: 0o700)])
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
        let tmp = path + ".tmp"
        guard FileManager.default.createFile(atPath: tmp, contents: try encoder.encode(policy),
                                             attributes: [.posixPermissions: NSNumber(value: 0o600)]),
              rename(tmp, path) == 0 else {
            throw PlanError("could not save \(path) (errno \(errno))")
        }
    }

    public func remove() throws {
        if exists { try FileManager.default.removeItem(atPath: path) }
    }
}

/// The LaunchAgent that runs `farrier quarantine expire-due` once a day (launchd catches up after sleep).
public enum ExpirySchedule {
    public static let label = "dev.farrier.quarantine-expiry"

    public static var plistPath: String {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/LaunchAgents/\(label).plist").path
    }

    public static func plist(executable: String, logDirectory: String, hour: Int = 11, minute: Int = 23) throws -> Data {
        let dict: [String: Any] = [
            "Label": label,
            "ProgramArguments": [executable, "quarantine", "expire-due"],
            "StartCalendarInterval": ["Hour": hour, "Minute": minute],
            "RunAtLoad": false,
            "ProcessType": "Background",
            "LowPriorityIO": true,
            "StandardOutPath": "\(logDirectory)/quarantine-expiry.log",
            "StandardErrorPath": "\(logDirectory)/quarantine-expiry.log",
        ]
        return try PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
    }

    /// Writes the agent and loads it (replacing an older one). macOS only.
    public static func install(executable: String, runner: CommandRunning = ProcessRunner()) throws {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let logs = "\(home)/Library/Logs/Farrier"
        try FileManager.default.createDirectory(atPath: logs, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: (plistPath as NSString).deletingLastPathComponent,
                                                withIntermediateDirectories: true)
        _ = runner.run("/bin/launchctl", ["bootout", "gui/\(getuid())/\(label)"], timeout: 10)
        guard FileManager.default.createFile(atPath: plistPath, contents: try plist(executable: executable, logDirectory: logs),
                                             attributes: [.posixPermissions: NSNumber(value: 0o644)]) else {
            throw PlanError("could not write \(plistPath)")
        }
        guard let r = runner.run("/bin/launchctl", ["bootstrap", "gui/\(getuid())", plistPath], timeout: 10), r.status == 0 else {
            throw PlanError("launchctl couldn't load \(plistPath)")
        }
    }

    public static func uninstall(runner: CommandRunning = ProcessRunner()) {
        _ = runner.run("/bin/launchctl", ["bootout", "gui/\(getuid())/\(label)"], timeout: 10)
        try? FileManager.default.removeItem(atPath: plistPath)
    }

    public static var installed: Bool { FileManager.default.fileExists(atPath: plistPath) }
}

extension CleanupApplier {
    /// The scheduled run: plans and deletes every quarantined plan past its days, under a policy the caller has
    /// checked. Nothing that's still within its days is touched.
    public static func expireDue(quarantine: Quarantine, host: String, now: Date = Date())
        -> (plan: Plan?, results: [CleanupItemResult]) {
        guard let plan = Planner.planExpiry(quarantine: quarantine, host: host, now: now).plan else { return (nil, []) }
        let results = (try? expire(plan, quarantine: quarantine, now: now)) ?? []
        return (plan, results)
    }
}
