import Foundation

/// What happened when collecting one fact. Shown by `farrier facts`, so a missing fact is never a mystery.
public struct CollectionNote: Sendable, Codable, Hashable {
    public enum Status: String, Sendable, Codable {
        case collected
        case unavailable  // the tool or file doesn't exist here (for example on Linux)
        case unparsed     // the tool ran, but its output wasn't recognised (a parser needs updating)
        case failed       // the tool failed or timed out
    }

    public let fact: String
    public let status: Status
    public let source: String
    public let detail: String?

    public init(fact: String, status: Status, source: String, detail: String?) {
        self.fact = fact
        self.status = status
        self.source = source
        self.detail = detail
    }
}

public struct CollectionResult: Sendable {
    public let facts: [String: FactValue]
    public let notes: [CollectionNote]

    public init(facts: [String: FactValue], notes: [CollectionNote]) {
        self.facts = facts
        self.notes = notes
    }

    /// Adds another result (for example the helper's T1 facts) to this one.
    public func merging(_ other: CollectionResult) -> CollectionResult {
        CollectionResult(facts: facts.merging(other.facts) { _, new in new }, notes: notes + other.notes)
    }
}

/// Collectors for the facts `posture.core` uses, all read-only and unprivileged (tier T0). Facts that need root
/// or Full Disk Access (installed profile payloads, launchd items with signatures, TCC grants) come with the
/// helper, through `readPrivileged`. The catalog is in docs/FACTS.md.
public struct SystemCollectors: Sendable {
    public let runner: CommandRunning
    public let readFile: @Sendable (String) -> Data?

    public init(runner: CommandRunning = ProcessRunner(),
                readFile: @escaping @Sendable (String) -> Data? = { FileManager.default.contents(atPath: $0) }) {
        self.runner = runner
        self.readFile = readFile
    }

    /// Fact id → how to collect it.
    struct Source: Sendable {
        let fact: String
        let executable: String
        let arguments: [String]
        let parse: @Sendable (CommandResult) -> FactValue?
    }

    static let commandSources: [Source] = [
        Source(fact: "os.version", executable: "/usr/bin/sw_vers", arguments: []) { Parsers.swVers($0.stdout) },
        Source(fact: "filevault.status", executable: "/usr/bin/fdesetup", arguments: ["status"]) { Parsers.fdesetupStatus($0.combined) },
        Source(fact: "sip.status", executable: "/usr/bin/csrutil", arguments: ["status"]) { Parsers.csrutilStatus($0.combined) },
        Source(fact: "gatekeeper.assessments", executable: "/usr/sbin/spctl", arguments: ["--status"]) { Parsers.spctlStatus($0.combined) },
        Source(fact: "firewall.globalState", executable: "/usr/libexec/ApplicationFirewall/socketfilterfw",
               arguments: ["--getglobalstate"]) { Parsers.firewallGlobalState($0.combined) },
        Source(fact: "mdm.enrollment", executable: "/usr/bin/profiles", arguments: ["status", "-type", "enrollment"]) {
            Parsers.profilesEnrollment($0.combined)
        },
    ]

    /// Software update settings: the local preferences, with managed preferences (from a profile) taking precedence.
    static let softwareUpdatePlist = "/Library/Preferences/com.apple.SoftwareUpdate.plist"
    static let softwareUpdateManagedPlist = "/Library/Managed Preferences/com.apple.SoftwareUpdate.plist"
    static let softwareUpdateKeys = [
        "AutomaticCheckEnabled", "AutomaticDownload", "CriticalUpdateInstall", "ConfigDataInstall",
        "AutomaticallyInstallMacOSUpdates", "AutomaticallyInstallAppUpdates",
    ]

    public func collect() -> CollectionResult {
        var facts: [String: FactValue] = [:]
        var notes: [CollectionNote] = []

        for source in Self.commandSources {
            let label = ([source.executable] + source.arguments).joined(separator: " ")
            guard let result = runner.run(source.executable, source.arguments, timeout: 10) else {
                notes.append(CollectionNote(fact: source.fact, status: .unavailable, source: label, detail: "not found"))
                continue
            }
            if result.timedOut {
                notes.append(CollectionNote(fact: source.fact, status: .failed, source: label, detail: "timed out"))
                continue
            }
            if let value = source.parse(result) {
                facts[source.fact] = value
                notes.append(CollectionNote(fact: source.fact, status: .collected, source: label, detail: nil))
            } else {
                let snippet = result.combined.trimmingCharacters(in: .whitespacesAndNewlines).prefix(160)
                notes.append(CollectionNote(fact: source.fact, status: result.status == 0 ? .unparsed : .failed,
                                            source: label, detail: "exit \(result.status): \(snippet)"))
            }
        }

        collectSoftwareUpdate(into: &facts, notes: &notes)
        return CollectionResult(facts: facts, notes: notes)
    }

    func collectSoftwareUpdate(into facts: inout [String: FactValue], notes: inout [CollectionNote]) {
        let fact = "softwareupdate.prefs"
        let local = readFile(Self.softwareUpdatePlist).flatMap(Parsers.propertyList)?.object
        let managed = readFile(Self.softwareUpdateManagedPlist).flatMap(Parsers.propertyList)?.object
        guard local != nil || managed != nil else {
            notes.append(CollectionNote(fact: fact, status: .unavailable, source: Self.softwareUpdatePlist, detail: "not found"))
            return
        }
        var merged: [String: FactValue] = [:]
        var managedKeys: [FactValue] = []
        for key in Self.softwareUpdateKeys {
            if let v = managed?[key] {
                merged[key] = v
                managedKeys.append(.string(key))
            } else if let v = local?[key] {
                merged[key] = v
            }
            // Absent keys stay absent: the posture engine reports them as unknown rather than guessing Apple's default.
        }
        facts[fact] = .object(merged)
        facts["softwareupdate.managedKeys"] = .array(managedKeys)
        notes.append(CollectionNote(fact: fact, status: .collected,
                                    source: managed == nil ? Self.softwareUpdatePlist : "\(Self.softwareUpdatePlist) + managed",
                                    detail: merged.count < Self.softwareUpdateKeys.count ? "\(Self.softwareUpdateKeys.count - merged.count) key(s) not set" : nil))
    }
}

/// Facts collected live, as a FactStore.
extension StaticFactStore {
    public init(_ result: CollectionResult) { self.init(result.facts) }
}
