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
    /// When both have a note for the same fact, the one that collected it wins (the other's note is dropped), so a
    /// fact is never shown as both collected and unavailable. If both collected it, `other`'s value and note win.
    public func merging(_ other: CollectionResult) -> CollectionResult {
        let mine = notes.filter { other.facts[$0.fact] == nil }
        let theirs = other.notes.filter { other.facts[$0.fact] != nil || facts[$0.fact] == nil }
        return CollectionResult(facts: facts.merging(other.facts) { _, new in new }, notes: mine + theirs)
    }
}

/// Collectors for the facts `posture.core` uses, all read-only and unprivileged (tier T0). Facts that need root
/// or Full Disk Access (installed profile payloads, TCC grants) come with the helper, through `readPrivileged`.
/// The catalog is in docs/FACTS.md.
public struct SystemCollectors: Sendable {
    public let runner: CommandRunning
    public let readFile: @Sendable (String) -> Data?
    /// Separate from `readFile`, so an absent file can be told apart from one that exists but can't be read.
    public let fileExists: @Sendable (String) -> Bool
    public let signatures: CodeSignatureChecking

    public init(runner: CommandRunning = ProcessRunner(),
                readFile: @escaping @Sendable (String) -> Data? = { FileManager.default.contents(atPath: $0) },
                fileExists: @escaping @Sendable (String) -> Bool = { FileManager.default.fileExists(atPath: $0) },
                signatures: CodeSignatureChecking = SecurityFrameworkSignatures()) {
        self.runner = runner
        self.readFile = readFile
        self.fileExists = fileExists
        self.signatures = signatures
    }

    /// A property-list file: absent (nil, nil), read (object, nil), or present but unreadable/corrupt (nil, problem).
    func loadPlist(_ path: String) -> (object: [String: FactValue]?, problem: String?) {
        guard fileExists(path) else { return (nil, nil) }
        guard let data = readFile(path) else { return (nil, "cannot read \(path)") }
        guard let object = Parsers.propertyList(data)?.object else { return (nil, "cannot parse \(path)") }
        return (object, nil)
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
        Source(fact: "firewall.stealthMode", executable: "/usr/libexec/ApplicationFirewall/socketfilterfw",
               arguments: ["--getstealthmode"]) { Parsers.firewallStealthMode($0.combined) },
        // Sockets of all users are listed without privileges (no process names, which would need root).
        Source(fact: "network.listeningTCP", executable: "/usr/sbin/netstat", arguments: ["-anp", "tcp"]) {
            Parsers.listeningTCPPorts($0.stdout)
        },
    ]

    /// Commands that legitimately print nothing when run unprivileged, and why.
    static let emptyOutputHints: [String: String] = [
        "network.listeningTCP": "no sockets visible without privileges (macOS 27+); the privileged helper collects it",
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
            } else if result.status == 0 && result.combined.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                      let hint = Self.emptyOutputHints[source.fact] {
                // Nothing at all, by design of the OS, not a parser problem.
                notes.append(CollectionNote(fact: source.fact, status: .unavailable, source: label, detail: hint))
            } else {
                let snippet = result.combined.trimmingCharacters(in: .whitespacesAndNewlines).prefix(160)
                notes.append(CollectionNote(fact: source.fact, status: result.status == 0 ? .unparsed : .failed,
                                            source: label, detail: "exit \(result.status): \(snippet)"))
            }
        }

        collectSoftwareUpdate(into: &facts, notes: &notes)
        collectDeclarationTypes(into: &facts, notes: &notes)

        let launch = LaunchItemsCollector(fileExists: fileExists, readFile: readFile, signatures: signatures).collect()
        if let value = launch.value { facts[LaunchItemsCollector.fact] = value }
        notes.append(launch.note)
        return CollectionResult(facts: facts, notes: notes)
    }

    /// Declarative Device Management declarations only ever come from an MDM server, so a Mac that isn't
    /// MDM-enrolled has none: `[]`. On an enrolled Mac they can't be read yet, so the fact is left out, and rules a
    /// declaration could manage stay "management unknown" (never fixed).
    func collectDeclarationTypes(into facts: inout [String: FactValue], notes: inout [CollectionNote]) {
        let fact = CoreFacts.declarationTypes
        let source = CoreFacts.enrollment
        switch facts[CoreFacts.enrollment]?.object?["mdm"] {
        case .bool(false)?:
            facts[fact] = .array([])
            notes.append(CollectionNote(fact: fact, status: .collected, source: source, detail: "not MDM-enrolled, so no declarations"))
        case .bool(true)?:
            notes.append(CollectionNote(fact: fact, status: .unavailable, source: source,
                                        detail: "MDM-enrolled: reading declarations isn't supported yet"))
        default:
            notes.append(CollectionNote(fact: fact, status: .unavailable, source: source, detail: "MDM enrollment is unknown"))
        }
    }

    /// `softwareupdate.prefs` alone (the helper re-reads it before and after changing it). Nil if it can't be read.
    public func softwareUpdatePrefs() -> FactValue? {
        var facts: [String: FactValue] = [:]
        var notes: [CollectionNote] = []
        collectSoftwareUpdate(into: &facts, notes: &notes)
        return facts["softwareupdate.prefs"]
    }

    func collectSoftwareUpdate(into facts: inout [String: FactValue], notes: inout [CollectionNote]) {
        let fact = "softwareupdate.prefs"
        let (local, localProblem) = loadPlist(Self.softwareUpdatePlist)
        let (managed, managedProblem) = loadPlist(Self.softwareUpdateManagedPlist)
        // Managed settings that exist but can't be read must not be replaced by local values: those might not be
        // the effective settings. The fact stays unknown.
        if let managedProblem {
            notes.append(CollectionNote(fact: fact, status: .failed, source: Self.softwareUpdateManagedPlist, detail: managedProblem))
            return
        }
        if let localProblem, managed == nil {
            notes.append(CollectionNote(fact: fact, status: .failed, source: Self.softwareUpdatePlist, detail: localProblem))
            return
        }
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
