import Foundation

/// Facts only the inventory needs (they take longer than posture's): installed apps with their code signatures,
/// system extensions, and the administrators. All T0. The rest of the inventory reuses the posture facts
/// (`launchd.items`, `mdm.profiles`, `tcc.grants`, `network.listeningTCP`).
public struct InventoryCollector: Sendable {
    public static let apps = "apps.installed"
    public static let systemExtensions = "system.extensions"
    public static let admins = "accounts.admins"

    public let runner: CommandRunning
    public let readFile: @Sendable (String) -> Data?
    public let fileExists: @Sendable (String) -> Bool
    public let listDirectory: @Sendable (String) -> [String]?
    public let signatures: CodeSignatureChecking
    /// Folders scanned for apps: `*.app` in each, and in its sub-folders one level down (e.g. /Applications/Utilities).
    public let appFolders: [String]
    /// The real path behind symlinks, so an app linked under another name (Xcode.app → Xcode_26.6.app) is listed once.
    /// Resolved one component at a time without touching privacy-protected folders; nil if it leads into one.
    public let resolve: @Sendable (String) -> String?
    public let isDirectory: @Sendable (String) -> Bool

    public init(runner: CommandRunning = ProcessRunner(),
                readFile: @escaping @Sendable (String) -> Data? = { FileManager.default.contents(atPath: $0) },
                fileExists: @escaping @Sendable (String) -> Bool = { FileManager.default.fileExists(atPath: $0) },
                listDirectory: @escaping @Sendable (String) -> [String]? = { try? FileManager.default.contentsOfDirectory(atPath: $0) },
                signatures: CodeSignatureChecking = SecurityFrameworkSignatures(),
                appFolders: [String] = ["/Applications", FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Applications").path],
                resolve: @escaping @Sendable (String) -> String? = { LaunchItemsCollector().resolvedOutsideProtectedFolders($0) },
                isDirectory: @escaping @Sendable (String) -> Bool = { path in
                    var dir: ObjCBool = false
                    return FileManager.default.fileExists(atPath: path, isDirectory: &dir) && dir.boolValue
                }) {
        self.runner = runner
        self.readFile = readFile
        self.fileExists = fileExists
        self.listDirectory = listDirectory
        self.signatures = signatures
        self.appFolders = appFolders
        self.resolve = resolve
        self.isDirectory = isDirectory
    }

    public func collect() -> CollectionResult {
        var facts: [String: FactValue] = [:]
        var notes: [CollectionNote] = []
        func command(_ fact: String, _ exe: String, _ args: [String], _ parse: (CommandResult) -> FactValue?) {
            let label = ([exe] + args).joined(separator: " ")
            guard let r = runner.run(exe, args, timeout: 15) else {
                return notes.append(CollectionNote(fact: fact, status: .unavailable, source: label, detail: "not found"))
            }
            if r.timedOut { return notes.append(CollectionNote(fact: fact, status: .failed, source: label, detail: "timed out")) }
            if let v = parse(r) {
                facts[fact] = v
                notes.append(CollectionNote(fact: fact, status: .collected, source: label, detail: nil))
            } else {
                let snippet = r.combined.trimmingCharacters(in: .whitespacesAndNewlines).prefix(160)
                notes.append(CollectionNote(fact: fact, status: r.status == 0 ? .unparsed : .failed, source: label,
                                            detail: "exit \(r.status): \(snippet)"))
            }
        }
        command(Self.systemExtensions, "/usr/bin/systemextensionsctl", ["list"]) { Parsers.systemExtensions($0.stdout) }
        command(Self.admins, "/usr/bin/dscl", [".", "-read", "/Groups/admin", "GroupMembership"]) { Parsers.groupMembers($0.combined) }
        let (apps, note) = collectApps()
        if let apps { facts[Self.apps] = apps }
        notes.append(note)
        return CollectionResult(facts: facts, notes: notes)
    }

    /// `[{ name, bundleID, version, path, signature }]`, sorted by path. An app whose Info.plist can't be read is
    /// still listed (with `error`), never dropped. An app or folder that leads into a privacy-protected folder (a
    /// symlink into Documents, a volume) is listed unchecked, never opened. No app folder at all: unavailable; one
    /// that can't be listed: failed (or, for a sub-folder, named in the note), so a partial scan never looks complete.
    func collectApps() -> (FactValue?, CollectionNote) {
        let source = appFolders.joined(separator: ", ")
        let roots = appFolders.filter(fileExists)
        guard !roots.isEmpty else {
            return (nil, CollectionNote(fact: Self.apps, status: .unavailable, source: source, detail: "no app folders"))
        }
        var paths: [String] = []
        var protected: [String] = []
        var unlisted: [String] = []
        for root in roots {
            guard let real = resolve(root) else { protected.append(root); continue }
            guard let names = listDirectory(real) else {
                return (nil, CollectionNote(fact: Self.apps, status: .failed, source: source, detail: "cannot list \(root)"))
            }
            for name in names.sorted() where !name.hasPrefix(".") {
                let path = "\(root)/\(name)"
                if name.hasSuffix(".app") { paths.append(path); continue }
                guard let target = resolve(path) else { continue }   // a link into a protected folder: not an app folder
                guard isDirectory(target) else { continue }
                guard let inner = listDirectory(target) else { unlisted.append(path); continue }
                for app in inner.sorted() where app.hasSuffix(".app") { paths.append("\(path)/\(app)") }
            }
        }
        var seen = Set<String>()
        var entries: [(path: String, real: String?)] = []
        for path in paths {
            let real = resolve(path)
            if let real, !seen.insert(real).inserted { continue }
            entries.append((real ?? path, real))
        }
        var checked = 0
        let items: [FactValue] = entries.sorted { $0.path < $1.path }.map { entry in
            let path = entry.path
            let fallback = ((path as NSString).lastPathComponent as NSString).deletingPathExtension
            var o: [String: FactValue] = ["path": .string(path)]
            guard entry.real != nil else {
                o["name"] = .string(fallback)
                o["error"] = .string("in a privacy-protected folder (or reached through one); not checked")
                return .object(o)
            }
            if let data = readFile("\(path)/Contents/Info.plist"), let info = Parsers.propertyList(data)?.object {
                o["name"] = .string(info["CFBundleDisplayName"]?.string ?? info["CFBundleName"]?.string ?? fallback)
                if let id = info["CFBundleIdentifier"]?.string { o["bundleID"] = .string(id) }
                if let v = info["CFBundleShortVersionString"]?.string, !v.isEmpty { o["version"] = .string(v) }
            } else {
                o["name"] = .string(fallback)
                o["error"] = .string("cannot read Info.plist")
            }
            if let sig = signatures.check(path: path) {
                o["signature"] = sig.factValue
                checked += 1
            }
            return .object(o)
        }
        var details: [String] = []
        if checked < items.count { details.append("\(items.count - checked) app(s) without a signature check") }
        if !protected.isEmpty { details.append("not opened (privacy-protected): \(protected.joined(separator: ", "))") }
        if !unlisted.isEmpty { details.append("cannot list \(unlisted.joined(separator: ", "))") }
        return (.array(items), CollectionNote(fact: Self.apps, status: .collected, source: source,
                                              detail: details.isEmpty ? nil : details.joined(separator: "; ")))
    }
}

// MARK: - The report

/// One part of the inventory: its items, how many need a look (`flagged`), and why it's missing if it is.
public struct InventorySection: Sendable, Codable, Equatable {
    public let id: String
    public let title: String
    public let available: Bool
    /// Why the section is empty or missing (not collected, needs the helper or Full Disk Access, …).
    public let note: String?
    public let items: [FactValue]
    /// Items whose code signature is invalid, missing or not notarized (apps, launch jobs), or couldn't be checked.
    public let flagged: Int
}

public struct InventoryReport: Sendable, Codable {
    public let sections: [InventorySection]
}

public enum Inventory {
    /// The sections, in display order: id, title, and the fact each comes from.
    public static let sections: [(id: String, title: String, fact: String)] = [
        ("apps", "Installed apps", InventoryCollector.apps),
        ("launchItems", "Launch agents and daemons", LaunchItemsCollector.fact),
        ("systemExtensions", "System extensions", InventoryCollector.systemExtensions),
        ("profiles", "Configuration profiles", CoreFacts.profiles),
        ("privacyGrants", "Privacy grants (Full Disk Access, Accessibility, Screen Recording, …)", "tcc.grants"),
        ("admins", "Administrators", InventoryCollector.admins),
        ("listeningPorts", "Listening TCP ports", "network.listeningTCP"),
        ("loginItems", "Login items and background tasks", "launchd.btm"),
    ]

    public static var sectionIDs: [String] { sections.map(\.id) }

    /// Builds the report from collected facts and their notes. `only`: section ids to include (nil: all).
    /// `flaggedOnly`: keep only flagged items in sections that flag (apps, launch items).
    public static func build(facts: [String: FactValue], notes: [CollectionNote], only: Set<String>? = nil,
                             flaggedOnly: Bool = false) -> InventoryReport {
        var out: [InventorySection] = []
        for s in sections where only?.contains(s.id) ?? true {
            guard let value = facts[s.fact] else {
                let reason = notes.first { $0.fact == s.fact }.map { n in n.detail ?? n.status.rawValue }
                    ?? (s.id == "loginItems" ? "not collected yet (needs the helper's Background Task Management read)" : "not collected")
                out.append(InventorySection(id: s.id, title: s.title, available: false, note: reason, items: [], flagged: 0))
                continue
            }
            let items: [FactValue] = value.array ?? value.object.map { _ in [value] } ?? [value]
            let flags = items.filter(needsALook)
            out.append(InventorySection(id: s.id, title: s.title, available: true,
                                        note: notes.first { $0.fact == s.fact && $0.status == .collected }?.detail,
                                        items: flaggedOnly && (s.id == "apps" || s.id == "launchItems") ? flags : items,
                                        flagged: flags.count))
        }
        return InventoryReport(sections: out)
    }

    /// An app or launch job whose code can't be trusted as is: no valid signature, not notarized (and not
    /// Apple's), or not checked at all. Other kinds of items are never flagged.
    public static func needsALook(_ item: FactValue) -> Bool {
        guard let o = item.object, o["path"] != nil || o["label"] != nil || o["plist"] != nil else { return false }
        // An app or launch job whose signature wasn't checked can't be vouched for.
        guard let sig = o["signature"]?.object else { return true }
        // Gatekeeper accepted it as notarized (or as Apple's): nothing to look at, whatever the static check said.
        if sig["gatekeeperAccepted"] == .bool(true),
           ["Notarized Developer ID", "Apple System", "Apple", "Mac App Store"].contains(sig["gatekeeperSource"]?.string ?? "") { return false }
        if sig["valid"] != .bool(true) { return true }
        if sig["appleSigned"] == .bool(true) { return false }
        return sig["notarized"] != .bool(true)
    }

    /// One line per item, for the CLI.
    public static func describe(_ item: FactValue, section: String) -> String {
        guard let o = item.object else { return item.string ?? item.description }
        func s(_ k: String) -> String? { o[k]?.string }
        let sig = o["signature"]?.object
        let signer: String? = sig.map { sig -> String in
            var parts: [String] = []
            if let source = sig["source"]?.string { parts.append(source) }
            if let team = sig["teamID"]?.string { parts.append("team \(team)") }
            return parts.joined(separator: ", ")
        }
        switch section {
        case "apps":
            var parts: [String] = [s("name") ?? "?"]
            if let v = s("version") { parts.append(v) }
            if let id = s("bundleID") { parts.append("(\(id))") }
            var line = parts.joined(separator: " ")
            if let signer { line += " — \(signer)" }
            if let reason = sig?["error"]?.string, reason != "unsigned", sig?["gatekeeperAccepted"] != .bool(true) {
                line += " (\(reason))"
            }
            if let e = s("error") { line += " — \(e)" }
            return line
        case "launchItems":
            var line = "\(s("label") ?? s("plist") ?? "?") [\(s("scope") ?? "?")]"
            if let signer { line += " — \(signer)" }
            if let script = s("script") { line += " — runs \(script)" }
            if let e = s("error") { line += " — \(e)" }
            return line
        case "systemExtensions":
            return "\(s("name") ?? "?") (\(s("bundleID") ?? "?"), team \(s("teamID") ?? "?")) — \(s("state") ?? "?")"
        case "profiles":
            var line = s("displayName") ?? s("identifier") ?? "?"
            if let org = s("organization") { line += " (\(org))" }
            if let types = o["payloadTypes"]?.array { line += " — " + types.compactMap(\.string).joined(separator: ", ") }
            return line
        case "privacyGrants":
            return "\(s("service") ?? "?"): \(s("client") ?? "?")"
        default:
            return item.description
        }
    }
}
