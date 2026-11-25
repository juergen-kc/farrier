import Foundation

/// A saved picture of the Mac: the inventory (apps, launch items, extensions, profiles, privacy grants, admins,
/// listening ports) and the collected settings facts, to compare with later (docs/ARCHITECTURE.md, `Snapshot`).
public struct Snapshot: Codable, Sendable, Equatable {
    public static let currentFormat = 1

    public let format: Int
    public let id: String
    public let createdAt: Int64
    /// The Mac's hardware UUID.
    public let host: String
    public let farrierVersion: String
    public let label: String?
    public let inventory: InventoryReport
    /// Every collected fact that isn't already an inventory section (OS version, FileVault, SIP, firewall, …).
    public let facts: [String: FactValue]
    /// Facts that couldn't be read, with why (so a diff doesn't mistake "unreadable" for "changed").
    public let missingFacts: [String: String]

    public init(id: String = UUID().uuidString.lowercased(), createdAt: Int64, host: String, label: String?,
                inventory: InventoryReport, facts: [String: FactValue], missingFacts: [String: String]) {
        self.format = Self.currentFormat
        self.id = id
        self.createdAt = createdAt
        self.host = host
        self.farrierVersion = FarrierVersion.string
        self.label = label
        self.inventory = inventory
        let sectionFacts = Set(Inventory.sections.map(\.fact))
        self.facts = facts.filter { !sectionFacts.contains($0.key) }
        self.missingFacts = missingFacts.filter { !sectionFacts.contains($0.key) }
    }

    /// From one collection: the inventory built the way `farrier inventory` builds it, and the other facts.
    public static func take(_ collected: CollectionResult, host: String, label: String?, now: Date = Date()) -> Snapshot {
        var missing: [String: String] = [:]
        for n in collected.notes where collected.facts[n.fact] == nil { missing[n.fact] = n.detail ?? n.status.rawValue }
        return Snapshot(createdAt: Int64(now.timeIntervalSince1970), host: host, label: label,
                        inventory: Inventory.build(facts: collected.facts, notes: collected.notes),
                        facts: collected.facts, missingFacts: missing)
    }
}

/// `~/Library/Application Support/Farrier/Snapshots/<id>.json` (folder 0700, files 0600: snapshots name the
/// admins, apps and privacy grants).
public struct SnapshotStore: Sendable {
    public let directory: String
    /// The most snapshots kept; the oldest beyond it are removed when a new one is saved.
    public let limit: Int

    public init(directory: String, limit: Int = 50) {
        self.directory = directory
        self.limit = limit
    }

    public static var `default`: SnapshotStore {
        SnapshotStore(directory: FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Farrier/Snapshots").path)
    }

    public func save(_ s: Snapshot) throws {
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: NSNumber(value: 0o700)])
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let path = "\(directory)/\(s.id).json"
        guard FileManager.default.createFile(atPath: path, contents: try encoder.encode(s),
                                             attributes: [.posixPermissions: NSNumber(value: 0o600)]) else {
            throw PlanError("could not write \(path)")
        }
        for old in list().dropFirst(limit) { try? FileManager.default.removeItem(atPath: "\(directory)/\(old.id).json") }
    }

    /// Newest first. Unreadable files are skipped.
    public func list() -> [Snapshot] {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: directory)) ?? []
        return names.filter { $0.hasSuffix(".json") }
            .compactMap { load(exactID: String($0.dropLast(5))) }
            .sorted { ($0.createdAt, $0.id) > ($1.createdAt, $1.id) }
    }

    func load(exactID id: String) -> Snapshot? {
        guard UUID(uuidString: id) != nil, id == id.lowercased(),
              let data = FileManager.default.contents(atPath: "\(directory)/\(id).json"),
              let s = try? JSONDecoder().decode(Snapshot.self, from: data), s.id == id else { return nil }
        return s
    }

    /// By id or unique prefix (at least 4 characters), or `latest`.
    public func load(_ idOrPrefix: String) throws -> Snapshot {
        let all = list()
        if idOrPrefix == "latest" {
            guard let s = all.first else { throw PlanError("no snapshots yet; make one with `farrier snapshot create`") }
            return s
        }
        let wanted = idOrPrefix.lowercased()
        guard wanted.count >= 4 else { throw PlanError("give at least 4 characters of the snapshot id") }
        let matches = all.filter { $0.id.hasPrefix(wanted) }
        guard let s = matches.first else { throw PlanError("no snapshot \(idOrPrefix) (see `farrier snapshot list`)") }
        guard matches.count == 1 else { throw PlanError("\(idOrPrefix) matches \(matches.count) snapshots; give more of the id") }
        return s
    }

    public func delete(_ idOrPrefix: String) throws -> Snapshot {
        let s = try load(idOrPrefix)
        try FileManager.default.removeItem(atPath: "\(directory)/\(s.id).json")
        return s
    }
}

// MARK: - Diff

/// One field that differs, as a dotted path (`version`, `signature.teamID`).
public struct FieldChange: Codable, Sendable, Equatable {
    public let field: String
    public let before: FactValue?
    public let after: FactValue?
}

public struct ItemChange: Codable, Sendable, Equatable {
    public let key: String
    public let summary: String
    public let fields: [FieldChange]
}

public struct SectionDiff: Codable, Sendable, Equatable {
    public let id: String
    public let title: String
    /// Not compared: the section couldn't be read in one of the two (a missing section isn't "everything removed").
    public let notCompared: String?
    public let added: [String]
    public let removed: [String]
    public let changed: [ItemChange]
}

public struct SnapshotDiff: Codable, Sendable, Equatable {
    public let from: SnapshotRef
    public let to: SnapshotRef
    public let sections: [SectionDiff]
    /// Settings facts whose value changed (or appeared or disappeared).
    public let facts: [FieldChange]
    /// Facts that couldn't be read in one of the two, so weren't compared.
    public let factsNotCompared: [String]
    public var changes: Int {
        sections.reduce(0) { $0 + $1.added.count + $1.removed.count + $1.changed.count } + facts.count
    }

    public struct SnapshotRef: Codable, Sendable, Equatable {
        public let id: String?
        public let createdAt: Int64
        public let label: String?
    }
}

public enum SnapshotDiffer {
    /// What identifies an item across snapshots, by section. Items without one fall back to their description.
    static func key(_ item: FactValue, section: String) -> String {
        guard let o = item.object else { return item.string ?? item.description }
        func s(_ k: String) -> String? { o[k]?.string }
        switch section {
        case "apps": return s("bundleID").map { "\($0) \(s("path") ?? "")" } ?? s("path") ?? item.description
        case "launchItems": return "\(s("scope") ?? "?"):\(s("label") ?? s("plist") ?? item.description)"
        case "systemExtensions": return s("bundleID") ?? item.description
        case "profiles": return s("identifier") ?? item.description
        case "privacyGrants": return "\(s("service") ?? "?"):\(s("client") ?? "?")"
        default: return item.description
        }
    }

    /// Every leaf of an object as a dotted path; arrays are compared whole.
    static func flatten(_ v: FactValue, _ prefix: String = "", into out: inout [String: FactValue]) {
        if let o = v.object, !o.isEmpty {
            for (k, sub) in o { flatten(sub, prefix.isEmpty ? k : "\(prefix).\(k)", into: &out) }
        } else {
            out[prefix] = v
        }
    }

    static func fieldChanges(_ a: FactValue, _ b: FactValue) -> [FieldChange] {
        var fa: [String: FactValue] = [:], fb: [String: FactValue] = [:]
        flatten(a, into: &fa)
        flatten(b, into: &fb)
        return Set(fa.keys).union(fb.keys).sorted().compactMap { k in
            fa[k] == fb[k] ? nil : FieldChange(field: k, before: fa[k], after: fb[k])
        }
    }

    public static func diff(_ a: Snapshot, _ b: Snapshot, toIsLive: Bool = false) -> SnapshotDiff {
        var sections: [SectionDiff] = []
        for meta in Inventory.sections {
            let sa = a.inventory.sections.first { $0.id == meta.id }
            let sb = b.inventory.sections.first { $0.id == meta.id }
            guard let sa, let sb, sa.available, sb.available else {
                let why = [sa, sb].compactMap { $0 }.first { !$0.available }?.note ?? "not collected"
                sections.append(SectionDiff(id: meta.id, title: meta.title, notCompared: why, added: [], removed: [], changed: []))
                continue
            }
            func index(_ s: InventorySection) -> [String: FactValue] {
                var d: [String: FactValue] = [:]
                for item in s.items { d[key(item, section: meta.id)] = item }
                return d
            }
            let ia = index(sa), ib = index(sb)
            func describe(_ k: String, _ v: FactValue) -> String { Inventory.describe(v, section: meta.id) }
            let added = Set(ib.keys).subtracting(ia.keys).sorted().map { describe($0, ib[$0]!) }
            let removed = Set(ia.keys).subtracting(ib.keys).sorted().map { describe($0, ia[$0]!) }
            let changed = Set(ia.keys).intersection(ib.keys).sorted().compactMap { k -> ItemChange? in
                let fields = fieldChanges(ia[k]!, ib[k]!)
                return fields.isEmpty ? nil : ItemChange(key: k, summary: describe(k, ib[k]!), fields: fields)
            }
            sections.append(SectionDiff(id: meta.id, title: meta.title, notCompared: nil, added: added, removed: removed, changed: changed))
        }
        let missing = Set(a.missingFacts.keys).union(b.missingFacts.keys)
        let factKeys = Set(a.facts.keys).union(b.facts.keys).subtracting(missing).sorted()
        let facts = factKeys.flatMap { k -> [FieldChange] in
            switch (a.facts[k], b.facts[k]) {
            case let (x?, y?): return x == y ? [] : fieldChanges(x, y).map { FieldChange(field: $0.field.isEmpty ? k : "\(k).\($0.field)", before: $0.before, after: $0.after) }
            case (nil, nil): return []
            case let (x, y): return [FieldChange(field: k, before: x, after: y)]
            }
        }
        return SnapshotDiff(from: .init(id: a.id, createdAt: a.createdAt, label: a.label),
                            to: .init(id: toIsLive ? nil : b.id, createdAt: b.createdAt, label: toIsLive ? "now" : b.label),
                            sections: sections, facts: facts, factsNotCompared: missing.sorted())
    }
}
