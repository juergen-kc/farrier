import Foundation

/// One journal line, before it is hashed.
public struct JournalRecord: Codable, Sendable, Equatable {
    public let time: Int64
    /// `cli`, `mcp:<client>`, or `helper`.
    public let actor: String
    public let planID: String
    public let planHash: String
    public let ruleID: String?
    public let action: String?
    /// `approved`, `refused`, `applied`, `alreadyCompliant`, `failed`, …
    public let outcome: String
    public let detail: String?

    public init(time: Int64, actor: String, planID: String, planHash: String, ruleID: String? = nil,
                action: String? = nil, outcome: String, detail: String? = nil) {
        self.time = time
        self.actor = actor
        self.planID = planID
        self.planHash = planHash
        self.ruleID = ruleID
        self.action = action
        self.outcome = outcome
        self.detail = detail
    }
}

/// A stored line: the record, the previous line's hash, and this line's hash over both.
public struct JournalEntry: Codable, Sendable, Equatable {
    public let record: JournalRecord
    public let prevHash: String
    public let hash: String

    static func hash(record: JournalRecord, prevHash: String) throws -> String {
        struct Hashed: Encodable { let record: JournalRecord; let prevHash: String }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return FarrierCrypto.sha256(try encoder.encode(Hashed(record: record, prevHash: prevHash))).hexString
    }
}

/// An append-only JSONL journal whose lines form a hash chain (docs/ARCHITECTURE.md, "Journal"). The chain
/// shows edits, deletions and reordering after the fact; it can't stop someone who can write the file from
/// rewriting all of it, which is why the helper keeps its own root-owned copy.
public struct Journal: Sendable {
    public static let genesis = String(repeating: "0", count: 64)

    public let url: URL
    /// POSIX mode for a new file (the directory is created 0755 if missing).
    public let mode: Int

    public init(url: URL, mode: Int = 0o600) {
        self.url = url
        self.mode = mode
    }

    public func append(_ record: JournalRecord) throws {
        let fm = FileManager.default
        try fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        let prev = try entries().last?.hash ?? Journal.genesis
        let entry = JournalEntry(record: record, prevHash: prev, hash: try JournalEntry.hash(record: record, prevHash: prev))
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        var line = try encoder.encode(entry)
        line.append(0x0A)
        if !fm.fileExists(atPath: url.path) {
            guard fm.createFile(atPath: url.path, contents: nil, attributes: [.posixPermissions: NSNumber(value: mode)]) else {
                throw PlanError("could not create the journal at \(url.path)")
            }
        }
        let handle = try FileHandle(forWritingTo: url)
        defer { try? handle.close() }
        try handle.seekToEnd()
        try handle.write(contentsOf: line)
    }

    /// All entries; an unreadable line throws (use `verify` to report problems instead).
    public func entries() throws -> [JournalEntry] {
        guard FileManager.default.fileExists(atPath: url.path) else { return [] }
        let text = String(decoding: try Data(contentsOf: url), as: UTF8.self)
        return try text.split(separator: "\n", omittingEmptySubsequences: true).map {
            try JSONDecoder().decode(JournalEntry.self, from: Data($0.utf8))
        }
    }

    /// Problems in the chain, by line number. Empty means intact (a missing journal is intact and empty).
    public func verify() -> [String] {
        guard FileManager.default.fileExists(atPath: url.path) else { return [] }
        guard let data = try? Data(contentsOf: url) else { return ["\(url.path): unreadable"] }
        var issues: [String] = []
        var prev = Journal.genesis
        let lines = String(decoding: data, as: UTF8.self).split(separator: "\n", omittingEmptySubsequences: false)
        for (n, line) in lines.enumerated() where !(line.isEmpty && n == lines.count - 1) {
            guard let entry = try? JSONDecoder().decode(JournalEntry.self, from: Data(line.utf8)) else {
                issues.append("line \(n + 1): not a journal entry")
                prev = ""
                continue
            }
            if entry.prevHash != prev { issues.append("line \(n + 1): does not follow the previous line (entries removed or reordered?)") }
            if (try? JournalEntry.hash(record: entry.record, prevHash: entry.prevHash)) != entry.hash {
                issues.append("line \(n + 1): hash mismatch (entry edited?)")
            }
            prev = entry.hash
        }
        return issues
    }
}
