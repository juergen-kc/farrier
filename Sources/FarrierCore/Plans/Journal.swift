import Foundation
#if canImport(Glibc)
import Glibc
#endif

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

    /// Appends one entry. Reading the last hash and writing the new line happen under an exclusive `flock` on the
    /// journal itself, so concurrent writers (two CLIs, two helper connections) can't fork the chain, and the write
    /// is a single `write(2)` on an `O_APPEND` descriptor. A journal that can't be read or parsed is not appended
    /// to: the caller must treat that as a failure (the helper then refuses to change anything).
    public func append(_ record: JournalRecord) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        let fd = open(url.path, O_RDWR | O_CREAT | O_APPEND | O_CLOEXEC, mode_t(mode))
        guard fd >= 0 else { throw PlanError("could not open the journal at \(url.path) (errno \(errno))") }
        defer { close(fd) }
        guard flock(fd, LOCK_EX) == 0 else { throw PlanError("could not lock the journal (errno \(errno))") }
        defer { flock(fd, LOCK_UN) }

        let existing = try Journal.readAll(fd)
        let prev = try Journal.parse(existing).last?.hash ?? Journal.genesis
        let entry = JournalEntry(record: record, prevHash: prev, hash: try JournalEntry.hash(record: record, prevHash: prev))
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        var line = try encoder.encode(entry)
        // A journal whose last line lost its newline (e.g. a crash mid-write) would merge with ours.
        if let last = existing.last, last != 0x0A { line.insert(0x0A, at: 0) }
        line.append(0x0A)
        let written = line.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
        guard written == line.count else { throw PlanError("could not write the journal (errno \(errno))") }
        guard fsync(fd) == 0 else { throw PlanError("could not sync the journal (errno \(errno))") }
    }

    private static func readAll(_ fd: Int32) throws -> Data {
        guard lseek(fd, 0, SEEK_SET) == 0 else { throw PlanError("could not read the journal (errno \(errno))") }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 65_536)
        while true {
            let n = buffer.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
            if n < 0 { throw PlanError("could not read the journal (errno \(errno))") }
            if n == 0 { return data }
            data.append(contentsOf: buffer[0..<n])
        }
    }

    private static func parse(_ data: Data) throws -> [JournalEntry] {
        try String(decoding: data, as: UTF8.self).split(separator: "\n", omittingEmptySubsequences: true).enumerated().map { n, line in
            guard let entry = try? JSONDecoder().decode(JournalEntry.self, from: Data(line.utf8)) else {
                throw PlanError("journal line \(n + 1) is not an entry; run `farrier journal verify`")
            }
            return entry
        }
    }

    /// All entries; an unreadable line throws (use `verify` to report problems instead).
    public func entries() throws -> [JournalEntry] {
        guard FileManager.default.fileExists(atPath: url.path) else { return [] }
        return try Journal.parse(try Data(contentsOf: url))
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
