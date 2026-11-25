import Foundation
import MCP
import Testing
@testable import FarrierCore
@testable import FarrierMCP

@Suite("Disk usage")
struct DiskUsageTests {
    private func manifest(_ bytes: Int64, expiresAt: Int64, state: QuarantineItem.State = .quarantined) -> QuarantineManifest {
        QuarantineManifest(format: 1, planID: UUID().uuidString.lowercased(), createdAt: 0, expiresAt: expiresAt, items: [
            QuarantineItem(index: 1, ruleID: "r", original: "/x", stored: "items/1/x", bytes: bytes, state: state),
        ])
    }

    @Test func measuresCategoriesAndSaysWhenSpaceComesBack() throws {
        let home = FakeHome()
        home.file("Library/Caches/a/blob", bytes: 30_000, daysAgo: 1)
        home.file("Library/Logs/x.log", bytes: 5_000, daysAgo: 1)
        home.file(".npm/_cacache/c", bytes: 20_000, daysAgo: 1)
        home.file(".cargo/registry/cache/d", bytes: 10_000, daysAgo: 1)
        home.file("Documents/secret.pdf", bytes: 90_000, daysAgo: 1)   // never read
        let scan = CleanupReport(rules: [], bytes: 7_000, candidates: 2)
        let now = Date(timeIntervalSince1970: 1_000_000)
        let quarantine = [manifest(4_000, expiresAt: 999_000), manifest(6_000, expiresAt: 1_100_000),
                          manifest(9_999, expiresAt: 0, state: .deleted), manifest(9_999, expiresAt: 0, state: .restored)]
        let r = DiskUsage.report(home: home.root, scan: scan, quarantine: quarantine,
                                 volume: VolumeUsage(totalBytes: 1_000, availableBytes: 100, availableWithPurgeableBytes: 250),
                                 localSnapshots: 3, now: now)
        let byID = Dictionary(uniqueKeysWithValues: r.categories.map { ($0.id, $0) })
        #expect((byID["caches"]?.bytes ?? 0) >= 30_000)
        #expect((byID["logs"]?.bytes ?? 0) >= 5_000)
        let pm = try #require(byID["packageManagers"])
        #expect(pm.bytes >= 30_000 && pm.paths.count == 2)          // only the folders that exist
        #expect(byID["xcode"] == nil)                                // missing: not listed
        #expect(!r.categories.contains { $0.paths.contains { $0.contains("Documents") } })
        #expect(r.notes.contains(DiskUsage.personalFoldersNote))
        #expect(r.reclaimable == Reclaimable(nowBytes: 4_000, afterExpiryBytes: 6_000, cleanupCandidatesBytes: 7_000, cleanupCandidates: 2))
        #expect(r.localSnapshots == 3)
        #expect(r.volume?.purgeableBytes == 150)
    }

    @Test func unreadableTrashIsALowerBound() throws {
        guard getuid() != 0 else { return }   // root reads everything (the Linux container); macOS CI isn't root
        let home = FakeHome()
        home.file(".Trash/old/f", bytes: 10_000, daysAgo: 1)
        chmod("\(home.root)/.Trash/old", 0)
        defer { chmod("\(home.root)/.Trash/old", 0o755) }
        let r = DiskUsage.report(home: home.root, scan: CleanupReport(rules: [], bytes: 0, candidates: 0), quarantine: [],
                                 volume: nil, localSnapshots: nil)
        let trash = try #require(r.categories.first { $0.id == "trash" })
        #expect(trash.incomplete == true && trash.note?.contains("Full Disk Access") == true)
    }

    @Test func volumeJSONCarriesPurgeable() throws {
        let v = VolumeUsage(totalBytes: 10, availableBytes: 3, availableWithPurgeableBytes: 5)
        let json = try #require(String(data: try JSONEncoder().encode(v), encoding: .utf8))
        #expect(json.contains("\"purgeableBytes\":2"))
        #expect(try JSONDecoder().decode(VolumeUsage.self, from: Data(json.utf8)) == v)
        #expect(VolumeUsage(totalBytes: 10, availableBytes: 3, availableWithPurgeableBytes: nil).purgeableBytes == nil)
    }

    @Test func localSnapshotListing() {
        let out = """
        Snapshots for disk /:
        com.apple.TimeMachine.2026-11-24-101500.local
        com.apple.TimeMachine.2026-11-25-101500.local
        """
        #expect(DiskUsage.parseLocalSnapshots(out) == 2)
        #expect(DiskUsage.parseLocalSnapshots("Snapshots for disk /:\n") == 0)
    }

    @Test func mcpTool() throws {
        let home = FakeHome()
        home.file("Library/Caches/a/blob", bytes: 30_000, daysAgo: 90)
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("farrier-ctx-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        var ctx = FarrierContext(
            collectFacts: { CollectionResult(facts: [:], notes: []) },
            rulePaths: [repoRoot.appendingPathComponent("rules").path],
            plans: PlanStore(directory: dir.appendingPathComponent("plans")),
            journal: Journal(url: dir.appendingPathComponent("j.jsonl")),
            host: { "H" }, applyThroughHelper: { _ in throw OperationError("none") }, actor: "mcp:test")
        ctx.cleanupScanner = { home.scanner() }
        ctx.quarantine = Quarantine(root: "\(home.root)/q")
        ctx.volumeUsage = { _ in VolumeUsage(totalBytes: 100, availableBytes: 10, availableWithPurgeableBytes: nil) }
        ctx.localSnapshots = { 0 }
        let r = try ToolCatalog.call("disk_usage", arguments: [:], context: ctx)
        #expect(r.isError != true)
        let o = try #require(r.structuredContent?.objectValue)
        #expect(o["reclaimable"]?.objectValue?["cleanupCandidates"]?.intValue == 1)
        #expect(o["volume"]?.objectValue?["availableBytes"]?.intValue == 10)
        let tool = try #require(ToolCatalog.tools.first { $0.name == "disk_usage" })
        #expect(tool.annotations.readOnlyHint == true)
    }
}
