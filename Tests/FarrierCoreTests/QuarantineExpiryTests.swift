import Foundation
import MCP
import Testing
@testable import FarrierCore
@testable import FarrierHelperKit
@testable import FarrierMCP

/// A fake home whose cache and log are already quarantined by one cleanup plan.
private struct Quarantined {
    let home = FakeHome()
    let quarantine: Quarantine
    let cleanup: Plan

    init() throws {
        home.file("Library/Caches/app/blob", bytes: 40_000, daysAgo: 60)
        home.dir("Library/Caches/app", daysAgo: 60)
        home.file("Library/Logs/old/a.log", bytes: 5_000, daysAgo: 90)
        home.dir("Library/Logs/old", daysAgo: 90)
        let packs = [try pack(packYAML(rule("caches", "targets:\n  - path: ~/Library/Caches/*\nminAge: 30d\n"),
                                       rule("logs", "targets:\n  - path: ~/Library/Logs/*\nminAge: 30d\n")))]
        quarantine = Quarantine(root: "\(home.root)/Library/Application Support/Farrier/Quarantine")
        let report = home.scanner().scan(packs)
        cleanup = try #require(Planner.planCleanup(report: report, host: "H", now: home.now).plan)
        let moved = try CleanupApplier.apply(cleanup, packs: packs, scanner: home.scanner(), quarantine: quarantine, now: home.now)
        #expect(moved.allSatisfy { $0.outcome == .applied })
    }

    var afterRetention: Date { home.now.addingTimeInterval(TimeInterval(Quarantine.retention + 60)) }
}

@Suite("Quarantine expiry")
struct QuarantineExpiryTests {
    @Test func onlyPlansPastTheirSevenDaysByDefault() throws {
        let q = try Quarantined()
        #expect(Planner.planExpiry(quarantine: q.quarantine, host: "H", now: q.home.now).plan == nil)
        let plan = try #require(Planner.planExpiry(quarantine: q.quarantine, host: "H", now: q.afterRetention).plan)
        #expect(plan.tier == .t3 && plan.tier.needsApproval)
        #expect(plan.items.count == 1)
        #expect(try QuarantineExpiryRules.validate(plan.items[0].parameters) == q.cleanup.id)
        #expect(plan.items[0].observed.object?["items"] == .int(2))
        #expect(plan.items[0].description == "Delete for good: what cleanup plan \(q.cleanup.id.prefix(8)) moved there")
        #expect(try Plan.decodeCanonical(plan.canonicalData()) == plan)
        // Named plans can go early.
        let early = try #require(Planner.planExpiry(quarantine: q.quarantine, planIDs: [q.cleanup.id], host: "H", now: q.home.now).plan)
        #expect(early.items[0].observed.object?["due"] == .bool(false))
    }

    @Test func expiryParametersAreChecked() {
        for bad: [String: String]? in [nil, [:], ["plan": "x"], ["plan": UUID().uuidString], ["plan": UUID().uuidString.lowercased(), "x": "y"]] {
            #expect(throws: PlanError.self) { try QuarantineExpiryRules.validate(bad) }
        }
    }

    @Test func expireDeletesAndRecords() throws {
        let q = try Quarantined()
        let folder = q.quarantine.folder(q.cleanup.id)
        // A read-only folder inside (as Go's module cache has) is deleted too.
        let m = try q.quarantine.load(q.cleanup.id)
        let ro = "\(folder)/\(m.items[0].stored)/ro"
        try FileManager.default.createDirectory(atPath: ro, withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: "\(ro)/f", contents: Data("x".utf8))
        chmod(ro, 0o555)
        // A symlink inside is removed, never followed.
        q.home.file("Documents/keep.txt", daysAgo: 1)
        try FileManager.default.createSymbolicLink(atPath: "\(folder)/\(m.items[1].stored)/link", withDestinationPath: "\(q.home.root)/Documents")

        let plan = try #require(Planner.planExpiry(quarantine: q.quarantine, planIDs: [q.cleanup.id], host: "H", now: q.home.now).plan)
        // The bytes recorded at planning time are the manifest's (the added files aren't in it).
        let results = try CleanupApplier.expire(plan, quarantine: q.quarantine, now: q.afterRetention)
        #expect(results.map(\.outcome) == [.applied], "\(results)")
        #expect(results[0].detail.contains("deleted 2 item(s)"))
        #expect(FileStat.lstat("\(folder)/items/1") == nil && FileStat.lstat("\(folder)/items/2") == nil)
        #expect(FileStat.lstat("\(q.home.root)/Documents/keep.txt") != nil)
        let after = try q.quarantine.load(q.cleanup.id)
        #expect(after.items.allSatisfy { $0.state == .deleted && $0.deletedAt != nil })
        #expect(after.held.isEmpty && after.quarantinedBytes == 0)
        // Nothing to restore, and nothing left to expire.
        let r = try CleanupApplier.restore(planID: q.cleanup.id, paths: [after.items[0].original], quarantine: q.quarantine)
        #expect(r[0].detail.contains("deleted for good"))
        let all = try CleanupApplier.restore(planID: q.cleanup.id, quarantine: q.quarantine)
        #expect(all.count == 1 && all[0].detail == "nothing left to restore: its items were deleted for good")
        #expect(Planner.planExpiry(quarantine: q.quarantine, host: "H", now: q.afterRetention).plan == nil)
    }

    @Test func expiryRefusesWhenTheQuarantineChanged() throws {
        let q = try Quarantined()
        let plan = try #require(Planner.planExpiry(quarantine: q.quarantine, planIDs: [q.cleanup.id], host: "H", now: q.home.now).plan)
        let m = try q.quarantine.load(q.cleanup.id)
        _ = try CleanupApplier.restore(planID: q.cleanup.id, paths: [m.items[0].original], quarantine: q.quarantine)
        let results = try CleanupApplier.expire(plan, quarantine: q.quarantine)
        #expect(results.map(\.outcome) == [.refused] && results[0].detail.contains("restored since"))
        #expect(try q.quarantine.load(q.cleanup.id).held.count == 1)
    }

    @Test func expiryRefusesAQuarantineFolderThatIsALink() throws {
        let q = try Quarantined()
        let plan = try #require(Planner.planExpiry(quarantine: q.quarantine, planIDs: [q.cleanup.id], host: "H", now: q.home.now).plan)
        let folder = q.quarantine.folder(q.cleanup.id)
        try FileManager.default.moveItem(atPath: folder, toPath: "\(q.home.root)/elsewhere")
        try FileManager.default.createSymbolicLink(atPath: folder, withDestinationPath: "\(q.home.root)/elsewhere")
        let results = try CleanupApplier.expire(plan, quarantine: q.quarantine)
        #expect(results.map(\.outcome) == [.refused])
        #expect(FileStat.lstat("\(q.home.root)/elsewhere/items/1") != nil)
    }

    @Test func mcpExpiryNeedsTheApproval() throws {
        let q = try Quarantined()
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("farrier-ctx-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        var ctx = FarrierContext(
            collectFacts: { CollectionResult(facts: [:], notes: []) }, rulePaths: [],
            plans: PlanStore(directory: dir.appendingPathComponent("plans")),
            journal: Journal(url: dir.appendingPathComponent("j.jsonl")),
            host: { "H" }, applyThroughHelper: { _ in throw OperationError("the helper must not be asked") }, actor: "mcp:test")
        ctx.quarantine = q.quarantine
        var asked: [String] = []
        ctx.approveInProcess = { plan in asked.append(plan.id); throw OperationError("the approval prompt was cancelled; nothing changed") }

        let none = try ToolCatalog.call("quarantine_plan_expiry", arguments: [:], context: ctx)
        #expect(none.structuredContent?.objectValue?["plan"]?.isNull ?? true)   // nothing past its 7 days yet
        let planned = try ToolCatalog.call("quarantine_plan_expiry",
                                           arguments: ["planIDs": .array([.string(String(q.cleanup.id.prefix(8)))])], context: ctx)
        let planID = try #require(planned.structuredContent?.objectValue?["plan"]?.objectValue?["id"]?.stringValue)
        let tool = try #require(ToolCatalog.tools.first { $0.name == "quarantine_plan_expiry" })
        #expect(tool.annotations.readOnlyHint == false)

        // Cancelled on the Mac: nothing deleted.
        let cancelled = try ToolCatalog.call("apply_plan", arguments: ["planID": .string(planID)], context: ctx)
        #expect(cancelled.isError == true && asked == [planID])
        #expect(try q.quarantine.load(q.cleanup.id).held.count == 2)

        ctx.approveInProcess = { _ in }
        let approved = try ToolCatalog.call("apply_plan", arguments: ["planID": .string(planID)], context: ctx)
        #expect(approved.isError != true)
        #expect(try q.quarantine.load(q.cleanup.id).held.isEmpty)
        // Applying it again: nothing to delete, so nobody is asked.
        var askedAgain = false
        ctx.approveInProcess = { _ in askedAgain = true }
        let again = try ToolCatalog.call("apply_plan", arguments: ["planID": .string(planID)], context: ctx)
        #expect(again.isError == true && !askedAgain)
        let outcomes = try ctx.journal.entries().map(\.record.outcome)
        #expect(outcomes == ["planned", "notApplied", "approved", "applied", "notApplied"])
    }
}
