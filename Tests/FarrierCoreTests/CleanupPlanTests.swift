import Foundation
import MCP
import Testing
@testable import FarrierCore
@testable import FarrierHelperKit
@testable import FarrierMCP

/// A fake home with a cache and a log old enough to clean up, a quarantine next to it, and a pack for both.
private struct Setup {
    let home = FakeHome()
    let packs: [RulePack]
    let yaml: String
    var quarantine: Quarantine { Quarantine(root: "\(home.root)/Library/Application Support/Farrier/Quarantine") }
    var cache: String { "\(home.root)/Library/Caches/app" }
    var log: String { "\(home.root)/Library/Logs/old" }

    init(running: Set<String> = []) throws {
        home.file("Library/Caches/app/blob", bytes: 40_000, daysAgo: 60)
        home.dir("Library/Caches/app", daysAgo: 60)
        home.file("Library/Logs/old/a.log", bytes: 5_000, daysAgo: 90)
        home.dir("Library/Logs/old", daysAgo: 90)
        yaml = packYAML(
            rule("caches", "targets:\n  - path: ~/Library/Caches/*\nminAge: 30d\nwhen:\n  processNotRunning: [App]\n"),
            rule("logs", "targets:\n  - path: ~/Library/Logs/*\nminAge: 30d\n"))
        packs = [try pack(yaml)]
    }

    func scanner(running: Set<String> = []) -> CleanupScanner { home.scanner(running: running) }

    func plan(paths: Set<String>? = nil) throws -> Plan {
        let report = scanner().scan(packs)
        return try #require(Planner.planCleanup(report: report, paths: paths, host: "H", now: home.now).plan)
    }

    func apply(_ plan: Plan, running: Set<String> = []) throws -> [CleanupItemResult] {
        try CleanupApplier.apply(plan, packs: packs, scanner: scanner(running: running), quarantine: quarantine, now: home.now)
    }
}

@Suite("Cleanup plans and quarantine")
struct CleanupPlanTests {
    @Test func plansRecordPathFingerprintAndSize() throws {
        let s = try Setup()
        let plan = try s.plan()
        #expect(plan.tier == .t2 && !plan.tier.needsApproval)
        #expect(plan.items.count == 2)
        let item = try #require(plan.items.first { $0.ruleID == "t.caches" })
        let p = try CleanupItemRules.validate(item.parameters)
        #expect(p.path == s.cache)
        #expect(p.fingerprint == FileStat.lstat(s.cache)?.fingerprint && p.fingerprint.hasSuffix(":d"))
        #expect((item.observed.object?["bytes"]?.number ?? 0) >= 40_000)
        #expect(item.description == "Move to Farrier's quarantine: \(s.cache)")
        // A saved plan reads back through the same checks as every other plan.
        #expect(try Plan.decodeCanonical(plan.canonicalData()) == plan)

        let only = try s.plan(paths: [s.log, "\(s.home.root)/Documents/x"])
        #expect(only.items.map(\.ruleID) == ["t.logs"])
        let skipped = Planner.planCleanup(report: s.scanner().scan(s.packs), paths: [s.log, "/nope"], host: "H").skipped
        #expect(skipped.contains { $0.reason.contains("/nope: not a cleanup candidate") })
    }

    @Test func cleanupItemParametersAreChecked() throws {
        for bad: [String: String]? in [nil, ["path": "/a"], ["path": "rel/x", "fingerprint": "1:2:3:d"],
                                        ["path": "/a/../b", "fingerprint": "1:2:3:d"], ["path": "/a/", "fingerprint": "1:2:3:d"],
                                        ["path": "/a", "fingerprint": "1:2:3:x"], ["path": "/a", "fingerprint": "1:2:d"], ["path": "/a", "fingerprint": "1:2:3:d", "extra": "1"]] {
            #expect(throws: PlanError.self) { try CleanupItemRules.validate(bad) }
        }
        #expect(try CleanupItemRules.validate(["path": "/a/b", "fingerprint": "1:2:3:f"]).path == "/a/b")
    }

    @Test func applyMovesIntoTheQuarantineAndRestorePutsBack() throws {
        let s = try Setup()
        let plan = try s.plan()
        let results = try s.apply(plan)
        #expect(results.map(\.outcome) == [.applied, .applied])
        #expect(FileStat.lstat(s.cache) == nil && FileStat.lstat(s.log) == nil)
        let m = try s.quarantine.load(plan.id)
        #expect(m.items.allSatisfy { $0.state == .quarantined })
        #expect(m.expiresAt == m.createdAt + 7 * 86_400)
        #expect(FileManager.default.fileExists(atPath: "\(s.quarantine.folder(plan.id))/\(m.items[0].stored)/blob"))
        #expect(m.quarantinedBytes >= 45_000)
        // Folder and manifest are private to the user.
        let attrs = try FileManager.default.attributesOfItem(atPath: s.quarantine.folder(plan.id))
        #expect((attrs[.posixPermissions] as? NSNumber)?.intValue == 0o700)
        // Applying the same plan again moves nothing.
        #expect(try s.apply(plan).allSatisfy { $0.outcome == .refused })

        let one = try CleanupApplier.restore(planID: plan.id, paths: [s.log], quarantine: s.quarantine, now: s.home.now)
        #expect(one.map(\.outcome) == [.applied] && FileStat.lstat("\(s.log)/a.log") != nil)
        let rest = try CleanupApplier.restore(planID: plan.id, quarantine: s.quarantine, now: s.home.now)
        #expect(rest.map(\.path) == [s.cache] && rest[0].outcome == .applied)
        #expect(FileStat.lstat("\(s.cache)/blob")?.allocatedBytes ?? 0 >= 40_000)
        let again = try CleanupApplier.restore(planID: plan.id, quarantine: s.quarantine, now: s.home.now)
        #expect(again.count == 1 && again[0].detail == "nothing left to restore")
    }

    @Test func applyRechecksEveryItem() throws {
        let s = try Setup()
        let plan = try s.plan()
        // The app came back: its rule is skipped now, so its cache stays.
        let running = try s.apply(plan, running: ["App"])
        #expect(running.first { $0.ruleID == "t.caches" }?.outcome == .refused)
        #expect(running.first { $0.ruleID == "t.caches" }?.detail.contains("App is running") == true)
        #expect(FileStat.lstat(s.cache) != nil)
        #expect(running.first { $0.ruleID == "t.logs" }?.outcome == .applied)
    }

    @Test func applyRefusesItemsUsedOrSwappedSincePlanning() throws {
        let s = try Setup()
        let plan = try s.plan()
        s.home.file("Library/Caches/app/new", daysAgo: 0)          // used since planning
        try FileManager.default.removeItem(atPath: s.log)          // swapped: same path, another folder
        s.home.file("Library/Logs/old/a.log", daysAgo: 90)
        s.home.dir("Library/Logs/old", daysAgo: 90)
        let results = try s.apply(plan)
        #expect(results.allSatisfy { $0.outcome == .refused })
        #expect(results.first { $0.ruleID == "t.caches" }?.detail.contains("no longer a candidate") == true)
        #expect(results.first { $0.ruleID == "t.logs" }?.detail.contains("changed since planning") == true)
        #expect(FileStat.lstat(s.cache) != nil && FileStat.lstat(s.log) != nil)
    }

    @Test func aTamperedPlanCantReachOtherPaths() throws {
        let s = try Setup()
        s.home.file("Documents/thesis.pdf", daysAgo: 400)
        let doc = "\(s.home.root)/Documents/thesis.pdf"
        let fp = try #require(FileStat.lstat(doc)).fingerprint
        let action = RemediationCatalog.cleanupQuarantine
        let item = PlanItem(ruleID: "t.caches", action: action.id, tier: .t2, summary: action.summary, fact: action.fact,
                            observed: .object([:]), parameters: ["path": doc, "fingerprint": fp])
        let plan = Plan(id: UUID().uuidString.lowercased(), createdAt: 0, expiresAt: .max, host: "H", items: [item])
        #expect(try s.apply(plan).map(\.outcome) == [.refused])
        #expect(FileStat.lstat(doc) != nil)
        // Nor can a user pack: only bundled packs are re-checked against.
        let user = RulePack(id: "t", title: "T", version: 1, rules: s.packs[0].rules, source: .user, file: "u.yaml")
        let viaUser = try CleanupApplier.apply(try s.plan(), packs: [user], scanner: s.scanner(), quarantine: s.quarantine)
        #expect(viaUser.allSatisfy { $0.outcome == .refused })
    }

    @Test func restoreLeavesItemsWhoseOriginalPathIsTaken() throws {
        let s = try Setup()
        let plan = try s.plan(paths: [s.cache])
        _ = try s.apply(plan)
        s.home.file("Library/Caches/app/recreated", daysAgo: 0)    // the app recreated its cache meanwhile
        let r = try CleanupApplier.restore(planID: plan.id, quarantine: s.quarantine)
        #expect(r.map(\.outcome) == [.refused] && r[0].detail.contains("something is at that path"))
        #expect(try s.quarantine.load(plan.id).items[0].state == .quarantined)
    }

    @Test func anInterruptedMoveIsRecognised() throws {
        let s = try Setup()
        let id = UUID().uuidString.lowercased()
        let m = QuarantineManifest(format: 1, planID: id, createdAt: 0, expiresAt: 1, items: [
            QuarantineItem(index: 1, ruleID: "t.caches", original: s.cache, stored: "items/1/app", bytes: 1, state: .moving),
        ])
        try s.quarantine.save(m)
        let r = try CleanupApplier.restore(planID: id, quarantine: s.quarantine)
        #expect(r.map(\.outcome) == [.applied] && r[0].detail.contains("never moved"))
        #expect(FileStat.lstat(s.cache) != nil)
    }

    @Test func theQuarantineIsProtected() {
        let s = FakeHome()
        #expect(s.scanner().isProtected("\(s.root)/Library/Application Support/Farrier/Quarantine/x"))
        #expect(ProtectedPaths.conflict(for: "~/Library/Application Support/*") != nil)
    }

    @Test func mcpPlanApplyListRestore() throws {
        let s = try Setup()
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("farrier-ctx-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        try FileManager.default.createDirectory(at: dir.appendingPathComponent("rules"), withIntermediateDirectories: true)
        try s.yaml.write(to: dir.appendingPathComponent("rules/t.yaml"), atomically: true, encoding: .utf8)
        var ctx = FarrierContext(
            collectFacts: { CollectionResult(facts: [:], notes: []) },
            rulePaths: [dir.appendingPathComponent("rules").path],
            plans: PlanStore(directory: dir.appendingPathComponent("plans")),
            journal: Journal(url: dir.appendingPathComponent("j.jsonl")),
            host: { "H" }, applyThroughHelper: { _ in throw OperationError("the helper must not be asked") }, actor: "mcp:test")
        ctx.cleanupScanner = { s.scanner() }
        ctx.quarantine = s.quarantine

        let planned = try ToolCatalog.call("cleanup_plan", arguments: ["paths": .array([.string(s.cache)])], context: ctx)
        #expect(planned.isError != true)
        let planID = try #require(planned.structuredContent?.objectValue?["plan"]?.objectValue?["id"]?.stringValue)
        let applied = try ToolCatalog.call("apply_plan", arguments: ["planID": .string(planID)], context: ctx)
        #expect(applied.isError != true)
        #expect(FileStat.lstat(s.cache) == nil)

        let list = try ToolCatalog.call("quarantine_list", arguments: ["details": .bool(true)], context: ctx)
        let plans = try #require(list.structuredContent?.objectValue?["plans"]?.arrayValue)
        #expect(plans.count == 1 && plans[0].objectValue?["quarantined"]?.intValue == 1)

        // `undo` points to restore for a cleanup plan.
        let helper = Journal(url: dir.appendingPathComponent("helper.jsonl"))
        #expect(throws: OperationError.self) { try Operations.planUndo(ctx, id: String(planID.prefix(8)), journal: helper) }

        let restored = try ToolCatalog.call("quarantine_restore", arguments: ["planID": .string(String(planID.prefix(8)))], context: ctx)
        #expect(restored.isError != true)
        #expect(FileStat.lstat(s.cache) != nil)
        let empty = try ToolCatalog.call("quarantine_list", arguments: [:], context: ctx)
        #expect(empty.structuredContent?.objectValue?["plans"]?.arrayValue?.isEmpty == true)

        let outcomes = try ctx.journal.entries().map(\.record.outcome)
        #expect(outcomes == ["planned", "applied", "restored"])
        // An expired plan or another Mac's isn't applied.
        let late = try Operations.planCleanup(ctx, paths: [s.log], now: Date(timeIntervalSince1970: 0))
        let out = try Operations.apply(ctx, id: try #require(late.plan?.id), now: s.home.now)
        #expect(out.error?.contains("expired") == true && FileStat.lstat(s.log) != nil)
    }
}
