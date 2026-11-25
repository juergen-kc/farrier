import Foundation
import MCP
import Testing
@testable import FarrierCore
@testable import FarrierHelperKit
@testable import FarrierMCP

private let host = "H"

/// A fake home with one user cache, plus a "system" folder outside it standing in for /Library/Caches (tests can't
/// use the real one; the linter, which only allows /Library/Caches and /Library/Logs, is tested separately).
private struct Setup {
    let home = FakeHome()
    let packs: [RulePack]
    let yaml: String
    var system: String { "\(home.root)/sys/Caches" }
    var systemQuarantine: Quarantine { Quarantine(root: "\(home.root)/sysq") }
    var userQuarantine: Quarantine { Quarantine(root: "\(home.root)/q") }

    init() throws {
        home.file("Library/Caches/userapp/blob", bytes: 10_000, daysAgo: 60)
        home.dir("Library/Caches/userapp", daysAgo: 60)
        home.file("sys/Caches/vendor/blob", bytes: 30_000, daysAgo: 60)
        home.dir("sys/Caches/vendor", daysAgo: 60)
        yaml = packYAML(
            rule("user", "targets:\n  - path: ~/Library/Caches/*\nminAge: 30d\n"),
            rule("sys", "privileged: true\ntargets:\n  - path: \(home.root)/sys/Caches/*\nminAge: 30d\n"))
        packs = [try pack(yaml)]
    }

    var userScanner: CleanupScanner { home.scanner() }
    var helperScanner: CleanupScanner {
        var s = home.scanner()
        s.privilegedOnly = true
        return s
    }
}

private func lintIssues(_ yaml: String) throws -> [String] {
    RuleLinter.lint([try pack(yaml)]).filter { $0.level == .error }.map(\.message)
}

@Suite("System cleanup")
struct SystemCleanupTests {
    @Test func privilegedRulesOnlyReachSystemCachesAndLogs() throws {
        #expect(try lintIssues(packYAML(rule("a", "privileged: true\ntargets:\n  - path: /Library/Caches/*\nminAge: 30d\n"))).isEmpty)
        #expect(try lintIssues(packYAML(rule("a", "privileged: true\ntargets:\n  - path: /Library/Logs/*\nminAge: 30d\n"))).isEmpty)
        #expect(try lintIssues(packYAML(rule("a", "privileged: true\ntargets:\n  - path: /Library/Preferences/*\n")))
            .contains { $0.contains("privileged target must be inside") })
        #expect(try lintIssues(packYAML(rule("a", "privileged: true\ntargets:\n  - path: /Library/Caches\n")))
            .contains { $0.contains("privileged target must be inside") })
        #expect(try lintIssues(packYAML(rule("a", "privileged: true\ntargets:\n  - path: ~/Library/Caches/*\n")))
            .contains { $0.contains("privileged target must be inside") })
        // A system path needs the helper: it can't be an ordinary (in-process) rule.
        #expect(try lintIssues(packYAML(rule("a", "targets:\n  - path: /Library/Caches/*\n")))
            .contains { $0.contains("need `privileged: true`") })
        // The bundled system pack is clean.
        let (packs, issues) = RuleLinter.loadPacks(at: [repoRoot.appendingPathComponent("rules/cleanup/system.library.yaml").path], source: .bundled)
        #expect((issues + RuleLinter.lint(packs)).filter { $0.level == .error }.isEmpty)
    }

    @Test func theUserScanSkipsSystemRulesAndTheHelperScanOnlyRunsThem() throws {
        let s = try Setup()
        let user = s.userScanner.scan(s.packs)
        #expect(user.rules.first { $0.ruleID == "t.sys" }?.skipped?.contains("privileged helper") == true)
        #expect(user.rules.first { $0.ruleID == "t.sys" }?.privileged == true)
        #expect(user.candidates == 1)
        let helper = s.helperScanner.scan(s.packs)
        #expect(helper.rules.map(\.ruleID) == ["t.sys"])
        #expect(helper.rules[0].candidates.map(\.path) == ["\(s.system)/vendor"])
    }

    @Test func systemPlansNeedApprovalAndHoldOnlySystemItems() throws {
        let s = try Setup()
        let merged = CleanupReport(rules: s.userScanner.scan(s.packs).rules.filter { $0.privileged != true }
                                       + s.helperScanner.scan(s.packs).rules, bytes: 0, candidates: 0)
        let user = try #require(Planner.planCleanup(report: merged, host: host).plan)
        #expect(user.items.map(\.action) == [RemediationCatalog.cleanupQuarantine.id])
        #expect(!user.needsApproval && user.tier == .t2)
        let system = try #require(Planner.planCleanup(report: merged, system: true, host: host).plan)
        #expect(system.items.map(\.action) == [RemediationCatalog.cleanupQuarantineSystem.id])
        #expect(system.needsApproval && system.tier == .t2)
        #expect(try Plan.decodeCanonical(system.canonicalData()) == system)
        #expect(system.items[0].description == "Move to Farrier's system quarantine: \(s.system)/vendor")
        // In-process apply refuses system items; only the helper's run takes them.
        #expect(throws: PlanError.self) {
            try CleanupApplier.apply(system, packs: s.packs, scanner: s.userScanner, quarantine: s.userQuarantine)
        }
    }

    @Test func theHelpersMoveRestoreAndExpiry() throws {
        let s = try Setup()
        let report = s.helperScanner.scan(s.packs)
        let plan = try #require(Planner.planCleanup(report: report, system: true, host: host, now: s.home.now).plan)
        let moved = try CleanupApplier.apply(plan, packs: s.packs, scanner: s.helperScanner, quarantine: s.systemQuarantine,
                                             system: true, now: s.home.now)
        #expect(moved.map(\.outcome) == [.applied])
        #expect(FileStat.lstat("\(s.system)/vendor") == nil)
        // With the user's scanner (privileged rules skipped) nothing would have matched.
        let m = try s.systemQuarantine.load(plan.id)

        // Restore: refused if the quarantine changed since planning, else everything goes back.
        let restore = try #require(Planner.planSystemRestore(manifest: m, host: host))
        #expect(restore.needsApproval && restore.tier == .t2)
        var changed = m
        changed.items[0].state = .restored
        try s.systemQuarantine.save(changed)
        #expect(CleanupApplier.restoreSystem(restore.items[0], quarantine: s.systemQuarantine).map(\.outcome) == [.refused])
        try s.systemQuarantine.save(m)
        #expect(CleanupApplier.restoreSystem(restore.items[0], quarantine: s.systemQuarantine).map(\.outcome) == [.applied])
        #expect(FileStat.lstat("\(s.system)/vendor/blob") != nil)

        // Expiry of the system quarantine is T3 and needs approval.
        _ = try CleanupApplier.apply(try #require(Planner.planCleanup(report: s.helperScanner.scan(s.packs), system: true, host: host).plan),
                                     packs: s.packs, scanner: s.helperScanner, quarantine: s.systemQuarantine, system: true)
        let expiry = try #require(Planner.planExpiry(manifests: s.systemQuarantine.list(), named: true, system: true, host: host).plan)
        #expect(expiry.tier == .t3 && expiry.items.allSatisfy { $0.action == RemediationCatalog.quarantineExpireSystem.id })
        #expect(try CleanupApplier.expire(expiry, quarantine: s.systemQuarantine).allSatisfy { $0.outcome == .applied })
    }

    @Test func operationsUseTheHelper() throws {
        let s = try Setup()
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("farrier-ctx-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        try FileManager.default.createDirectory(at: dir.appendingPathComponent("rules"), withIntermediateDirectories: true)
        // The client's packs must lint: its system rule points at /Library/Caches. The (stubbed) helper scans the
        // test's stand-in folder with the same rule ids, as the real helper scans with its own bundled packs.
        let clientYAML = packYAML(
            rule("user", "targets:\n  - path: ~/Library/Caches/*\nminAge: 30d\n"),
            rule("sys", "privileged: true\ntargets:\n  - path: /Library/Caches/*\nminAge: 30d\n"))
        try clientYAML.write(to: dir.appendingPathComponent("rules/t.yaml"), atomically: true, encoding: .utf8)
        var sentToHelper: [Plan] = []
        var ctx = FarrierContext(
            collectFacts: { CollectionResult(facts: [:], notes: []) },
            rulePaths: [dir.appendingPathComponent("rules").path],
            plans: PlanStore(directory: dir.appendingPathComponent("plans")),
            journal: Journal(url: dir.appendingPathComponent("j.jsonl")),
            host: { host }, applyThroughHelper: { plan in
                // Stands in for the helper: its batch runs as SystemCleanup.apply does.
                sentToHelper.append(plan)
                let results: [CleanupItemResult]
                switch plan.items[0].action {
                case RemediationCatalog.cleanupQuarantineSystem.id:
                    results = try CleanupApplier.apply(plan, packs: s.packs, scanner: s.helperScanner, quarantine: s.systemQuarantine, system: true)
                case RemediationCatalog.quarantineRestoreSystem.id:
                    results = CleanupApplier.restoreSystem(plan.items[0], quarantine: s.systemQuarantine)
                default:
                    results = try CleanupApplier.expire(plan, quarantine: s.systemQuarantine)
                }
                return ApplyReply(planID: plan.id, results: results.map {
                    ItemResult(ruleID: $0.ruleID, action: plan.items[0].action, outcome: $0.outcome == .applied ? .applied : .refused, detail: $0.detail)
                }, error: nil)
            }, actor: "mcp:test")
        ctx.cleanupScanner = { s.userScanner }
        ctx.quarantine = s.userQuarantine
        ctx.scanSystemCleanup = { s.helperScanner.scan(s.packs) }
        ctx.systemQuarantine = { s.systemQuarantine.list() }

        // The scan merges the helper's results in place of the skipped system rule.
        let scan = try Operations.cleanupScan(ctx)
        #expect(scan.candidates == 2 && scan.rules.first { $0.ruleID == "t.sys" }?.skipped == nil)

        let planned = try ToolCatalog.call("cleanup_plan", arguments: ["system": .bool(true)], context: ctx)
        let planID = try #require(planned.structuredContent?.objectValue?["plan"]?.objectValue?["id"]?.stringValue)
        #expect(try ToolCatalog.call("apply_plan", arguments: ["planID": .string(planID)], context: ctx).isError != true)
        #expect(sentToHelper.count == 1 && FileStat.lstat("\(s.system)/vendor") == nil)
        #expect(FileStat.lstat("\(s.home.root)/Library/Caches/userapp") != nil)   // the user's cache isn't part of it

        let list = Operations.quarantineList(ctx)
        #expect(list.plans.count == 1 && list.plans[0].system == true)

        // Restoring a system plan goes through the helper too.
        let restored = try Operations.quarantineRestore(ctx, id: String(planID.prefix(8)))
        #expect(restored.results.map(\.outcome) == [.applied] && sentToHelper.count == 2)
        #expect(FileStat.lstat("\(s.system)/vendor/blob") != nil)

        // The helper unavailable: the system rule is skipped with the reason, the user's still scanned.
        ctx.scanSystemCleanup = { throw OperationError("the helper isn't running") }
        let without = try Operations.cleanupScan(ctx)
        #expect(without.rules.first { $0.ruleID == "t.sys" }?.skipped?.contains("the helper isn't running") == true)
        #expect(without.candidates == 1)
    }
}
