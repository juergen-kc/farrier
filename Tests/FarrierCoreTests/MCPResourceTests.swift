import Foundation
import MCP
import Testing
@testable import FarrierCore
@testable import FarrierMCP

private func context() throws -> FarrierContext {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("farrier-res-\(UUID().uuidString)")
    var ctx = FarrierContext(
        collectFacts: { CollectionResult(facts: [:], notes: []) },
        rulePaths: [repoRoot.appendingPathComponent("rules").path],
        plans: PlanStore(directory: dir.appendingPathComponent("plans")),
        journal: Journal(url: dir.appendingPathComponent("journal.jsonl")),
        host: { "H" }, applyThroughHelper: { _ in throw OperationError("none") }, actor: "mcp:test")
    ctx.snapshots = SnapshotStore(directory: dir.appendingPathComponent("snapshots").path)
    return ctx
}

private func plan(_ id: String, expiresAt: Int64) -> Plan {
    let item = PlanItem(ruleID: "posture.core.firewall", action: "firewall.enable", tier: .t4,
                        summary: RemediationCatalog.firewallEnable.summary, fact: "firewall.globalState", observed: .string("off"))
    return Plan(id: id, createdAt: expiresAt - 900, expiresAt: expiresAt, host: "H", items: [item])
}

@Suite("MCP resources and progress")
struct MCPResourceTests {
    @Test func listsJournalsAndLivePlans() throws {
        let ctx = try context()
        let now = Date(timeIntervalSince1970: 2_000_000_000)
        _ = try ctx.plans.save(plan("aaaaaaaa-0000-4000-8000-000000000001", expiresAt: 2_000_000_500))   // live
        _ = try ctx.plans.save(plan("bbbbbbbb-0000-4000-8000-000000000002", expiresAt: 1_999_999_000))   // expired
        let uris = ResourceCatalog.list(ctx, now: now).map(\.uri)
        #expect(uris == ["farrier://journal/recent", "farrier://journal/helper", "farrier://plan/aaaaaaaa-0000-4000-8000-000000000001"])
        #expect(ResourceCatalog.templates.map(\.uriTemplate) == ["farrier://plan/{id}", "farrier://snapshot/{id}"])
        #expect(try ctx.plans.load(exactID: "aaaaaaaa-0000-4000-8000-000000000001").id == "aaaaaaaa-0000-4000-8000-000000000001")
        #expect(throws: PlanError.self) { try ctx.plans.load(exactID: "aaaa") }   // exact ids only
        #expect(throws: PlanError.self) { try ctx.plans.load(exactID: "../../etc/passwd") }
    }

    @Test func readsPlansAndJournalsAsJSON() throws {
        let ctx = try context()
        let now = Date(timeIntervalSince1970: 2_000_000_000)
        _ = try ctx.plans.save(plan("aaaaaaaa-0000-4000-8000-000000000001", expiresAt: 2_000_000_500))
        try ctx.journal.append(JournalRecord(time: 1, actor: "cli", planID: "aaaaaaaa-0000-4000-8000-000000000001", planHash: "h", outcome: "planned"))

        let planContent = try #require(ResourceCatalog.read("farrier://plan/aaaa", ctx, now: now).first)
        #expect(planContent.uri == "farrier://plan/aaaa")
        #expect(planContent.mimeType == "application/json")
        let view = try JSONDecoder().decode(PlanView.self, from: Data(try #require(planContent.text).utf8))
        #expect(view.plan.items.first?.action == "firewall.enable")
        #expect(view.expiresInSeconds == 500)

        let journal = try #require(ResourceCatalog.read("farrier://journal/recent", ctx).first?.text)
        #expect(journal.contains("\"outcome\":\"planned\""))
        let helper = Journal(url: FileManager.default.temporaryDirectory.appendingPathComponent("farrier-res-helper-\(UUID().uuidString).jsonl"))
        #expect(try ResourceCatalog.read("farrier://journal/helper", ctx, helperJournal: helper).first?.text?.contains("\"journal\":\"helper\"") == true)

        #expect(throws: MCPError.self) { try ResourceCatalog.read("farrier://plan/zzzz", ctx) }
        #expect(throws: MCPError.self) { try ResourceCatalog.read("file:///etc/passwd", ctx) }
    }

    @Test func progressSaysWhatsHappening() {
        #expect(ToolProgress.message(tool: "apply_plan", seconds: 0).contains("approve on the Mac"))
        #expect(ToolProgress.message(tool: "apply_plan", seconds: 10).hasSuffix("(10 s)"))
        #expect(ToolProgress.message(tool: "inventory", seconds: 0).contains("signatures"))
        #expect(ToolProgress.message(tool: "something_new", seconds: 0) == "working")
    }
}
