import Foundation
import MCP
import Testing
@testable import FarrierCore
@testable import FarrierHelperKit
@testable import FarrierMCP

private let testHost = "8E5C0F3A-0000-4000-8000-0000000000AA"

/// A context with the sample facts, the repo's rule packs, and plans and journal in a temporary directory.
private func context(apply: @escaping (Plan) throws -> ApplyReply = { _ in throw OperationError("no helper in tests") })
    throws -> (FarrierContext, URL) {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("farrier-mcp-\(UUID().uuidString)")
    let sample = try StaticFactStore(json: Data(contentsOf: repoRoot.appendingPathComponent("examples/facts-sample.json")))
    let ctx = FarrierContext(
        collectFacts: { CollectionResult(facts: sample.facts, notes: sample.facts.keys.map {
            CollectionNote(fact: $0, status: .collected, source: "sample", detail: nil)
        }) },
        rulePaths: [repoRoot.appendingPathComponent("rules").path],
        plans: PlanStore(directory: dir.appendingPathComponent("plans")),
        journal: Journal(url: dir.appendingPathComponent("journal.jsonl")),
        host: { testHost },
        applyThroughHelper: apply,
        actor: "mcp:test")
    return (ctx, dir)
}

private func object(_ r: CallTool.Result) throws -> [String: Value] {
    try #require(r.structuredContent?.objectValue, "no structured content: \(r.content)")
}

@Suite("MCP tools")
struct MCPToolTests {
    @Test func catalogIsWellFormed() {
        let tools = ToolCatalog.tools
        #expect(Set(tools.map(\.name)).count == tools.count)
        for t in tools {
            #expect(t.annotations.title?.isEmpty == false, "\(t.name) needs an annotation title (Claude Code shows it)")
            #expect(t.inputSchema.objectValue?["type"] == "object")
        }
        let apply = tools.first { $0.name == "apply_plan" }
        #expect(apply?.annotations.destructiveHint == true)
        #expect(apply?.annotations.readOnlyHint == false)
        for name in ["farrier_status", "facts_collect", "posture_check", "posture_explain", "plan_show", "journal_recent"] {
            #expect(tools.first { $0.name == name }?.annotations.readOnlyHint == true, "\(name) should be read-only")
        }
        // Planning writes a plan file but changes nothing on the Mac.
        let plan = tools.first { $0.name == "posture_plan_remediation" }
        #expect(plan?.annotations.readOnlyHint == false)
        #expect(plan?.annotations.destructiveHint == false)
    }

    @Test func postureCheckReturnsFindings() throws {
        let (ctx, dir) = try context()
        defer { try? FileManager.default.removeItem(at: dir) }
        let r = ToolCatalog.call("posture_check", arguments: [:], context: ctx)
        #expect(r.isError == nil)
        let findings = try #require(try object(r)["findings"]?.arrayValue)
        let firewall = try #require(findings.first { $0.objectValue?["ruleID"] == "posture.core.firewall" }?.objectValue)
        #expect(firewall["status"] == "fail")
        #expect(firewall["fixable"] == true)
        // The text content carries the same JSON, for clients that only read text.
        if case .text(let text, _, _) = try #require(r.content.first) { #expect(text.contains("posture.core.firewall")) }

        let one = ToolCatalog.call("posture_check", arguments: ["ruleIDs": ["posture.core.sip"]], context: ctx)
        #expect(try object(one)["findings"]?.arrayValue?.count == 1)
        #expect(ToolCatalog.call("posture_check", arguments: ["ruleIDs": ["nope"]], context: ctx).isError == true)
        #expect(ToolCatalog.call("posture_check", arguments: ["ruleIDs": "posture.core.sip"], context: ctx).isError == true)
    }

    @Test func explainSaysHowARuleIsFixed() throws {
        let (ctx, dir) = try context()
        defer { try? FileManager.default.removeItem(at: dir) }
        let firewall = try object(ToolCatalog.call("posture_explain", arguments: ["ruleID": "posture.core.firewall"], context: ctx))
        #expect(firewall["fixImplemented"] == true)
        #expect(firewall["fixAction"] == "firewall.enable")
        #expect(firewall["expectation"]?.stringValue?.contains("one of") == true)
        let filevault = try object(ToolCatalog.call("posture_explain", arguments: ["ruleID": "posture.core.filevault"], context: ctx))
        #expect(filevault["automaticFix"] == false)
        #expect(filevault["guidance"]?.stringValue?.isEmpty == false)
        #expect(ToolCatalog.call("posture_explain", arguments: [:], context: ctx).isError == true)
    }

    @Test func planShowApplyAndJournal() throws {
        let (ctx, dir) = try context(apply: { plan in
            ApplyReply(planID: plan.id, results: plan.items.map {
                ItemResult(ruleID: $0.ruleID, action: $0.action, outcome: .applied, detail: "off → on")
            }, error: nil)
        })
        defer { try? FileManager.default.removeItem(at: dir) }

        let planned = try object(ToolCatalog.call("posture_plan_remediation", arguments: [:], context: ctx))
        let plan = try #require(planned["plan"]?.objectValue)
        #expect(plan["tier"] == "T4")
        #expect(plan["host"] == .string(testHost))
        let id = try #require(plan["id"]?.stringValue)

        let shown = try object(ToolCatalog.call("plan_show", arguments: ["planID": .string(String(id.prefix(8)))], context: ctx))
        #expect(shown["needsApproval"] == true)
        #expect(shown["expired"] == false)
        #expect(shown["planHash"] == planned["planHash"])

        let applied = ToolCatalog.call("apply_plan", arguments: ["planID": .string(id)], context: ctx)
        #expect(applied.isError == nil)
        #expect(try object(applied)["results"]?.arrayValue?.first?.objectValue?["outcome"] == "applied")

        let journal = try object(ToolCatalog.call("journal_recent", arguments: [:], context: ctx))
        #expect(journal["intact"] == true)
        let outcomes = journal["entries"]?.arrayValue?.compactMap { $0.objectValue?["outcome"]?.stringValue }
        #expect(outcomes == ["planned", "applied"])
        #expect(journal["entries"]?.arrayValue?.first?.objectValue?["actor"] == "mcp:test")
    }

    @Test func aRefusedApplyIsAnErrorResult() throws {
        let (ctx, dir) = try context(apply: { _ in throw OperationError("the approval prompt was cancelled; nothing changed") })
        defer { try? FileManager.default.removeItem(at: dir) }
        let id = try #require(try object(ToolCatalog.call("posture_plan_remediation", arguments: [:], context: ctx))["plan"]?
            .objectValue?["id"]?.stringValue)
        let r = ToolCatalog.call("apply_plan", arguments: ["planID": .string(id)], context: ctx)
        #expect(r.isError == true)
        #expect(try object(r)["error"]?.stringValue?.contains("cancelled") == true)
        #expect(ToolCatalog.call("apply_plan", arguments: ["planID": "ffffffff"], context: ctx).isError == true)
    }

    @Test func unknownToolsAndPromptsAreErrors() {
        #expect(ToolCatalog.call("shell_run", arguments: [:], context: FarrierContext.live(actor: "test")).isError == true)
        #expect(throws: (any Error).self) { try Runbooks.get("nope") }
        #expect(Runbooks.prompts.map(\.name) == ["security-checkup"])
    }

    @Test func expectationsDescribeThemselves() throws {
        let e = try Expectation.parse(.object(["all": .array([
            .object(["path": .string("CriticalUpdateInstall"), "equals": .bool(true)]),
            .object(["in": .array([.string("on"), .string("blockAll")])]),
        ])]))
        #expect(e.description == #"all of (CriticalUpdateInstall equals true; one of "on", "blockAll")"#)
    }
}
