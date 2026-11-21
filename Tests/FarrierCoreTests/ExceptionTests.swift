import Foundation
import MCP
import Testing
@testable import FarrierCore
@testable import FarrierMCP

private let rule = "posture.core.unsigned-launch-items"
private let host = "8E5C0F3A-0000-4000-8000-0000000000EE"

private func launchItem(_ label: String, team: String?, valid: Bool = true, notarized: Bool = false,
                        identifier: String? = nil) -> FactValue {
    var sig: [String: FactValue] = ["valid": .bool(valid), "notarized": .bool(notarized)]
    if let team { sig["teamID"] = .string(team) }
    if let identifier { sig["identifier"] = .string(identifier) }
    return .object(["label": .string(label), "signature": .object(sig)])
}

private let parallels = [
    launchItem("com.parallels.vm.prltoolsd", team: "4C6364ACXT", identifier: "com.parallels.desktop.console.common"),
    launchItem("com.parallels.copypaste", team: "4C6364ACXT", identifier: "com.parallels.desktop.console.common"),
]

private func exception(team: String = "4C6364ACXT", identifier: String? = nil) -> PostureException {
    PostureException(ruleID: rule, teamID: team, identifier: identifier, reason: "Parallels Guest Tools in this VM",
                     acceptedAt: 1_800_000_000, planID: "p")
}

private func packs() throws -> [RulePack] {
    let (packs, issues) = RuleLinter.loadPacks(at: [repoRoot.appendingPathComponent("rules/posture").path], source: .bundled)
    try #require(issues.filter { $0.level == .error }.isEmpty)
    return packs
}

private func finding(_ items: [FactValue], _ exceptions: [PostureException]) throws -> Finding {
    let report = PostureEngine.evaluate(try packs(), facts: StaticFactStore(["launchd.items": .array(items)]), exceptions: exceptions)
    return try #require(report.findings.first { $0.ruleID == rule })
}

@Suite("Posture exceptions")
struct ExceptionTests {
    @Test func matchingNeedsAValidSignatureByTheTeam() {
        let e = exception()
        #expect(e.matches(parallels[0]))
        #expect(!e.matches(launchItem("x", team: "4C6364ACXT", valid: false)))  // a broken signature is never accepted
        #expect(!e.matches(launchItem("x", team: "ABCDE12345")))
        #expect(!e.matches(launchItem("x", team: nil)))
        #expect(exception(identifier: "com.parallels.desktop.console.common").matches(parallels[1]))
        #expect(!exception(identifier: "com.parallels.other").matches(parallels[1]))
    }

    @Test func exceptionsOnlyRemoveTheVendorsItems() throws {
        #expect(try finding(parallels, []).status == .fail)
        let accepted = try finding(parallels, [exception()])
        #expect(accepted.status == .pass)
        #expect(accepted.accepted == ["com.parallels.vm.prltoolsd", "com.parallels.copypaste"])
        // Another vendor's failing item still fails, and is the one named.
        let other = try finding(parallels + [launchItem("com.sketchy.agent", team: "ZZZZZ99999")], [exception()])
        #expect(other.status == .fail)
        #expect(other.reason?.contains("com.sketchy.agent") == true)
        #expect(other.reason?.contains("parallels") == false)
        // An exception for another rule changes nothing.
        let elsewhere = PostureException(ruleID: "posture.core.firewall", teamID: "4C6364ACXT", identifier: nil,
                                         reason: "x", acceptedAt: 0, planID: "p")
        #expect(try finding(parallels, [elsewhere]).status == .fail)
    }

    @Test func parametersAreStrict() {
        func ok(_ p: [String: String], rule r: String = rule) -> Bool { (try? ExceptionRules.validate(ruleID: r, p)) != nil }
        #expect(ok(["teamID": "4C6364ACXT", "reason": "Parallels Guest Tools"]))
        #expect(!ok(["teamID": "4c6364acxt", "reason": "lowercase"]))
        #expect(!ok(["teamID": "4C6364ACX", "reason": "too short"]))
        #expect(!ok(["teamID": "4C6364ACXT", "reason": "two\nlines"]))
        #expect(!ok(["teamID": "4C6364ACXT", "reason": "x"]))
        #expect(!ok(["teamID": "4C6364ACXT", "reason": "ok reason", "path": "/tmp"]))
        #expect(!ok(["teamID": "4C6364ACXT", "identifier": "a b", "reason": "spaces"]))
        #expect(!ok(["teamID": "4C6364ACXT", "reason": "not this rule"], rule: "posture.core.firewall"))
    }

    @Test func planningAnExceptionMakesAReviewableT4Plan() throws {
        let facts = StaticFactStore(["launchd.items": .array(parallels)])
        #expect(throws: PlanError.self) {
            try Planner.planException(ruleID: rule, teamID: "ZZZZZ99999", identifier: nil, reason: "nothing signed by it",
                                      facts: facts, existing: [], host: host)
        }
        #expect(throws: PlanError.self) {
            try Planner.planException(ruleID: rule, teamID: "4C6364ACXT", identifier: nil, reason: "already there",
                                      facts: facts, existing: [exception()], host: host)
        }
        let plan = try Planner.planException(ruleID: rule, teamID: "4C6364ACXT", identifier: nil,
                                             reason: "Parallels Guest Tools in this VM", facts: facts, existing: [], host: host)
        #expect(plan.tier == .t4)
        let item = try #require(plan.items.first)
        #expect(item.observed == .array([.string("com.parallels.vm.prltoolsd"), .string("com.parallels.copypaste")]))
        #expect(item.description.contains("team 4C6364ACXT"))
        #expect(item.description.contains("Parallels Guest Tools in this VM"))
        #expect(try Plan.decodeCanonical(plan.canonicalData()) == plan)

        // Edited parameters are re-validated when the plan is loaded (and again by the helper).
        let text = String(decoding: try plan.canonicalData(), as: UTF8.self)
        let forged = Data(text.replacingOccurrences(of: "\"teamID\":\"4C6364ACXT\"", with: "\"teamID\":\"anything\"").utf8)
        #expect(forged != (try plan.canonicalData()))
        #expect(throws: PlanError.self) { try Plan.decodeCanonical(forged) }
    }

    @Test func onlyExceptionsTakeParameters() throws {
        let item = PlanItem(ruleID: "posture.core.firewall", action: "firewall.enable", tier: .t4,
                            summary: RemediationCatalog.firewallEnable.summary, fact: "firewall.globalState",
                            observed: .string("off"), parameters: ["teamID": "4C6364ACXT"])
        let data = try Plan(id: "x", createdAt: 1, expiresAt: 2, host: host, items: [item]).canonicalData()
        #expect(throws: PlanError.self) { try Plan.decodeCanonical(data) }
        // Plans without parameters encode exactly as before (no key), so earlier plans keep their hashes.
        let plain = PlanItem(ruleID: "r", action: "firewall.enable", tier: .t4, summary: "s", fact: "f", observed: .null)
        let json = String(decoding: try JSONEncoder().encode(plain), as: UTF8.self)
        #expect(!json.contains("parameters"))
    }

    @Test func removalNeedsAnExistingException() throws {
        #expect(throws: PlanError.self) {
            try Planner.planExceptionRemoval(ruleID: rule, teamID: "4C6364ACXT", identifier: nil, existing: [], host: host)
        }
        let plan = try Planner.planExceptionRemoval(ruleID: rule, teamID: "4C6364ACXT", identifier: nil,
                                                    existing: [exception()], host: host)
        #expect(plan.items.first?.action == "exception.remove")
        #expect(try Plan.decodeCanonical(plan.canonicalData()) == plan)
    }

    @Test func theStoreIgnoresFilesItCantTrust() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("farrier-exc-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("exceptions.json").path
        #expect(ExceptionStore(path: path).load().exceptions.isEmpty)
        #expect(ExceptionStore(path: path).load().problem == nil)

        try ExceptionStore.encode([exception()]).write(to: URL(fileURLWithPath: path))
        try FileManager.default.setAttributes([.posixPermissions: NSNumber(value: 0o666)], ofItemAtPath: path)
        let loose = ExceptionStore(path: path).load()
        #expect(loose.exceptions.isEmpty)               // writable by others: ignored
        #expect(loose.problem?.contains("ignored") == true)
        #expect(ExceptionStore(path: path, requireRootOwned: false).load().exceptions == [exception()])

        try Data("garbage".utf8).write(to: URL(fileURLWithPath: path))
        #expect(ExceptionStore(path: path, requireRootOwned: false).load().problem?.contains("cannot parse") == true)
    }

    @Test func mcpToolsPlanAndListExceptions() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("farrier-exc-mcp-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        var ctx = FarrierContext(
            collectFacts: { CollectionResult(facts: ["launchd.items": .array(parallels)], notes: []) },
            rulePaths: [repoRoot.appendingPathComponent("rules").path],
            plans: PlanStore(directory: dir.appendingPathComponent("plans")),
            journal: Journal(url: dir.appendingPathComponent("journal.jsonl")),
            host: { host }, applyThroughHelper: { _ in throw OperationError("no helper") }, actor: "mcp:test")
        ctx.exceptions = { ([], nil) }

        let planned = ToolCatalog.call("posture_plan_exception",
                                       arguments: ["teamID": "4C6364ACXT", "reason": "Parallels Guest Tools in this VM"], context: ctx)
        #expect(planned.isError == nil)
        let item = try #require(planned.structuredContent?.objectValue?["plan"]?.objectValue?["items"]?.arrayValue?.first?.objectValue)
        #expect(item["action"] == "exception.add")
        #expect(ToolCatalog.call("posture_plan_exception", arguments: ["teamID": "4C6364ACXT"], context: ctx).isError == true)  // no reason

        ctx.exceptions = { ([exception()], nil) }
        let listed = ToolCatalog.call("exceptions_list", arguments: [:], context: ctx)
        #expect(listed.structuredContent?.objectValue?["exceptions"]?.arrayValue?.count == 1)
        let posture = ToolCatalog.call("posture_check", arguments: ["ruleIDs": [.string(rule)]], context: ctx)
        let f = try #require(posture.structuredContent?.objectValue?["findings"]?.arrayValue?.first?.objectValue)
        #expect(f["status"] == "pass")
        #expect(f["accepted"]?.arrayValue?.count == 2)
    }
}
