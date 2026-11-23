import Foundation
import Testing
@testable import FarrierCore
@testable import FarrierMCP

private let planA = "6f7d2c1a-0000-4000-8000-00000000000a"
private let planB = "6f7d2c1a-0000-4000-8000-00000000000b"

private func applied(_ plan: String, _ rule: String, _ action: String, previous: FactValue?, reverts: String? = nil) -> JournalRecord {
    JournalRecord(time: 1, actor: "helper", planID: plan, planHash: "h", ruleID: rule, action: action, outcome: "applied",
                  detail: nil, previous: previous, reverts: reverts)
}

private let facts = StaticFactStore(["firewall.globalState": .string("on"), "firewall.stealthMode": .string("on"),
                                     "softwareupdate.prefs": .object(["CriticalUpdateInstall": .bool(true), "ConfigDataInstall": .bool(true)])])

@Suite("Undo")
struct UndoTests {
    @Test func undoPlansTheReverseOfWhatThePlanApplied() throws {
        let journal = [
            applied(planA, "posture.core.firewall", "firewall.enable", previous: .string("off")),
            applied(planA, "posture.core.auto-security-updates", "softwareupdate.enableSecurityAutoInstall",
                    previous: .object(["CriticalUpdateInstall": .bool(false), "ConfigDataInstall": .bool(true)])),
            applied(planA, "posture.core.gatekeeper", "gatekeeper.enable", previous: nil),
            JournalRecord(time: 1, actor: "helper", planID: planA, planHash: "h", outcome: "approved"),
        ]
        let (plan, skipped) = try Planner.planUndo(planID: planA, journal: journal, facts: facts, host: "H")
        let items = try #require(plan?.items)
        #expect(items.map(\.action) == ["firewall.restore", "softwareupdate.restoreSecurityAutoInstall"])
        #expect(items.allSatisfy { $0.parameters == ["reverts": planA] && $0.tier == .t4 })
        #expect(items[0].observed == .string("on"))  // the current state, which the helper checks again
        #expect(items[0].description == "Undo: turn the application firewall off again (undoes plan 6f7d2c1a)")
        #expect(skipped == [PlanSkip(ruleID: "posture.core.gatekeeper", reason: RemediationCatalog.noUndoReason("gatekeeper.enable"))])
        // It's an ordinary canonical plan: the parameter is validated on decode.
        #expect(try Plan.decodeCanonical(try #require(plan).canonicalData()) == plan)
    }

    @Test func whatCantBeUndoneIsSaidWhy() throws {
        #expect(throws: PlanError.self) { try Planner.planUndo(planID: planB, journal: [], facts: facts, host: "H") }
        let journal = [
            applied(planA, "posture.core.firewall", "firewall.enable", previous: .string("off")),
            applied(planB, "posture.core.firewall", "firewall.restore", previous: nil, reverts: planA),
            applied(planA, "posture.core.firewall-stealth", "firewall.stealthEnable", previous: nil),  // older Farrier
        ]
        let (plan, skipped) = try Planner.planUndo(planID: planA, journal: journal, facts: facts, host: "H")
        #expect(plan == nil)
        #expect(skipped.map(\.reason) == ["already undone", "the journal has no earlier state for it (applied by an older Farrier)"])
        // An undo isn't undone in turn: the fix is planned again instead.
        let (again, why) = try Planner.planUndo(planID: planB, journal: journal, facts: facts, host: "H")
        #expect(again == nil)
        #expect(why.first?.reason.contains("itself an undo") == true)
    }

    @Test func undoParametersAreStrict() throws {
        #expect(try UndoRules.validate(["reverts": planA]) == planA)
        for bad: [String: String]? in [nil, [:], ["reverts": "abc"], ["reverts": planA.uppercased()], ["reverts": planA, "x": "y"]] {
            #expect(throws: PlanError.self) { try UndoRules.validate(bad) }
        }
        // Every undo action reverses a catalog action and keeps its tier and MDM checks.
        for undo in RemediationCatalog.all where undo.reverses != nil {
            let forward = try #require(RemediationCatalog.action(undo.reverses!))
            #expect(undo.tier == forward.tier && undo.fact == forward.fact)
            #expect(undo.managedPayloadTypes == forward.managedPayloadTypes && undo.managedPreference == forward.managedPreference)
            #expect(RemediationCatalog.undo(of: forward.id) == undo)
        }
    }

    @Test func journalRecordsWithoutTheNewFieldsHashTheSame() throws {
        // Old entries (no previous/reverts) must verify unchanged: absent optionals aren't encoded.
        let old = JournalRecord(time: 5, actor: "helper", planID: planA, planHash: "h", outcome: "approved")
        let data = try JSONEncoder().encode(old)
        #expect(!String(decoding: data, as: UTF8.self).contains("previous"))
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("farrier-undo-\(UUID().uuidString)")
        let journal = Journal(url: dir.appendingPathComponent("j.jsonl"))
        try journal.append(old)
        try journal.append(applied(planA, "posture.core.firewall", "firewall.enable", previous: .string("off")))
        #expect(journal.verify().isEmpty)
        #expect(try journal.entries().last?.record.previous == .string("off"))
    }

    @Test func operationResolvesAPrefixFromTheHelperJournal() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("farrier-undo-\(UUID().uuidString)")
        let helper = Journal(url: dir.appendingPathComponent("helper.jsonl"))
        try helper.append(applied(planA, "posture.core.firewall", "firewall.enable", previous: .string("off")))
        let ctx = FarrierContext(
            collectFacts: { CollectionResult(facts: facts.facts, notes: []) },
            rulePaths: [repoRoot.appendingPathComponent("rules").path],
            plans: PlanStore(directory: dir.appendingPathComponent("plans")),
            journal: Journal(url: dir.appendingPathComponent("user.jsonl")),
            host: { "H" }, applyThroughHelper: { _ in throw OperationError("none") }, actor: "cli")
        let out = try Operations.planUndo(ctx, id: "6f7d2c1a-0000-4000-8000-00000000000", journal: helper)
        #expect(out.plan?.items.first?.action == "firewall.restore")
        #expect(throws: OperationError.self) { try Operations.planUndo(ctx, id: "ffff", journal: helper) }
        #expect(try ctx.journal.entries().last?.record.reverts == planA)
    }
}
