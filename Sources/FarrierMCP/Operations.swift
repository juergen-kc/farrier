import FarrierCore
import FarrierHelperKit
import Foundation

// What the CLI and the MCP server share: the same facts, rules, plans and apply path, so `farrier … --json` and
// a tool's structured content are the same data.

// MARK: - Environment

/// T0 facts from the collectors, plus T1 facts from the privileged helper when it's available (macOS, running
/// from Farrier.app, helper enabled, console session). Without the helper, T1 facts are noted as unavailable.
public func collectAllFacts() -> CollectionResult {
    let base = SystemCollectors().collect()
    #if os(macOS)
    return base.merging(HelperClient.collectPrivilegedFacts())
    #else
    return base
    #endif
}

/// Rule packs when no path is given: those bundled in Farrier.app (`Contents/Resources/rules`) when running from
/// the app, so the installed CLI works from any directory; otherwise `./rules` (a checkout).
public func defaultRulePaths() -> [String] {
    if Bundle.main.bundlePath.hasSuffix(".app"), let resources = Bundle.main.resourceURL {
        let bundled = resources.appendingPathComponent("rules")
        if FileManager.default.fileExists(atPath: bundled.path) { return [bundled.path] }
    }
    return ["rules"]
}

/// The user journal (docs/ARCHITECTURE.md, "Journal"). The helper keeps its own, root-owned one.
public let userJournal = Journal(url: FileManager.default.homeDirectoryForCurrentUser
    .appendingPathComponent("Library/Application Support/Farrier/journal.jsonl"))

public let helperJournal = Journal(url: URL(fileURLWithPath: HelperConstants.helperJournalPath))

/// Everything an operation touches outside itself, so tests can substitute facts, rules and storage.
public struct FarrierContext {
    public var collectFacts: () -> CollectionResult
    public var rulePaths: [String]
    public var plans: PlanStore
    public var journal: Journal
    public var host: () -> String
    /// Applies a T3/T4 plan through the helper (asks the user on the Mac). Not available on Linux.
    public var applyThroughHelper: (Plan) throws -> ApplyReply
    /// Who is asking, for the journal: `cli` or `mcp:<client name>`.
    public var actor: String

    public init(collectFacts: @escaping () -> CollectionResult, rulePaths: [String], plans: PlanStore, journal: Journal,
                host: @escaping () -> String, applyThroughHelper: @escaping (Plan) throws -> ApplyReply, actor: String) {
        self.collectFacts = collectFacts
        self.rulePaths = rulePaths
        self.plans = plans
        self.journal = journal
        self.host = host
        self.applyThroughHelper = applyThroughHelper
        self.actor = actor
    }

    public static func live(actor: String) -> FarrierContext {
        FarrierContext(
            collectFacts: collectAllFacts,
            rulePaths: defaultRulePaths(),
            plans: .default,
            journal: userJournal,
            host: { HostIdentity.hardwareUUID() ?? "unknown-host" },
            applyThroughHelper: { plan in
                #if os(macOS)
                return try PlanApplier.apply(plan)
                #else
                throw OperationError("applying plans needs macOS and Farrier.app")
                #endif
            },
            actor: actor
        )
    }
}

public struct OperationError: Error, CustomStringConvertible {
    public let description: String
    public init(_ description: String) { self.description = description }
}

// MARK: - Outputs (the JSON shapes of the tools and of `--json`)

public struct FactsOutput: Codable {
    public let facts: [String: FactValue]
    public let notes: [CollectionNote]
}

public struct PostureOutput: Codable {
    public let findings: [Finding]
    public let summary: [String: Int]
    /// How each fact was obtained, or why it's missing (only for the facts the evaluated rules use).
    public let collection: [CollectionNote]
}

public struct RuleExplanation: Codable {
    public let id: String
    public let pack: String
    public let title: String
    public let severity: Severity
    public let fact: String
    public let expectation: String
    public let managedBy: [ManagedBy]
    public let automaticFix: Bool
    public let fixAction: String?
    /// Whether Farrier can carry the fix out today (it's in the remediation catalog).
    public let fixImplemented: Bool
    public let guidance: String?
    public let mappings: [String: String]
}

public struct PlanOutput: Codable {
    public let plan: Plan?
    public let planHash: String?
    public let skipped: [PlanSkip]
    public let path: String?
    public let next: String
}

public struct PlanView: Codable {
    public let plan: Plan
    public let planHash: String
    public let expired: Bool
    public let expiresInSeconds: Int64
    public let needsApproval: Bool
}

public struct ApplyOutput: Codable {
    public let planID: String
    public let results: [ItemResult]
    /// Set when the plan was not applied (refused, cancelled, not set up) or stopped partway.
    public let error: String?
}

public struct JournalOutput: Codable {
    public let journal: String
    public let path: String
    public let intact: Bool
    public let issues: [String]
    public let entries: [JournalRecord]
}

// MARK: - Operations

public enum Operations {
    /// Loads the rule packs and refuses to go on if any has errors (the same checks as `farrier rules lint`).
    public static func packs(_ ctx: FarrierContext) throws -> [RulePack] {
        let (packs, loadIssues) = RuleLinter.loadPacks(at: ctx.rulePaths, source: .bundled)
        let errors = (loadIssues + RuleLinter.lint(packs)).filter { $0.level == .error }
        guard errors.isEmpty else {
            throw OperationError("rule packs have errors: \(errors.map { "\($0)" }.joined(separator: "; "))")
        }
        return packs
    }

    public static func facts(_ ctx: FarrierContext) -> FactsOutput {
        let result = ctx.collectFacts()
        return FactsOutput(facts: result.facts, notes: result.notes.sorted { $0.fact < $1.fact })
    }

    public static func posture(_ ctx: FarrierContext, ruleIDs: Set<String>? = nil) throws -> PostureOutput {
        let packs = try packs(ctx)
        let collected = ctx.collectFacts()
        let report = PostureEngine.evaluate(packs, facts: StaticFactStore(collected))
        var used: Set<String> = [CoreFacts.profilePayloadTypes, CoreFacts.declarationTypes]
        for pack in packs { for case .check(let rule) in pack.rules { used.insert(rule.fact) } }
        let findings = ruleIDs.map { ids in report.findings.filter { ids.contains($0.ruleID) } } ?? report.findings
        if let ruleIDs {
            let unknown = ruleIDs.subtracting(report.findings.map(\.ruleID))
            guard unknown.isEmpty else { throw OperationError("no such posture rule: \(unknown.sorted().joined(separator: ", "))") }
        }
        return PostureOutput(findings: findings, summary: PostureReport(findings: findings).summary,
                             collection: collected.notes.filter { used.contains($0.fact) }.sorted { $0.fact < $1.fact })
    }

    public static func explain(_ ctx: FarrierContext, ruleID: String) throws -> RuleExplanation {
        for pack in try packs(ctx) {
            for case .check(let rule) in pack.rules where rule.id == ruleID {
                return RuleExplanation(
                    id: rule.id, pack: pack.id, title: rule.title, severity: rule.severity, fact: rule.fact,
                    expectation: rule.expect.description, managedBy: rule.managedBy,
                    automaticFix: rule.remediation.automatic, fixAction: rule.remediation.action,
                    fixImplemented: rule.remediation.action.flatMap(RemediationCatalog.action) != nil,
                    guidance: rule.remediation.guidance?.trimmingCharacters(in: .whitespacesAndNewlines),
                    mappings: rule.mappings)
            }
        }
        throw OperationError("no such posture rule: \(ruleID)")
    }

    /// Plans fixes for failing posture checks and saves the plan. Nothing on the Mac changes.
    public static func planPosture(_ ctx: FarrierContext, ruleIDs: Set<String>? = nil, now: Date = Date()) throws -> PlanOutput {
        let packs = try packs(ctx)
        let store = StaticFactStore(ctx.collectFacts())
        let report = PostureEngine.evaluate(packs, facts: store)
        let (plan, skipped) = Planner.plan(report: report, packs: packs, facts: store, ruleIDs: ruleIDs,
                                           host: ctx.host(), now: now)
        guard let plan else {
            return PlanOutput(plan: nil, planHash: nil, skipped: skipped, path: nil, next: "nothing to fix automatically")
        }
        let url = try ctx.plans.save(plan)
        let hash = try plan.hash().hexString
        try? ctx.journal.append(JournalRecord(time: plan.createdAt, actor: ctx.actor, planID: plan.id, planHash: hash,
                                              outcome: "planned", detail: "\(plan.items.count) item(s), \(plan.tier.rawValue)"))
        let next = plan.tier.needsApproval
            ? "review the plan with the user; applying it asks them for Touch ID or their password on this Mac"
            : "review the plan with the user, then apply it"
        return PlanOutput(plan: plan, planHash: hash, skipped: skipped, path: url.path, next: next)
    }

    public static func show(_ ctx: FarrierContext, id: String, now: Date = Date()) throws -> PlanView {
        let plan = try ctx.plans.load(id)
        let left = plan.expiresAt - Int64(now.timeIntervalSince1970)
        return PlanView(plan: plan, planHash: try plan.hash().hexString, expired: left <= 0,
                        expiresInSeconds: max(0, left), needsApproval: plan.tier.needsApproval)
    }

    /// Applies a saved plan. Blocks until the user answers the prompt on the Mac (or cancels).
    public static func apply(_ ctx: FarrierContext, id: String) throws -> ApplyOutput {
        let plan = try ctx.plans.load(id)
        let hash = try plan.hash().hexString
        func record(_ outcome: String, _ r: ItemResult? = nil, detail: String? = nil) {
            try? ctx.journal.append(JournalRecord(time: Int64(Date().timeIntervalSince1970), actor: ctx.actor, planID: plan.id,
                                                  planHash: hash, ruleID: r?.ruleID, action: r?.action,
                                                  outcome: outcome, detail: detail ?? r?.detail))
        }
        do {
            let reply = try ctx.applyThroughHelper(plan)
            for r in reply.results { record(r.outcome.rawValue, r) }
            if let error = reply.error { record("stopped", detail: error) }
            return ApplyOutput(planID: plan.id, results: reply.results, error: reply.error)
        } catch {
            record("notApplied", detail: "\(error)")
            return ApplyOutput(planID: plan.id, results: [], error: "\(error)")
        }
    }

    public static func journal(_ which: Journal, name: String, last: Int) -> JournalOutput {
        let issues = which.verify()
        let entries = ((try? which.entries()) ?? []).suffix(max(0, min(last, 500))).map(\.record)
        return JournalOutput(journal: name, path: which.url.path, intact: issues.isEmpty, issues: issues, entries: Array(entries))
    }
}
