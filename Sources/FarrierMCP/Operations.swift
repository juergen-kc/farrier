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
    /// `.bundled` for Farrier's own packs; `.user` for packs given on the command line (they can't plan fixes).
    public var rulePackSource: RulePack.Source = .bundled
    public var plans: PlanStore
    public var journal: Journal
    public var host: () -> String
    /// Applies a T3/T4 plan through the helper (asks the user on the Mac). Not available on Linux.
    public var applyThroughHelper: (Plan) throws -> ApplyReply
    /// Who is asking, for the journal: `cli` or `mcp:<client name>`.
    public var actor: String
    /// Approved posture exceptions (the root-owned file the helper writes).
    public var exceptions: () -> (exceptions: [PostureException], problem: String?) = { ExceptionStore().load() }
    /// The facts only the inventory needs (apps, system extensions, admins); slower, so not part of `collectFacts`.
    public var collectInventory: () -> CollectionResult = { InventoryCollector().collect() }
    /// Evaluates cleanup rules against the user's home folder (read-only).
    public var cleanupScanner: () -> CleanupScanner = { CleanupScanner() }
    /// Where cleanup plans move items to.
    public var quarantine: Quarantine = .default
    /// The volume holding a path, and the number of APFS local snapshots (for `disk_usage`).
    public var volumeUsage: (String) -> VolumeUsage? = { VolumeUsage.live($0) }
    public var localSnapshots: () -> Int? = { DiskUsage.liveLocalSnapshots() }
    /// Asks the user on the Mac (Touch ID or password) to approve a plan this process applies itself (T3 expiry of
    /// the quarantine). Throws unless they approved. Not available on Linux.
    public var approveInProcess: (Plan) throws -> Void = { plan in
        #if os(macOS)
        try PlanApplier.approveInProcess(plan)
        #else
        throw OperationError("approving plans needs macOS and Farrier.app")
        #endif
    }

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
    /// How this Mac is managed (MDM enrollment, profiles, managed preferences).
    public let management: ManagementSummary
    /// How each fact was obtained, or why it's missing (only for the facts the evaluated rules use).
    public let collection: [CollectionNote]
    /// The approved exceptions in effect, and why none could be read if so.
    public let exceptions: [PostureException]
    public let exceptionsProblem: String?
}

public struct ExceptionsOutput: Codable {
    public let exceptions: [PostureException]
    public let problem: String?
    public let path: String
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

public struct QuarantineSummary: Codable {
    public let planID: String
    public let createdAt: Int64
    /// From then on the items may be deleted for good (by an expiry plan, T3); until then they can be restored.
    public let expiresAt: Int64
    public let expired: Bool
    public let quarantined: Int
    public let restored: Int
    /// What the quarantined items take up: freed only once they're deleted.
    public let bytes: Int64
    public let path: String
    public let items: [QuarantineItem]?
}

public struct QuarantineOutput: Codable {
    public let plans: [QuarantineSummary]
    /// Space the quarantine holds now (freed after expiry, not before).
    public let bytes: Int64
}

public struct RestoreOutput: Codable {
    public let planID: String
    public let results: [ItemResult]
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
        let (packs, loadIssues) = RuleLinter.loadPacks(at: ctx.rulePaths, source: ctx.rulePackSource)
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
        let (exceptions, exceptionsProblem) = ctx.exceptions()
        let report = PostureEngine.evaluate(packs, facts: StaticFactStore(collected), exceptions: exceptions)
        var used: Set<String> = [CoreFacts.profilePayloadTypes, CoreFacts.declarationTypes, CoreFacts.managedPreferences,
                                 CoreFacts.profiles, CoreFacts.enrollment]
        for pack in packs { for case .check(let rule) in pack.rules { used.insert(rule.fact) } }
        let findings = ruleIDs.map { ids in report.findings.filter { ids.contains($0.ruleID) } } ?? report.findings
        if let ruleIDs {
            let unknown = ruleIDs.subtracting(report.findings.map(\.ruleID))
            guard unknown.isEmpty else { throw OperationError("no such posture rule: \(unknown.sorted().joined(separator: ", "))") }
        }
        return PostureOutput(findings: findings, summary: PostureReport(findings: findings).summary,
                             management: ManagementSummary(facts: StaticFactStore(collected)),
                             collection: collected.notes.filter { used.contains($0.fact) }.sorted { $0.fact < $1.fact },
                             exceptions: exceptions, exceptionsProblem: exceptionsProblem)
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
        let report = PostureEngine.evaluate(packs, facts: store, exceptions: ctx.exceptions().exceptions)
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

    /// Plans undoing an applied plan (by id or unique prefix), from the helper's journal. Nothing changes until the
    /// undo plan is applied, which asks the user on the Mac like any other T4 plan.
    public static func planUndo(_ ctx: FarrierContext, id: String, journal: Journal = helperJournal,
                                now: Date = Date()) throws -> PlanOutput {
        let records: [JournalRecord]
        do { records = try journal.entries().map(\.record) } catch {
            throw OperationError("can't read the helper's journal: \(error)")
        }
        let applied = Set(records.filter { $0.outcome == "applied" && $0.ruleID != nil }.map(\.planID))
        let matches = applied.filter { $0.hasPrefix(id.lowercased()) }
        if matches.isEmpty, id.count >= 4, let quarantined = try? ctx.quarantine.resolve(id) {
            throw OperationError("plan \(quarantined.prefix(8)) was a cleanup: put its items back with `farrier restore \(quarantined.prefix(8))` "
                                 + "(MCP: quarantine_restore)")
        }
        guard matches.count == 1, let planID = matches.first, !id.isEmpty else {
            throw OperationError(matches.isEmpty ? "no applied plan \(id) in the helper's journal"
                                                 : "\(id) matches more than one applied plan; give more of the id")
        }
        let (plan, skipped): (Plan?, [PlanSkip])
        do {
            (plan, skipped) = try Planner.planUndo(planID: planID, journal: records, facts: StaticFactStore(ctx.collectFacts()),
                                                   host: ctx.host(), now: now)
        } catch let error as PlanError {
            throw OperationError(error.description)
        }
        guard let plan else {
            return PlanOutput(plan: nil, planHash: nil, skipped: skipped, path: nil, next: "nothing to undo automatically")
        }
        let url = try ctx.plans.save(plan)
        let hash = try plan.hash().hexString
        try? ctx.journal.append(JournalRecord(time: plan.createdAt, actor: ctx.actor, planID: plan.id, planHash: hash,
                                              outcome: "planned", detail: "undo of \(planID.prefix(8)): \(plan.items.count) item(s)",
                                              reverts: planID))
        return PlanOutput(plan: plan, planHash: hash, skipped: skipped, path: url.path,
                          next: "review the undo plan with the user; applying it asks them for Touch ID or their password on this Mac")
    }

    /// Read-only: what the cleanup rules match, and how much space it takes. `minAge` (`30d`, `12w`) raises every
    /// rule's minimum age; it never lowers one.
    public static func cleanupScan(_ ctx: FarrierContext, ruleIDs: Set<String>? = nil, minAge: String? = nil) throws -> CleanupReport {
        var age: RuleDuration?
        if let minAge {
            guard let d = RuleDuration(minAge) else { throw OperationError("`minAge` must look like 30d, 12w or 48h, got `\(minAge)`") }
            age = d
        }
        let packs = try packs(ctx)
        if let ruleIDs {
            let known = Set(packs.flatMap { $0.rules.compactMap { r -> String? in if case .cleanup(let c) = r { return c.id }; return nil } })
            let unknown = ruleIDs.subtracting(known)
            guard unknown.isEmpty else {
                throw OperationError("unknown cleanup rule(s): \(unknown.sorted().joined(separator: ", ")); `farrier rules list` shows them")
            }
        }
        return ctx.cleanupScanner().scan(packs, ruleIDs: ruleIDs, minAge: age)
    }

    /// What's on this Mac: apps, launch jobs, extensions, profiles, privacy grants, admins, ports. Read-only.
    public static func inventory(_ ctx: FarrierContext, sections: Set<String>? = nil, flaggedOnly: Bool = false) throws -> InventoryReport {
        if let sections {
            let unknown = sections.subtracting(Inventory.sectionIDs)
            guard unknown.isEmpty else {
                throw OperationError("no such inventory section: \(unknown.sorted().joined(separator: ", ")) "
                                     + "(sections: \(Inventory.sectionIDs.joined(separator: ", ")))")
            }
        }
        let collected = ctx.collectFacts().merging(ctx.collectInventory())
        return Inventory.build(facts: collected.facts, notes: collected.notes, only: sections, flaggedOnly: flaggedOnly)
    }

    public static func exceptions(_ ctx: FarrierContext) -> ExceptionsOutput {
        let (list, problem) = ctx.exceptions()
        return ExceptionsOutput(exceptions: list, problem: problem, path: ExceptionStore.defaultPath)
    }

    /// Plans an exception (add, or remove when `reason` is nil and `remove` is set). Nothing changes until it's
    /// applied, which asks the user on the Mac.
    public static func planException(_ ctx: FarrierContext, ruleID: String, teamID: String, identifier: String?,
                                     reason: String?, remove: Bool, now: Date = Date()) throws -> PlanOutput {
        let existing = ctx.exceptions().exceptions
        let plan: Plan
        do {
            if remove {
                plan = try Planner.planExceptionRemoval(ruleID: ruleID, teamID: teamID, identifier: identifier,
                                                        existing: existing, host: ctx.host(), now: now)
            } else {
                guard let reason else { throw OperationError("an exception needs a reason") }
                plan = try Planner.planException(ruleID: ruleID, teamID: teamID, identifier: identifier, reason: reason,
                                                 facts: StaticFactStore(ctx.collectFacts()), existing: existing,
                                                 host: ctx.host(), now: now)
            }
        } catch let error as PlanError {
            throw OperationError(error.description)
        }
        let url = try ctx.plans.save(plan)
        let hash = try plan.hash().hexString
        try? ctx.journal.append(JournalRecord(time: plan.createdAt, actor: ctx.actor, planID: plan.id, planHash: hash,
                                              ruleID: ruleID, action: plan.items.first?.action, outcome: "planned",
                                              detail: plan.items.first?.description))
        return PlanOutput(plan: plan, planHash: hash, skipped: [], path: url.path,
                          next: "review it with the user; applying it asks them for Touch ID or their password on this Mac")
    }

    public static func show(_ ctx: FarrierContext, id: String, now: Date = Date()) throws -> PlanView {
        let plan = try ctx.plans.load(id)
        let left = plan.expiresAt - Int64(now.timeIntervalSince1970)
        return PlanView(plan: plan, planHash: try plan.hash().hexString, expired: left <= 0,
                        expiresInSeconds: max(0, left), needsApproval: plan.tier.needsApproval)
    }

    /// Applies a saved plan. Blocks until the user answers the prompt on the Mac (or cancels).
    public static func apply(_ ctx: FarrierContext, id: String, now: Date = Date()) throws -> ApplyOutput {
        let plan = try ctx.plans.load(id)
        if plan.tier == .t2 { return applyCleanup(ctx, plan, now: now) }
        if plan.items.allSatisfy({ $0.action == RemediationCatalog.quarantineExpire.id }) {
            return applyExpiry(ctx, plan, now: now)
        }
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

    // MARK: Cleanup plans and the quarantine

    /// Scans and plans moving the candidates (all, or only `paths`) into the quarantine. T2: applying needs no
    /// approval on the Mac, and every item can be restored for 7 days.
    public static func planCleanup(_ ctx: FarrierContext, ruleIDs: Set<String>? = nil, minAge: String? = nil,
                                   paths: Set<String>? = nil, now: Date = Date()) throws -> PlanOutput {
        guard ctx.rulePackSource == .bundled else {
            throw OperationError("cleanup plans only come from Farrier's own rule packs; user packs can scan, not plan")
        }
        let report = try cleanupScan(ctx, ruleIDs: ruleIDs, minAge: minAge)
        let (plan, skipped) = Planner.planCleanup(report: report, paths: paths, host: ctx.host(), now: now)
        guard let plan else {
            return PlanOutput(plan: nil, planHash: nil, skipped: skipped, path: nil, next: "nothing to clean up")
        }
        let url = try ctx.plans.save(plan)
        let hash = try plan.hash().hexString
        let bytes = plan.items.reduce(0) { $0 + Int64($1.observed.object?["bytes"]?.number ?? 0) }
        try? ctx.journal.append(JournalRecord(time: plan.createdAt, actor: ctx.actor, planID: plan.id, planHash: hash,
                                              outcome: "planned", detail: "cleanup: \(plan.items.count) item(s), \(ByteCount.format(bytes))"))
        return PlanOutput(plan: plan, planHash: hash, skipped: skipped, path: url.path,
                          next: "review the plan with the user; applying it moves the items into Farrier's quarantine, "
                              + "where they stay restorable for 7 days (space is freed when the quarantine expires)")
    }

    /// Applies a cleanup (T2) plan in this process: no helper, no approval prompt.
    static func applyCleanup(_ ctx: FarrierContext, _ plan: Plan, now: Date) -> ApplyOutput {
        let hash = (try? plan.hash().hexString) ?? ""
        func journal(_ outcome: String, ruleID: String? = nil, detail: String?) {
            try? ctx.journal.append(JournalRecord(time: Int64(now.timeIntervalSince1970), actor: ctx.actor, planID: plan.id,
                                                  planHash: hash, ruleID: ruleID,
                                                  action: ruleID == nil ? nil : RemediationCatalog.cleanupQuarantine.id,
                                                  outcome: outcome, detail: detail))
        }
        let refusal: String?
        if plan.host != ctx.host() { refusal = "the plan was made on another Mac" }
        else if Int64(now.timeIntervalSince1970) >= plan.expiresAt { refusal = "the plan expired; make a new one" }
        else { refusal = nil }
        if let refusal {
            journal("notApplied", detail: refusal)
            return ApplyOutput(planID: plan.id, results: [], error: refusal)
        }
        do {
            let results = try CleanupApplier.apply(plan, packs: try packs(ctx), scanner: ctx.cleanupScanner(),
                                                   quarantine: ctx.quarantine, now: now)
            let items = results.map { r -> ItemResult in
                let outcome: ItemResult.Outcome = r.outcome == .applied ? .applied : r.outcome == .refused ? .refused : .failed
                return ItemResult(ruleID: r.ruleID, action: RemediationCatalog.cleanupQuarantine.id, outcome: outcome,
                                  detail: "\(r.path): \(r.detail)")
            }
            for r in items { journal(r.outcome.rawValue, ruleID: r.ruleID, detail: r.detail) }
            return ApplyOutput(planID: plan.id, results: items, error: nil)
        } catch {
            journal("notApplied", detail: "\(error)")
            return ApplyOutput(planID: plan.id, results: [], error: "\(error)")
        }
    }

    /// Plans deleting quarantined items for good (T3): every cleanup plan past its 7 days, or the given ones
    /// (ids or prefixes) also before. Nothing is deleted until the plan is applied and the user approves on the Mac.
    public static func planExpiry(_ ctx: FarrierContext, ids: [String]? = nil, now: Date = Date()) throws -> PlanOutput {
        var planIDs: [String]?
        if let ids, !ids.isEmpty {
            do { planIDs = try ids.map { try ctx.quarantine.resolve($0) } } catch let e as PlanError { throw OperationError(e.description) }
        }
        let (plan, skipped) = Planner.planExpiry(quarantine: ctx.quarantine, planIDs: planIDs, host: ctx.host(), now: now)
        guard let plan else {
            let none = planIDs == nil ? "nothing in the quarantine is past its 7 days" : "nothing to delete"
            return PlanOutput(plan: nil, planHash: nil, skipped: skipped, path: nil, next: none)
        }
        let url = try ctx.plans.save(plan)
        let hash = try plan.hash().hexString
        let bytes = plan.items.reduce(0) { $0 + Int64($1.observed.object?["bytes"]?.number ?? 0) }
        try? ctx.journal.append(JournalRecord(time: plan.createdAt, actor: ctx.actor, planID: plan.id, planHash: hash,
                                              outcome: "planned", detail: "expiry: \(plan.items.count) quarantined plan(s), \(ByteCount.format(bytes))"))
        return PlanOutput(plan: plan, planHash: hash, skipped: skipped, path: url.path,
                          next: "review it with the user: this deletes the items for good. Applying it asks them for Touch ID "
                              + "or their password on this Mac")
    }

    /// Applies an expiry (T3) plan in this process, after the user approved it on the Mac.
    static func applyExpiry(_ ctx: FarrierContext, _ plan: Plan, now: Date) -> ApplyOutput {
        let hash = (try? plan.hash().hexString) ?? ""
        func journal(_ outcome: String, ruleID: String? = nil, detail: String?) {
            try? ctx.journal.append(JournalRecord(time: Int64(Date().timeIntervalSince1970), actor: ctx.actor, planID: plan.id,
                                                  planHash: hash, ruleID: ruleID,
                                                  action: ruleID == nil ? nil : RemediationCatalog.quarantineExpire.id,
                                                  outcome: outcome, detail: detail))
        }
        let t = Int64(now.timeIntervalSince1970)
        let refusal: String? = plan.host != ctx.host() ? "the plan was made on another Mac"
            : t >= plan.expiresAt ? "the plan expired; make a new one" : nil
        if let refusal {
            journal("notApplied", detail: refusal)
            return ApplyOutput(planID: plan.id, results: [], error: refusal)
        }
        // Don't ask for an approval that can't lead anywhere (already deleted, restored since, …).
        let problems = CleanupApplier.expiryProblems(plan, quarantine: ctx.quarantine)
        if problems.count == plan.items.count {
            let why = problems.sorted { $0.key < $1.key }.map { "\($0.key.prefix(8)): \($0.value)" }.joined(separator: "; ")
            journal("notApplied", detail: why)
            return ApplyOutput(planID: plan.id, results: [], error: "nothing to delete, so nothing was asked: \(why)")
        }
        do {
            try ctx.approveInProcess(plan)
            journal("approved", detail: "on this Mac")
        } catch {
            journal("notApplied", detail: "\(error)")
            return ApplyOutput(planID: plan.id, results: [], error: "\(error)")
        }
        do {
            let results = try CleanupApplier.expire(plan, quarantine: ctx.quarantine, now: Date())
            let items = results.map { r in
                ItemResult(ruleID: r.ruleID, action: RemediationCatalog.quarantineExpire.id,
                           outcome: r.outcome == .applied ? .applied : r.outcome == .refused ? .refused : .failed,
                           detail: "\(r.path): \(r.detail)")
            }
            for r in items { journal(r.outcome.rawValue, ruleID: r.ruleID, detail: r.detail) }
            return ApplyOutput(planID: plan.id, results: items, error: nil)
        } catch {
            journal("notApplied", detail: "\(error)")
            return ApplyOutput(planID: plan.id, results: [], error: "\(error)")
        }
    }

    /// Read-only: how the disk is used, and what Farrier can free and when.
    public static func diskUsage(_ ctx: FarrierContext, now: Date = Date()) throws -> DiskUsageReport {
        let scan = try cleanupScan(ctx)
        let home = ctx.cleanupScanner().home
        return DiskUsage.report(home: home, scan: scan, quarantine: ctx.quarantine.list(), volume: ctx.volumeUsage(home),
                                localSnapshots: ctx.localSnapshots(), now: now)
    }

    public static func quarantineList(_ ctx: FarrierContext, details: Bool = false, now: Date = Date()) -> QuarantineOutput {
        let t = Int64(now.timeIntervalSince1970)
        // Fully restored plans hold nothing; their manifests stay, as a record, but aren't listed.
        let plans = ctx.quarantine.list().filter { !$0.held.isEmpty }.map { m in
            QuarantineSummary(planID: m.planID, createdAt: m.createdAt, expiresAt: m.expiresAt, expired: t >= m.expiresAt,
                              quarantined: m.held.count,
                              restored: m.items.filter { $0.state == .restored }.count,
                              bytes: m.quarantinedBytes, path: ctx.quarantine.folder(m.planID), items: details ? m.items : nil)
        }
        return QuarantineOutput(plans: plans, bytes: plans.reduce(0) { $0 + $1.bytes })
    }

    /// Puts a cleanup plan's items back (all, or only the given original paths). T2, no approval.
    public static func quarantineRestore(_ ctx: FarrierContext, id: String, paths: Set<String>? = nil,
                                         now: Date = Date()) throws -> RestoreOutput {
        let planID: String
        do { planID = try ctx.quarantine.resolve(id) } catch let e as PlanError { throw OperationError(e.description) }
        let results: [CleanupItemResult]
        do { results = try CleanupApplier.restore(planID: planID, paths: paths, quarantine: ctx.quarantine, now: now) }
        catch { throw OperationError("can't restore plan \(planID.prefix(8)): \(error)") }
        let items = results.map { r -> ItemResult in
            ItemResult(ruleID: r.ruleID, action: "cleanup.restore",
                       outcome: r.outcome == .applied ? .applied : r.outcome == .refused ? .refused : .failed,
                       detail: "\(r.path): \(r.detail)")
        }
        for r in items {
            try? ctx.journal.append(JournalRecord(time: Int64(now.timeIntervalSince1970), actor: ctx.actor, planID: planID,
                                                  planHash: "", ruleID: r.ruleID, action: r.action,
                                                  outcome: r.outcome == .applied ? "restored" : r.outcome.rawValue,
                                                  detail: r.detail, reverts: planID))
        }
        return RestoreOutput(planID: planID, results: items)
    }

    public static func journal(_ which: Journal, name: String, last: Int) -> JournalOutput {
        let issues = which.verify()
        let entries = ((try? which.entries()) ?? []).suffix(max(0, min(last, 500))).map(\.record)
        return JournalOutput(journal: name, path: which.url.path, intact: issues.isEmpty, issues: issues, entries: Array(entries))
    }
}
