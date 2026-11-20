import ArgumentParser
import FarrierCore
import FarrierHelperKit
import Foundation

/// The user journal (docs/ARCHITECTURE.md, "Journal"). The helper keeps its own, root-owned one.
let userJournal = Journal(url: FileManager.default.homeDirectoryForCurrentUser
    .appendingPathComponent("Library/Application Support/Farrier/journal.jsonl"))

func note(_ message: String) {
    FileHandle.standardError.write(Data("\(message)\n".utf8))
}

// MARK: - farrier setup

struct Setup: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Set up the approval key that plans changing system settings need (macOS, from Farrier.app).",
        discussion: """
        Creates a Secure Enclave key whose use needs Touch ID or your login password, stores it in your login \
        keychain so that only Farrier can use it, and enrolls its public key with the privileged helper. Enrolling \
        shows an admin dialog. Run it again at any time: it checks the key and re-enrolls or rotates only if needed.
        """
    )

    @Flag(help: "Replace the key with a new one, even if the current one is intact.")
    var rotate = false

    func run() throws {
        try Helper.macOnly()
        #if os(macOS)
        do {
            let report = try ApprovalSetup.run(rotate: rotate)
            for step in report.steps { print("- \(step)") }
            print("approval key ready: \(report.fingerprint.map { String($0.prefix(16)) + "…" } ?? "?")")
        } catch {
            note("setup failed: \(error)")
            throw ExitCode(1)
        }
        #endif
    }
}

// MARK: - farrier plan

struct PlanCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "plan",
        abstract: "Make and inspect plans. Nothing changes until `farrier apply`.",
        subcommands: [PlanPosture.self, PlanShow.self, PlanList.self]
    )
}

struct PlanPosture: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "posture",
        abstract: "Plan fixes for failing posture checks.",
        discussion: "Only failing checks with an automatic fix are planned. Settings MDM manages, or that can't be checked for MDM management, are left out with the reason."
    )

    @Option(name: .customLong("rule"), help: "Only these rule ids (repeatable). Default: every fixable failure.")
    var ruleIDs: [String] = []

    @Option(name: .customLong("rules"), help: "Rule pack files or directories. Default: the packs bundled with Farrier.app, or ./rules.")
    var rulePaths: [String] = []

    @Option(help: "JSON file with facts to use instead of collecting (for testing; such a plan only applies if the facts match this Mac).")
    var facts: String?

    @Flag(help: "Output JSON.")
    var json = false

    func run() throws {
        let (packs, loadIssues) = RuleLinter.loadPacks(at: rulePaths.isEmpty ? defaultRulePaths() : rulePaths, source: .bundled)
        let errors = (loadIssues + RuleLinter.lint(packs)).filter { $0.level == .error }
        guard errors.isEmpty else {
            for e in errors { note("\(e)") }
            throw ExitCode(2)
        }
        let store: StaticFactStore
        if let facts {
            store = try StaticFactStore(json: Data(contentsOf: URL(fileURLWithPath: facts)))
        } else {
            store = StaticFactStore(collectAllFacts().facts)
        }
        let report = PostureEngine.evaluate(packs, facts: store)
        let host = HostIdentity.hardwareUUID() ?? "unknown-host"
        let (plan, skipped) = Planner.plan(report: report, packs: packs, facts: store,
                                           ruleIDs: ruleIDs.isEmpty ? nil : Set(ruleIDs), host: host)
        var saved: URL?
        if let plan {
            saved = try PlanStore.default.save(plan)
            try? userJournal.append(JournalRecord(time: plan.createdAt, actor: "cli", planID: plan.id,
                                                  planHash: (try plan.hash()).hexString, outcome: "planned",
                                                  detail: "\(plan.items.count) item(s), \(plan.tier.rawValue)"))
        }
        if json {
            struct Out: Encodable { let plan: Plan?; let planHash: String?; let skipped: [PlanSkip]; let path: String? }
            try Output.json(Out(plan: plan, planHash: try plan?.hash().hexString, skipped: skipped, path: saved?.path))
            return
        }
        if let plan { printPlan(plan) } else { print("nothing to fix automatically") }
        if !skipped.isEmpty {
            print("left out:")
            for s in skipped { print("  \(s.ruleID): \(s.reason)") }
        }
        if let plan { print("\nreview it, then run: farrier apply \(plan.id.prefix(8))") }
    }
}

func printPlan(_ plan: Plan) {
    let expires = Date(timeIntervalSince1970: TimeInterval(plan.expiresAt))
    let left = max(0, Int(expires.timeIntervalSinceNow / 60))
    print("plan \(plan.id)  (\(plan.tier.rawValue), hash \(plan.shortHash()), expires in \(left) min)")
    for item in plan.items {
        print("  [\(item.tier.rawValue)] \(item.summary)")
        print("        rule \(item.ruleID): \(item.fact) is \(item.observed)  → action \(item.action)")
    }
    if plan.tier.needsApproval { print("applying it asks for Touch ID or your password on this Mac") }
}

struct PlanShow: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "show", abstract: "Show a plan.")

    @Argument(help: "Plan id or a unique prefix.")
    var id: String

    @Flag(help: "Output JSON.")
    var json = false

    func run() throws {
        let plan = try PlanStore.default.load(id)
        if json { try Output.json(plan) } else { printPlan(plan) }
    }
}

struct PlanList: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "list", abstract: "List saved plans.")

    func run() throws {
        let store = PlanStore.default
        for id in store.ids() {
            guard let plan = try? store.load(id) else { print("\(id)  (unreadable)"); continue }
            let expired = Int64(Date().timeIntervalSince1970) >= plan.expiresAt
            print("\(id)  \(plan.tier.rawValue)  \(plan.items.count) item(s)\(expired ? "  expired" : "")")
        }
    }
}

// MARK: - farrier apply

struct Apply: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Apply a plan (macOS, from Farrier.app). T3/T4 plans ask for Touch ID or your password.",
        discussion: "The helper re-checks everything itself: the approval signature, the plan hash, this Mac, MDM ownership and the current state of each setting."
    )

    @Argument(help: "Plan id or a unique prefix.")
    var id: String

    func run() throws {
        let plan = try PlanStore.default.load(id)
        printPlan(plan)
        try Helper.macOnly()
        #if os(macOS)
        let hash = (try plan.hash()).hexString
        do {
            let reply = try PlanApplier.apply(plan)
            var failed = false
            for r in reply.results {
                print("\(r.outcome.rawValue.padding(toLength: 16, withPad: " ", startingAt: 0)) \(r.ruleID): \(r.detail ?? "")")
                try? userJournal.append(JournalRecord(time: Int64(Date().timeIntervalSince1970), actor: "cli", planID: plan.id,
                                                      planHash: hash, ruleID: r.ruleID, action: r.action,
                                                      outcome: r.outcome.rawValue, detail: r.detail))
                if r.outcome == .failed || r.outcome == .refused { failed = true }
            }
            if failed { throw ExitCode(1) }
        } catch let error as ExitCode {
            throw error
        } catch {
            try? userJournal.append(JournalRecord(time: Int64(Date().timeIntervalSince1970), actor: "cli", planID: plan.id,
                                                  planHash: hash, outcome: "notApplied", detail: "\(error)"))
            note("not applied: \(error)")
            throw ExitCode(1)
        }
        #endif
    }
}

// MARK: - farrier journal

struct JournalCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "journal",
        abstract: "Inspect the journals of planned and applied changes.",
        subcommands: [JournalVerify.self, JournalShow.self]
    )

    static var journals: [(String, Journal)] {
        [("user", userJournal), ("helper", Journal(url: URL(fileURLWithPath: HelperConstants.helperJournalPath)))]
    }
}

struct JournalVerify: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "verify", abstract: "Check both journals' hash chains.")

    func run() throws {
        var bad = false
        for (name, journal) in JournalCommand.journals {
            let issues = journal.verify()
            let count = (try? journal.entries().count) ?? 0
            print("\(name) journal (\(journal.url.path)): \(issues.isEmpty ? "intact, \(count) entries" : "\(issues.count) problem(s)")")
            for i in issues { print("  \(i)") }
            bad = bad || !issues.isEmpty
        }
        if bad { throw ExitCode(1) }
    }
}

struct JournalShow: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "show", abstract: "Show the latest journal entries.")

    @Flag(help: "Show the helper's journal instead of yours.")
    var helper = false

    @Option(help: "How many entries.")
    var last = 20

    func run() throws {
        let journal = helper ? JournalCommand.journals[1].1 : JournalCommand.journals[0].1
        let formatter = ISO8601DateFormatter()
        for e in try journal.entries().suffix(max(0, last)) {
            let r = e.record
            let when = formatter.string(from: Date(timeIntervalSince1970: TimeInterval(r.time)))
            var line = "\(when)  \(r.actor)  \(r.planID.prefix(8))  \(r.outcome)"
            if let rule = r.ruleID { line += "  \(rule)" }
            if let d = r.detail { line += "  — \(d)" }
            print(line)
        }
    }
}
