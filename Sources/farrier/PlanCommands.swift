import ArgumentParser
import FarrierCore
import FarrierHelperKit
import FarrierMCP
import Foundation


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

    @Option(name: .customLong("rules"), help: "Rule packs to use instead, loaded as user packs (which can't plan fixes). Default: the packs bundled with Farrier.app, or ./rules.")
    var rulePaths: [String] = []

    @Option(help: "JSON file with facts to use instead of collecting (for testing; such a plan only applies if the facts match this Mac).")
    var facts: String?

    @Flag(help: "Output JSON.")
    var json = false

    func run() throws {
        // Packs given on the command line are user packs: they can't declare automatic fixes, and the planner
        // never plans from them. Only the packs that ship with Farrier (or ./rules in a checkout) can.
        let out: PlanOutput
        do {
            let ctx = try cliContext(rulePaths: rulePaths, factsFile: facts, explicitRulesAreUserPacks: true)
            out = try Operations.planPosture(ctx, ruleIDs: ruleIDs.isEmpty ? nil : Set(ruleIDs))
        } catch let error as OperationError {
            note("\(error)")
            throw ExitCode(2)
        }
        if json {
            try Output.json(out)
            return
        }
        if let plan = out.plan { printPlan(plan) } else { print("nothing to fix automatically") }
        if !out.skipped.isEmpty {
            print("left out:")
            for s in out.skipped { print("  \(s.ruleID): \(s.reason)") }
        }
        if let plan = out.plan { print("\nreview it, then run: farrier apply \(plan.id.prefix(8))") }
    }
}

func printPlan(_ plan: Plan) {
    let expires = Date(timeIntervalSince1970: TimeInterval(plan.expiresAt))
    let left = max(0, Int(expires.timeIntervalSinceNow / 60))
    print("plan \(plan.id)  (\(plan.tier.rawValue), hash \(plan.shortHash()), expires in \(left) min)")
    for item in plan.items {
        print("  [\(item.tier.rawValue)] \(item.description)")
        if item.parameters == nil {
            print("        rule \(item.ruleID): \(item.fact) is \(item.observed)  → action \(item.action)")
        } else {
            let label = item.action == RemediationCatalog.exceptionRemove.id ? "reason it was accepted" : "covers"
            print("        \(label): \(item.observed)  → action \(item.action)")
        }
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
        if json {
            try Output.json(try Operations.show(FarrierContext.live(actor: "cli"), id: id))
        } else {
            printPlan(try PlanStore.default.load(id))
        }
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
        // The same operation as the MCP tool `apply_plan`, journal entries included.
        let out = try Operations.apply(FarrierContext.live(actor: "cli"), id: plan.id)
        for r in out.results {
            print("\(r.outcome.rawValue.padding(toLength: 16, withPad: " ", startingAt: 0)) \(r.ruleID): \(r.detail ?? "")")
        }
        if let error = out.error {
            note(out.results.isEmpty ? "not applied: \(error)" : "stopped: \(error)")
            throw ExitCode(1)
        }
        if out.results.contains(where: { $0.outcome == .failed || $0.outcome == .refused }) { throw ExitCode(1) }
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
        [("user", userJournal), ("helper", helperJournal)]
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

// MARK: - farrier exceptions

struct ExceptionsCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "exceptions",
        abstract: "Accept a vendor's signed items for a rule (for example unnotarized but Developer ID–signed launch items).",
        discussion: """
        Exceptions are stored by the privileged helper in a root-owned file. Adding or removing one makes a plan; \
        `farrier apply` then asks for Touch ID or your password, like any change to system settings.
        """,
        subcommands: [ExceptionsList.self, ExceptionsAdd.self, ExceptionsRemove.self]
    )
}

struct ExceptionsList: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "list", abstract: "List the approved exceptions.")

    @Flag(help: "Output JSON.")
    var json = false

    func run() throws {
        let out = Operations.exceptions(FarrierContext.live(actor: "cli"))
        if json { return try Output.json(out) }
        if let problem = out.problem { note(problem) }
        if out.exceptions.isEmpty { print("no exceptions") }
        let formatter = ISO8601DateFormatter()
        for e in out.exceptions {
            let when = formatter.string(from: Date(timeIntervalSince1970: TimeInterval(e.acceptedAt)))
            print("\(e.ruleID)  team \(e.teamID)\(e.identifier.map { " (\($0))" } ?? "")  — \(e.reason)  [\(when), plan \(e.planID.prefix(8))]")
        }
    }
}

struct ExceptionsAdd: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "add", abstract: "Plan an exception for a vendor's signed items.")

    @Option(help: "The posture rule.") var rule = "posture.core.unsigned-launch-items"
    @Option(help: "The vendor's Apple Team ID (TeamIdentifier, as in `farrier facts`).") var team: String
    @Option(help: "Only this signing identifier of the team.") var identifier: String?
    @Option(help: "Why it's acceptable (shown in the approval prompt and kept with the exception).") var reason: String

    func run() throws {
        try planAndPrint { ctx in
            try Operations.planException(ctx, ruleID: rule, teamID: team, identifier: identifier, reason: reason, remove: false)
        }
    }
}

struct ExceptionsRemove: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "remove", abstract: "Plan removing an exception.")

    @Option(help: "The posture rule.") var rule = "posture.core.unsigned-launch-items"
    @Option(help: "The vendor's Apple Team ID.") var team: String
    @Option(help: "The signing identifier, if the exception has one.") var identifier: String?

    func run() throws {
        try planAndPrint { ctx in
            try Operations.planException(ctx, ruleID: rule, teamID: team, identifier: identifier, reason: nil, remove: true)
        }
    }
}

func planAndPrint(_ make: (FarrierContext) throws -> PlanOutput) throws {
    let out: PlanOutput
    do {
        out = try make(FarrierContext.live(actor: "cli"))
    } catch let error as OperationError {
        note("\(error)")
        throw ExitCode(2)
    }
    guard let plan = out.plan else { return print(out.next) }
    printPlan(plan)
    print("\nreview it, then run: farrier apply \(plan.id.prefix(8))")
}
