import ArgumentParser
import FarrierCore
import FarrierHelperKit
import FarrierMCP
import Foundation


func note(_ message: String) {
    FileHandle.standardError.write(Data("\(activeRedactor?.redact(message) ?? message)\n".utf8))
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

    @Flag(help: "Output JSON.")
    var json = false

    func run() throws {
        try Helper.macOnly()
        #if os(macOS)
        do {
            let report = try ApprovalSetup.run(rotate: rotate)
            if json {
                try Output.json(report)
                return
            }
            for step in report.steps { print("- \(step)") }
            var ready = "approval key ready: \(report.fingerprint.map { String($0.prefix(16)) + "…" } ?? "?")"
            if let enrolledAt = report.enrolledAt {
                let next = Date(timeIntervalSince1970: TimeInterval(enrolledAt + Int64(ApprovalKeyPolicy.maxAgeDays) * 86_400))
                let f = DateFormatter()
                f.dateStyle = .medium
                f.timeStyle = .none
                ready += " (replaced every \(ApprovalKeyPolicy.maxAgeDays) days: run `farrier setup` again before \(f.string(from: next)))"
            }
            print(ready)
            // Not part of the key, but the last step of onboarding: say if it's missing, and how to fix it.
            if case .success(false)? = try? HelperClient.fullDiskAccess() {
                print("next: give Farrier.app Full Disk Access, for the checks that read privacy-protected data: `farrier helper full-disk-access`")
            }
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
        subcommands: [PlanPosture.self, PlanCleanup.self, PlanExpire.self, PlanShow.self, PlanList.self]
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

struct PlanCleanup: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "cleanup",
        abstract: "Plan moving what `farrier cleanup scan` lists into Farrier's quarantine.",
        discussion: """
        Applying the plan moves the items into ~/Library/Application Support/Farrier/Quarantine (on the same volume, \
        never copied); `farrier restore` puts them back for 7 days. The space is freed when the quarantine expires.
        """
    )

    @Option(name: .customLong("rule"), help: "Only this cleanup rule (repeatable).")
    var rules: [String] = []

    @Option(help: "Only items unused for at least this long (60d, 12w). Raises each rule's own minimum.")
    var minAge: String?

    @Option(name: .customLong("path"), help: "Only this candidate path (repeatable), as the scan lists it.")
    var paths: [String] = []

    @Flag(help: "Output JSON.")
    var json = false

    @OptionGroup var redaction: RedactOption

    func run() throws {
        redaction.apply()
        let out: PlanOutput
        do {
            let home = FileManager.default.homeDirectoryForCurrentUser.path
            let full = paths.map { $0.hasPrefix("~/") ? home + $0.dropFirst(1) : $0 }
            out = try Operations.planCleanup(FarrierContext.live(actor: "cli"), ruleIDs: rules.isEmpty ? nil : Set(rules),
                                             minAge: minAge, paths: full.isEmpty ? nil : Set(full))
        } catch let error as OperationError {
            note("\(error)")
            throw ExitCode(2)
        }
        if json {
            try Output.json(out)
            return
        }
        if let plan = out.plan { printPlan(plan) } else { print("nothing to clean up") }
        if !out.skipped.isEmpty {
            print("left out:")
            for s in out.skipped { print("  \(s.ruleID): \(s.reason)") }
        }
        if let plan = out.plan { print("\nreview it, then run: farrier apply \(plan.id.prefix(8))") }
    }
}

struct PlanExpire: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "expire",
        abstract: "Plan deleting quarantined items for good, to free their space.",
        discussion: """
        By default, every cleanup plan whose 7 days are over; with --plan, the plans you name, also before then. \
        It can't be undone, so applying it asks for Touch ID or your password (T3).
        """
    )

    @Option(name: .customLong("plan"), help: "Only this cleanup plan's quarantine (id or prefix, repeatable; see `farrier quarantine list`).")
    var plans: [String] = []

    @Flag(help: "Output JSON.")
    var json = false

    @OptionGroup var redaction: RedactOption

    func run() throws {
        redaction.apply()
        let out: PlanOutput
        do {
            out = try Operations.planExpiry(FarrierContext.live(actor: "cli"), ids: plans.isEmpty ? nil : plans)
        } catch let error as OperationError {
            note("\(error)")
            throw ExitCode(2)
        }
        if json {
            try Output.json(out)
            return
        }
        if let plan = out.plan { printPlan(plan) } else { print(out.next) }
        if !out.skipped.isEmpty {
            print("left out:")
            for s in out.skipped { print("  \(s.reason)") }
        }
        if let plan = out.plan { print("\nreview it, then run: farrier apply \(plan.id.prefix(8))") }
    }
}

struct Undo: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Plan undoing what an applied plan changed. Nothing changes until `farrier apply`.",
        discussion: """
        Reads the privileged helper's journal, which records the state each change replaced, and plans restoring it \
        (the firewall, stealth mode, automatic security updates). The helper only undoes changes its journal shows \
        that plan made, and only if the setting is still as Farrier left it. Applying the undo plan asks for Touch \
        ID or your password, like any change to system settings.
        """
    )

    @Argument(help: "The applied plan's id, or a unique prefix (see `farrier journal show --helper`).")
    var planID: String

    @Flag(help: "Output JSON.")
    var json = false

    func run() throws {
        let out: PlanOutput
        do {
            out = try Operations.planUndo(FarrierContext.live(actor: "cli"), id: planID)
        } catch let error as OperationError {
            note("\(error)")
            throw ExitCode(2)
        }
        if json {
            try Output.json(out)
            return
        }
        if let plan = out.plan { printPlan(plan) } else { print("nothing to undo automatically") }
        if !out.skipped.isEmpty {
            print("left out:")
            for s in out.skipped { print("  \(s.ruleID): \(s.reason)") }
        }
        if let plan = out.plan { print("\nreview it, then run: farrier apply \(plan.id.prefix(8))") }
    }
}

/// `~/…` for paths in the user's home folder.
func shortPath(_ path: String) -> String {
    let home = FileManager.default.homeDirectoryForCurrentUser.path
    return path.hasPrefix(home + "/") ? "~" + path.dropFirst(home.count) : path
}

func printPlan(_ plan: Plan) {
    let expires = Date(timeIntervalSince1970: TimeInterval(plan.expiresAt))
    let left = max(0, Int(expires.timeIntervalSinceNow / 60))
    print("plan \(plan.id)  (\(plan.tier.rawValue), hash \(plan.shortHash()), expires in \(left) min)")
    if plan.items.allSatisfy({ $0.action == RemediationCatalog.cleanupQuarantine.id }) {
        var total: Int64 = 0
        for item in plan.items {
            let o = item.observed.object ?? [:]
            let bytes = Int64(o["bytes"]?.number ?? 0)
            total += bytes
            let path = (try? CleanupItemRules.validate(item.parameters).path).map(shortPath) ?? "?"
            let regen = o["regenerable"] == .bool(true) ? "regenerable" : "not regenerable"
            print("  [T2] \(ByteCount.format(bytes).padding(toLength: 9, withPad: " ", startingAt: 0)) \(Int(o["ageDays"]?.number ?? 0))d  \(path)")
            print("        rule \(item.ruleID), \(regen)")
        }
        print("moves \(plan.items.count) item(s), \(ByteCount.format(total)), into Farrier's quarantine; "
              + "`farrier restore` puts them back for \(Quarantine.retention / 86_400) days")
        return
    }
    if plan.items.allSatisfy({ $0.action == RemediationCatalog.quarantineExpire.id }) {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .none
        var total: Int64 = 0
        for item in plan.items {
            let o = item.observed.object ?? [:]
            let bytes = Int64(o["bytes"]?.number ?? 0)
            total += bytes
            let due = Date(timeIntervalSince1970: TimeInterval(o["expiresAt"]?.number ?? 0))
            let when = o["due"] == .bool(true) ? "kept until \(f.string(from: due))" : "early: would be kept until \(f.string(from: due))"
            print("  [T3] \(item.description)")
            print("        \(Int(o["items"]?.number ?? 0)) item(s), \(ByteCount.format(bytes)); \(when)")
        }
        print("deletes \(ByteCount.format(total)) for good: it can't be undone")
        print("applying it asks for Touch ID or your password on this Mac")
        return
    }
    for item in plan.items {
        print("  [\(item.tier.rawValue)] \(item.description)")
        if item.parameters == nil || RemediationCatalog.action(item.action)?.reverses != nil {
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

    @OptionGroup var redaction: RedactOption

    func run() throws {
        redaction.apply()
        if json {
            try Output.json(try Operations.show(FarrierContext.live(actor: "cli"), id: id))
        } else {
            printPlan(try PlanStore.default.load(id))
        }
    }
}

struct PlanList: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "list", abstract: "List saved plans.")

    @Flag(help: "Output JSON.")
    var json = false

    @OptionGroup var redaction: RedactOption

    struct Row: Encodable { let id: String; let tier: String?; let items: Int?; let expiresAt: Int64?; let expired: Bool?; let error: String? }

    func run() throws {
        redaction.apply()
        let store = PlanStore.default
        if json {
            let now = Int64(Date().timeIntervalSince1970)
            try Output.json(store.ids().map { id -> Row in
                guard let plan = try? store.load(exactID: id) else {
                    return Row(id: id, tier: nil, items: nil, expiresAt: nil, expired: nil, error: "unreadable")
                }
                return Row(id: id, tier: plan.tier.rawValue, items: plan.items.count, expiresAt: plan.expiresAt,
                           expired: now >= plan.expiresAt, error: nil)
            })
            return
        }
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

    @Flag(help: "Output JSON (the per-item results).")
    var json = false

    @Flag(name: .shortAndLong, help: "Cleanup plans (T2): don't ask before moving the items into the quarantine.")
    var yes = false

    func run() throws {
        let plan = try PlanStore.default.load(id)
        if !json { printPlan(plan) }
        if plan.tier == .t2 && !yes {
            // T2 isn't approved on the Mac: it's confirmed here (docs/ARCHITECTURE.md, tiers).
            guard isatty(0) != 0 else {
                note("not applied: confirm with --yes (no terminal to ask in)")
                throw ExitCode(1)
            }
            FileHandle.standardError.write(Data("move these items into the quarantine? [y/N] ".utf8))
            guard let answer = readLine(), ["y", "yes"].contains(answer.lowercased()) else {
                note("not applied")
                throw ExitCode(1)
            }
        }
        if plan.tier.needsApproval { try Helper.macOnly() }
        // The same operation as the MCP tool `apply_plan`, journal entries included.
        let out = try Operations.apply(FarrierContext.live(actor: "cli"), id: plan.id)
        if json {
            try Output.json(out)
            if out.error != nil || out.results.contains(where: { $0.outcome == .failed || $0.outcome == .refused }) { throw ExitCode(1) }
            return
        }
        for r in out.results {
            print("\(r.outcome.rawValue.padding(toLength: 16, withPad: " ", startingAt: 0)) \(r.ruleID): \(r.detail.map(shortPathsIn) ?? "")")
        }
        if plan.tier == .t2 {
            let moved = out.results.filter { $0.outcome == .applied }.count
            if moved > 0 { print("\nmoved \(moved) item(s); put them back with: farrier restore \(plan.id.prefix(8))") }
            if out.error == nil && moved > 0 { return }   // items in use again are refused, not a failed cleanup
        }
        if let error = out.error {
            note(out.results.isEmpty ? "not applied: \(error)" : "stopped: \(error)")
            throw ExitCode(1)
        }
        if out.results.contains(where: { $0.outcome == .failed || $0.outcome == .refused }) { throw ExitCode(1) }
        #if os(macOS)
        // After a successful apply, say if the approval key is due for its periodic rotation.
        if let key = try? HelperClient.approvalKeyStatus(),
           let notice = ApprovalKeyPolicy.notice(enrolledAt: key.enrolledAt, now: Int64(Date().timeIntervalSince1970)) {
            note(notice)
        }
        #endif
    }
}

func shortPathsIn(_ text: String) -> String {
    let home = FileManager.default.homeDirectoryForCurrentUser.path
    return text.replacingOccurrences(of: home + "/", with: "~/")
}

// MARK: - farrier restore and farrier quarantine

struct Restore: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Put a cleanup plan's items back from the quarantine.",
        discussion: "Items whose original path is taken again stay in the quarantine; move what's there away, then run it again."
    )

    @Argument(help: "The cleanup plan's id, or a unique prefix (see `farrier quarantine list`).")
    var planID: String

    @Option(name: .customLong("path"), help: "Only this original path (repeatable).")
    var paths: [String] = []

    @Flag(help: "Output JSON.")
    var json = false

    @OptionGroup var redaction: RedactOption

    func run() throws {
        redaction.apply()
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let full = paths.map { $0.hasPrefix("~/") ? home + $0.dropFirst(1) : $0 }
        let out: RestoreOutput
        do {
            out = try Operations.quarantineRestore(FarrierContext.live(actor: "cli"), id: planID, paths: full.isEmpty ? nil : Set(full))
        } catch let error as OperationError {
            note("\(error)")
            throw ExitCode(2)
        }
        if json {
            try Output.json(out)
        } else {
            for r in out.results {
                print("\(r.outcome.rawValue.padding(toLength: 10, withPad: " ", startingAt: 0)) \(r.detail.map(shortPathsIn) ?? "")")
            }
        }
        if !out.results.contains(where: { $0.outcome == .applied }) { throw ExitCode(1) }
    }
}

struct QuarantineCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "quarantine",
        abstract: "Inspect Farrier's quarantine.",
        subcommands: [List.self, AutoExpire.self, ExpireDue.self]
    )

    static func describe(_ s: AutoExpiryStatus) -> String {
        guard s.enabled else {
            return "automatic deletion: off (`farrier quarantine auto-expire on` deletes items once their 7 days are over)"
        }
        if let problem = s.problem { return "automatic deletion: on, but not running: \(problem)" }
        let schedule = s.scheduled ? "daily" : "approved, but the daily schedule isn't installed: turn it on again"
        return "automatic deletion: on (\(schedule)), once items' 7 days are over"
    }

    struct AutoExpire: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "auto-expire",
            abstract: "Delete quarantined items automatically once their 7 days are over.",
            discussion: """
            `on` asks for Touch ID or your password once: deleting for good is T3, and this approves it in advance for \
            items past their 7 days only. A daily background job then deletes them. The approval is tied to the \
            approval key, so after the key's monthly rotation the job stops until you turn it on again. `off` needs \
            no approval.
            """
        )

        @Argument(help: "on, off or status.")
        var state: String = "status"

        @Flag(help: "Output JSON.")
        var json = false

        func run() throws {
            let ctx = FarrierContext.live(actor: "cli")
            let status: AutoExpiryStatus
            do {
                switch state {
                case "on":
                    try Helper.macOnly()
                    let bundle = Bundle.main.bundlePath
                    guard bundle.hasSuffix(".app"), let exe = Bundle.main.executablePath else {
                        note("turn it on with the installed farrier (from Farrier.app), not a development build")
                        throw ExitCode(2)
                    }
                    status = try Operations.enableAutoExpiry(ctx, executable: exe)
                case "off": status = try Operations.disableAutoExpiry(ctx)
                case "status": status = Operations.autoExpiryStatus(ctx)
                default:
                    note("expected on, off or status")
                    throw ExitCode(2)
                }
            } catch let error as OperationError {
                note("\(error)")
                throw ExitCode(1)
            }
            if json { try Output.json(status) } else { print(QuarantineCommand.describe(status)) }
        }
    }

    struct ExpireDue: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "expire-due",
            abstract: "Delete quarantined items past their 7 days, under the approval `auto-expire on` saved (what the daily job runs)."
        )

        @Flag(help: "Output JSON.")
        var json = false

        func run() throws {
            let out = Operations.runDueExpiry(FarrierContext.live(actor: "schedule"))
            if json {
                try Output.json(out)
            } else {
                let stamp = ISO8601DateFormatter().string(from: Date())
                if out.results.isEmpty && out.error == nil { print("\(stamp) nothing past its 7 days") }
                for r in out.results { print("\(stamp) \(r.outcome.rawValue) \(r.detail.map(shortPathsIn) ?? "")") }
                if let e = out.error { print("\(stamp) not run: \(e)") }
            }
            if out.error != nil || out.results.contains(where: { $0.outcome != .applied }) { throw ExitCode(1) }
        }
    }

    struct List: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "List quarantined cleanup plans and what they hold.")

        @Flag(help: "List every item.")
        var items = false

        @Flag(help: "Output JSON.")
        var json = false

        @OptionGroup var redaction: RedactOption

        func run() throws {
            redaction.apply()
            let out = Operations.quarantineList(FarrierContext.live(actor: "cli"), details: items || json)
            if json {
                try Output.json(out)
                return
            }
            guard !out.plans.isEmpty else {
                print("the quarantine is empty")
                print(QuarantineCommand.describe(out.autoExpiry))
                return
            }
            let f = DateFormatter()
            f.dateStyle = .medium
            f.timeStyle = .short
            for p in out.plans {
                let when = f.string(from: Date(timeIntervalSince1970: TimeInterval(p.expiresAt)))
                let expiry = p.expired ? "its 7 days ended \(when): restorable until it's deleted" : "kept until \(when)"
                let restored = p.restored > 0 ? ", \(p.restored) restored" : ""
                print("\(p.planID.prefix(8))  \(ByteCount.format(p.bytes).padding(toLength: 9, withPad: " ", startingAt: 0)) \(p.quarantined) item(s)\(restored), \(expiry)")
                for item in p.items ?? [] where items {
                    print("    \(item.state == .restored ? "restored" : "        ")  \(shortPath(item.original))")
                }
            }
            print("\n\(ByteCount.format(out.bytes)) held in the quarantine; it's freed when the items are deleted")
            if out.plans.contains(where: \.expired) && out.autoExpiry.active != true {
                print("past their 7 days: `farrier plan expire` plans deleting them (Touch ID or your password)")
            }
            print(QuarantineCommand.describe(out.autoExpiry))
        }
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

    @Flag(help: "Output JSON.")
    var json = false

    struct Row: Encodable { let journal: String; let path: String; let intact: Bool; let entries: Int; let issues: [String] }

    func run() throws {
        if json {
            let rows = JournalCommand.journals.map { name, journal -> Row in
                let issues = journal.verify()
                return Row(journal: name, path: journal.url.path, intact: issues.isEmpty,
                           entries: (try? journal.entries().count) ?? 0, issues: issues)
            }
            try Output.json(rows)
            if rows.contains(where: { !$0.intact }) { throw ExitCode(1) }
            return
        }
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

    @Flag(help: "Output JSON (the entries and whether the chain is intact).")
    var json = false

    @OptionGroup var redaction: RedactOption

    func run() throws {
        redaction.apply()
        let journal = helper ? JournalCommand.journals[1].1 : JournalCommand.journals[0].1
        if json {
            try Output.json(Operations.journal(journal, name: helper ? "helper" : "user", last: last))
            return
        }
        let formatter = ISO8601DateFormatter()
        for e in try journal.entries().suffix(max(0, last)) {
            let r = e.record
            let when = formatter.string(from: Date(timeIntervalSince1970: TimeInterval(r.time)))
            var line = "\(when)  \(r.actor)  \(r.planID.prefix(8))  \(r.outcome)"
            if let rule = r.ruleID { line += "  \(rule)" }
            if let d = r.detail { line += "  — \(d)" }
            if let p = r.previous { line += "  (was \(p); `farrier undo \(r.planID.prefix(8))` restores it)" }
            if let reverted = r.reverts { line += "  (undoes \(reverted.prefix(8)))" }
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

    @OptionGroup var redaction: RedactOption

    func run() throws {
        redaction.apply()
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
    @Flag(help: "Output JSON.") var json = false

    func run() throws {
        try planAndPrint(json: json) { ctx in
            try Operations.planException(ctx, ruleID: rule, teamID: team, identifier: identifier, reason: reason, remove: false)
        }
    }
}

struct ExceptionsRemove: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "remove", abstract: "Plan removing an exception.")

    @Option(help: "The posture rule.") var rule = "posture.core.unsigned-launch-items"
    @Option(help: "The vendor's Apple Team ID.") var team: String
    @Option(help: "The signing identifier, if the exception has one.") var identifier: String?
    @Flag(help: "Output JSON.") var json = false

    func run() throws {
        try planAndPrint(json: json) { ctx in
            try Operations.planException(ctx, ruleID: rule, teamID: team, identifier: identifier, reason: nil, remove: true)
        }
    }
}

func planAndPrint(json: Bool = false, _ make: (FarrierContext) throws -> PlanOutput) throws {
    let out: PlanOutput
    do {
        out = try make(FarrierContext.live(actor: "cli"))
    } catch let error as OperationError {
        note("\(error)")
        throw ExitCode(2)
    }
    if json { return try Output.json(out) }
    guard let plan = out.plan else { return print(out.next) }
    printPlan(plan)
    print("\nreview it, then run: farrier apply \(plan.id.prefix(8))")
}

// MARK: - farrier uninstall

struct Uninstall: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Remove Farrier's per-user state (macOS). For a full uninstall run the script it points to with sudo.",
        discussion: """
        Unregisters the privileged helper and deletes the approval key from your login keychain. With --purge, also \
        your saved plans, journal and logs. The root-owned parts (the app, the enrolled public key, the helper's \
        authorization right, the `farrier` wrapper) are removed by \
        `sudo /Applications/Farrier.app/Contents/Resources/uninstall.sh`, which runs this first.
        """
    )

    @Flag(help: "Also remove saved plans, the journal and logs.")
    var purge = false

    @Flag(help: "Don't ask for confirmation.")
    var yes = false

    func run() throws {
        try Helper.macOnly()
        #if os(macOS)
        if !yes {
            print("Remove Farrier's helper registration and approval key\(purge ? ", plans, journal and logs" : "")? [y/N] ", terminator: "")
            guard let answer = readLine(), ["y", "yes"].contains(answer.lowercased()) else {
                print("nothing removed")
                return
            }
        }
        var problems: [String] = []
        let (status, message) = HelperClient.unregister()
        print("helper: \(status)" + (message.map { " (\($0))" } ?? ""))
        // `unregister` reports failure instead of throwing: anything but "gone" is a problem worth a nonzero exit.
        if message != nil || !["notRegistered", "notFound"].contains(status) {
            problems.append("the helper is still registered (\(status))\(message.map { ": \($0)" } ?? "")")
        }
        do {
            try ApprovalKey.delete()
            print("approval key: removed from the login keychain")
        } catch {
            problems.append("approval key: \(error)")
        }
        // The daily expiry job goes either way: without the app it would only fail.
        if ExpirySchedule.installed {
            ExpirySchedule.uninstall()
            print("automatic quarantine expiry: removed")
        }
        if purge {
            let home = FileManager.default.homeDirectoryForCurrentUser
            for path in [".farrier", "Library/Application Support/Farrier", "Library/Logs/Farrier"] {
                let url = home.appendingPathComponent(path)
                guard FileManager.default.fileExists(atPath: url.path) else { continue }
                do {
                    try FileManager.default.removeItem(at: url)
                    print("removed ~/\(path)")
                } catch {
                    problems.append("~/\(path): \(error)")
                }
            }
        }
        for p in problems { note(p) }
        if ProcessInfo.processInfo.environment["SUDO_USER"] == nil {
            // This bundle's own script, wherever the app is installed.
            let bundle = Bundle.main.bundlePath.hasSuffix(".app") ? Bundle.main.bundlePath : "/Applications/Farrier.app"
            let script = "'" + (bundle + "/Contents/Resources/uninstall.sh").replacingOccurrences(of: "'", with: "'\\''") + "'"
            print("\nto finish (the app, the enrolled key, the authorization right, the wrapper):")
            print("  sudo \(script)\(purge ? " --purge" : "")")
        }
        if !problems.isEmpty { throw ExitCode(1) }
        #endif
    }
}
