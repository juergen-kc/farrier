import ArgumentParser
import FarrierCore
import FarrierHelperKit
import FarrierMCP
import Foundation

@main
struct Farrier: AsyncParsableCommand {
    static let version = FarrierVersion.string

    static let configuration = CommandConfiguration(
        commandName: "farrier",
        abstract: "Keep your Mac sound: hygiene, posture, drift, patching and debugging.",
        discussion: "v0.1: rule packs, fact collection, posture evaluation, the privileged helper, and plan → approve → apply for the first fix (firewall). `farrier mcp` serves the same over MCP (stdio).",
        version: version,
        subcommands: [Posture.self, InventoryCommand.self, Facts.self, Rules.self, PlanCommand.self, Apply.self, Undo.self, Setup.self, ExceptionsCommand.self, JournalCommand.self, Helper.self, MCPCommand.self, Uninstall.self]
    )
}

// MARK: - farrier rules

struct Rules: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Work with rule packs.",
        subcommands: [Lint.self, List.self]
    )

    struct Lint: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Validate rule packs (schema, safety, protected paths).")

        @Argument(help: "Rule pack files or directories. Default: the packs bundled with Farrier.app, or ./rules.")
        var paths: [String] = []

        @Flag(help: "Treat the packs as user packs, with the stricter user-pack rules.")
        var user = false

        @Flag(help: "Output JSON.")
        var json = false

        func run() throws {
            let source: RulePack.Source = user ? .user : .bundled
            let (packs, loadIssues) = RuleLinter.loadPacks(at: paths.isEmpty ? defaultRulePaths() : paths, source: source)
            let issues = loadIssues + RuleLinter.lint(packs)
            let errors = issues.filter { $0.level == .error }.count

            if json {
                try Output.json(LintReport(packs: packs.count, rules: packs.reduce(0) { $0 + $1.rules.count }, issues: issues))
            } else {
                for issue in issues { print(issue) }
                let warnings = issues.count - errors
                print("\(packs.count) pack(s), \(packs.reduce(0) { $0 + $1.rules.count }) rule(s): \(errors) error(s), \(warnings) warning(s)")
            }
            if errors > 0 { throw ExitCode(1) }
        }
    }

    struct List: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "List the rules in the given packs.")

        @Argument(help: "Rule pack files or directories. Default: the packs bundled with Farrier.app, or ./rules.")
        var paths: [String] = []

        @Flag(help: "Output JSON.")
        var json = false

        func run() throws {
            let (packs, issues) = RuleLinter.loadPacks(at: paths.isEmpty ? defaultRulePaths() : paths, source: .bundled)
            for issue in issues where issue.level == .error { FileHandle.standardError.write(Data("\(issue)\n".utf8)) }
            let rows = packs.flatMap { pack in
                pack.rules.map { RuleSummary(pack: pack.id, id: $0.id, kind: $0.kind, title: $0.title) }
            }
            if json {
                try Output.json(rows)
            } else {
                for r in rows { print("\(r.kind.padding(toLength: 8, withPad: " ", startingAt: 0)) \(r.id)  \(r.title)") }
            }
        }
    }
}

// MARK: - farrier posture

struct Posture: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Evaluate posture checks.",
        discussion: "Collects facts from this Mac (read-only, unprivileged) unless --facts gives a JSON file instead. Facts that need the privileged helper are reported as unknown for now."
    )

    @Option(name: .customLong("rules"), help: "Rule pack files or directories. Default: the packs bundled with Farrier.app, or ./rules.")
    var rulePaths: [String] = []

    @Option(help: "JSON file with facts to use instead of collecting: { \"<fact id>\": <value>, … }")
    var facts: String?

    @Flag(help: "Output JSON.")
    var json = false

    @OptionGroup var redaction: RedactOption

    func run() throws {
        redaction.apply()
        let out: PostureOutput
        do {
            out = try Operations.posture(try cliContext(rulePaths: rulePaths, factsFile: facts))
        } catch let error as OperationError {
            note("\(error)")
            throw ExitCode(2)
        }
        if json {
            try Output.json(out)
            return
        }
        print("this Mac: \(out.management.description)")
        for f in out.findings {
            let mark: String
            switch f.status {
            case .pass: mark = "PASS"
            case .fail: mark = "FAIL"
            case .unknown: mark = "????"
            }
            var line = "\(mark)  \(f.severity.rawValue.padding(toLength: 8, withPad: " ", startingAt: 0)) \(f.ruleID)"
            if f.managed { line += "  [managed by \(f.managedByProfile.map { "profile \($0)" } ?? f.managedBy ?? "MDM")]" }
            if f.fixable { line += "  [fixable]" }
            if f.managementUnknown && f.status != .pass { line += "  [MDM management not checked]" }
            if let accepted = f.accepted { line += "  [\(accepted.count) accepted by exception]" }
            print(line)
            if let reason = f.reason { print("      \(reason)") }
        }
        if let problem = out.exceptionsProblem { note(problem) }
        let s = out.summary
        print("\(s["pass"] ?? 0) passed, \(s["fail"] ?? 0) failed, \(s["unknown"] ?? 0) unknown, \(s["managed"] ?? 0) managed by MDM")
    }
}

/// The context the CLI commands run in: live by default, with `--rules` and `--facts` overrides. The CLI and the
/// MCP server go through the same `Operations`, so `--json` output and tool results have the same shape.
func cliContext(rulePaths: [String], factsFile: String?, explicitRulesAreUserPacks: Bool = false) throws -> FarrierContext {
    var ctx = FarrierContext.live(actor: "cli")
    if !rulePaths.isEmpty {
        ctx.rulePaths = rulePaths
        if explicitRulesAreUserPacks { ctx.rulePackSource = .user }
    }
    if let factsFile {
        let store = try StaticFactStore(json: Data(contentsOf: URL(fileURLWithPath: factsFile)))
        let notes = store.facts.keys.sorted().map {
            CollectionNote(fact: $0, status: .collected, source: "file", detail: factsFile)
        }
        ctx.collectFacts = { CollectionResult(facts: store.facts, notes: notes) }
    }
    return ctx
}

// MARK: - farrier facts

struct Facts: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Collect facts from this Mac and show them, with the reason for any that are missing.",
        discussion: "Read-only and unprivileged. Use --save to write a fact file for `farrier posture --facts` or for test fixtures."
    )

    @Flag(help: "Output JSON (facts and collection notes).")
    var json = false

    @Option(help: "Also write the facts (only) as JSON to this file.")
    var save: String?

    @OptionGroup var redaction: RedactOption

    func run() throws {
        redaction.apply()
        let result = Operations.facts(FarrierContext.live(actor: "cli"))
        if let save {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
            try encoder.encode(result.facts).write(to: URL(fileURLWithPath: save))
        }
        if json {
            try Output.json(result)
            return
        }
        for note in result.notes.sorted(by: { $0.fact < $1.fact }) {
            let value = result.facts[note.fact].map(\.description) ?? "—"
            var line = "\(note.status.rawValue.padding(toLength: 11, withPad: " ", startingAt: 0)) \(note.fact) = \(value)"
            if let detail = note.detail { line += "   (\(detail))" }
            print(line)
        }
    }
}


// MARK: - farrier inventory

struct InventoryCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "inventory",
        abstract: "List what's on this Mac: apps, launch jobs, extensions, profiles, privacy grants, admins, ports.",
        discussion: """
        Read-only. Apps and launch jobs show their code signature; those that aren't validly signed and notarized are \
        marked with !. Privacy grants need Full Disk Access for Farrier.app, profiles need the privileged helper; a \
        section that can't be read says why.
        """
    )

    @Option(name: .customLong("section"), help: "Only this section (repeatable): \(Inventory.sectionIDs.joined(separator: ", ")).")
    var sections: [String] = []

    @Flag(help: "Only the apps and launch jobs that need a look.")
    var flagged = false

    @Flag(help: "Output JSON.")
    var json = false

    @OptionGroup var redaction: RedactOption

    func run() throws {
        redaction.apply()
        let report: InventoryReport
        do {
            report = try Operations.inventory(FarrierContext.live(actor: "cli"),
                                              sections: sections.isEmpty ? nil : Set(sections), flaggedOnly: flagged)
        } catch let error as OperationError {
            note("\(error)")
            throw ExitCode(2)
        }
        if json {
            try Output.json(report)
            return
        }
        for (n, section) in report.sections.enumerated() {
            if n > 0 { print("") }
            var header = "\(section.title)"
            if section.available {
                header += " (\(section.items.count)"
                if section.flagged > 0 { header += ", \(section.flagged) need a look" }
                header += ")"
            }
            print(header)
            guard section.available else {
                print("  — \(section.note ?? "not collected")")
                continue
            }
            if section.items.isEmpty { print("  none") }
            for item in section.items {
                let mark = Inventory.needsALook(item) ? "!" : " "
                print(" \(mark) \(Inventory.describe(item, section: section.id))")
            }
        }
    }
}

// MARK: - farrier helper

struct Helper: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Manage and check the privileged helper (macOS, from Farrier.app only).",
        subcommands: [Status.self, Register.self, Unregister.self, FullDiskAccessCommand.self, Ping.self, WhoAmI.self]
    )

    static func macOnly() throws {
        #if !os(macOS)
        FileHandle.standardError.write(Data("the privileged helper exists only on macOS\n".utf8))
        throw ExitCode(2)
        #endif
    }

    struct Status: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Show the helper's registration status, and whether it has Full Disk Access.")

        @Flag(help: "Output JSON: the same as the MCP tool farrier_status (helper, approval key and its age, Full Disk Access, problems).")
        var json = false

        @OptionGroup var redaction: RedactOption

        func run() throws {
            redaction.apply()
            if json { return try Output.json(FarrierMCP.Status.current()) }
            try Helper.macOnly()
            #if os(macOS)
            print("helper: \(HelperClient.status)")
            guard HelperClient.status == "enabled" else { return }
            print("full disk access: \(FullDiskAccessCommand.describe())")
            #endif
        }
    }

    struct Register: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Register the helper (macOS then asks you to approve it).")
        @Flag(help: "Output JSON.") var json = false
        func run() throws {
            try Helper.macOnly()
            #if os(macOS)
            let (status, message) = HelperClient.register()
            if json { return try Output.json(RegistrationOutput(status: status, message: message)) }
            print("helper: \(status)")
            if let message { print(message) }
            #endif
        }
    }

    struct Unregister: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Unregister the helper.")
        @Flag(help: "Output JSON.") var json = false
        func run() throws {
            try Helper.macOnly()
            #if os(macOS)
            let (status, message) = HelperClient.unregister()
            if json { return try Output.json(RegistrationOutput(status: status, message: message)) }
            print("helper: \(status)")
            if let message { print(message) }
            #endif
        }
    }

    struct FullDiskAccessCommand: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "full-disk-access",
            abstract: "Check that Farrier.app has Full Disk Access, and help you grant it if not.",
            discussion: """
            Some checks read privacy-protected data (for example which apps hold privacy grants). Only Farrier's \
            root helper reads it, and only with Full Disk Access granted to Farrier.app; your terminal or AI client \
            never gets that access. Without it, those checks report "unknown" rather than pass or fail.

            If the access is missing, this opens System Settings → Privacy & Security → Full Disk Access, shows \
            Farrier.app in the Finder, and waits until you've turned it on.
            """
        )

        @Flag(help: "Only check; don't open System Settings or wait.")
        var check = false

        @Flag(help: "Output JSON ({ granted, reason }); implies --check.")
        var json = false

        @Option(help: "How long to wait for the grant, in seconds.")
        var timeout: Int = 300

        /// One line for `helper status`.
        static func describe() -> String {
            #if os(macOS)
            do {
                switch try HelperClient.fullDiskAccess() {
                case .success(true): return "granted"
                case .success(false): return "not granted (run `farrier helper full-disk-access`)"
                case .failure(let unknown): return "unknown (\(unknown.reason))"
                }
            } catch {
                return "unknown (\(error))"
            }
            #else
            return "unknown (macOS only)"
            #endif
        }

        func run() throws {
            try Helper.macOnly()
            #if os(macOS)
            if json {
                struct Out: Encodable { let granted: Bool?; let reason: String? }
                switch (try? HelperClient.fullDiskAccess()) {
                case .success(let g)?: try Output.json(Out(granted: g, reason: nil))
                case .failure(let u)?: try Output.json(Out(granted: nil, reason: u.reason))
                case nil: try Output.json(Out(granted: nil, reason: "the helper isn't available"))
                }
                return
            }
            let granted: Bool
            do {
                try HelperClient.ensureCurrent()
                switch try HelperClient.fullDiskAccess() {
                case .success(let g): granted = g
                case .failure(let unknown):
                    note("can't tell whether Farrier.app has Full Disk Access: \(unknown.reason)")
                    throw ExitCode(1)
                }
            } catch let exit as ExitCode {
                throw exit
            } catch {
                note("\(error)")
                throw ExitCode(1)
            }
            if granted {
                print("Full Disk Access: granted to Farrier.app")
                return
            }
            print("Full Disk Access: not granted to Farrier.app")
            if check { throw ExitCode(1) }

            let app = Bundle.main.bundlePath
            print("""

            To grant it:
              1. In System Settings → Privacy & Security → Full Disk Access (opening now), click +.
              2. Choose Farrier.app (\(app); a Finder window shows it), or drag it from the Finder into the list.
              3. Make sure the switch next to Farrier is on.

            Only Farrier's root helper uses this access; the terminal or AI client running farrier doesn't get it.
            Waiting up to \(timeout) s (Ctrl-C to stop; run this again later to check)…
            """)
            _ = ProcessRunner().run("/usr/bin/open", [FullDiskAccess.settingsURL], timeout: 10)
            _ = ProcessRunner().run("/usr/bin/open", ["-R", app], timeout: 10)

            let deadline = Date().addingTimeInterval(TimeInterval(max(timeout, 0)))
            while Date() < deadline {
                Thread.sleep(forTimeInterval: 2)
                // Each check is bounded by the time left, so a helper that stalls can't outlast --timeout.
                let left = deadline.timeIntervalSinceNow
                guard left > 0 else { break }
                if case .success(true)? = try? HelperClient.fullDiskAccess(timeout: min(left, 10)) {
                    print("Full Disk Access: granted to Farrier.app")
                    return
                }
            }
            note("still not granted after \(timeout) s; run `farrier helper full-disk-access` again once you've turned it on")
            throw ExitCode(1)
            #endif
        }
    }

    struct Ping: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Talk to the helper: its version, and whether it runs as root.")
        @Flag(help: "Output JSON.") var json = false
        func run() throws {
            try Helper.macOnly()
            #if os(macOS)
            do {
                let info = try HelperClient.hello()
                if json { return try Output.json(info) }
                print("helper \(info.version) (protocol \(info.protocolVersion)), pid \(info.pid), euid \(info.euid)")
                if info.willExit { print("version differs from this farrier (\(FarrierVersion.string)): the helper restarts on the next call") }
            } catch {
                FileHandle.standardError.write(Data("\(error)\n".utf8))
                throw ExitCode(1)
            }
            #endif
        }
    }

    struct WhoAmI: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "whoami",
            abstract: "How the helper sees this caller (console-session check).")
        @Flag(help: "Output JSON.") var json = false
        func run() throws {
            try Helper.macOnly()
            #if os(macOS)
            do {
                let d = try HelperClient.whoAmI()
                if json { return try Output.json(d) }
                print("accepted: \(d.accepted)  uid \(d.callerEUID)  console user \(d.consoleUser)  session \(d.sessionBits)")
                for r in d.reasons { print("  - \(r)") }
            } catch {
                FileHandle.standardError.write(Data("\(error)\n".utf8))
                throw ExitCode(1)
            }
            #endif
        }
    }
}

struct RegistrationOutput: Encodable {
    let status: String
    let message: String?
}

// MARK: - Output

struct LintReport: Encodable {
    let packs: Int
    let rules: Int
    let issues: [LintIssue]
}

struct RuleSummary: Encodable {
    let pack: String
    let id: String
    let kind: String
    let title: String
}

enum Output {
    static func json<T: Encodable>(_ value: T) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        print(String(decoding: try encoder.encode(value), as: UTF8.self))
    }
}
