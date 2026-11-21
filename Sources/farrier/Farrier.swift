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
        subcommands: [Posture.self, Facts.self, Rules.self, PlanCommand.self, Apply.self, Setup.self, ExceptionsCommand.self, JournalCommand.self, Helper.self, MCPCommand.self, Uninstall.self]
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

    func run() throws {
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
        for f in out.findings {
            let mark: String
            switch f.status {
            case .pass: mark = "PASS"
            case .fail: mark = "FAIL"
            case .unknown: mark = "????"
            }
            var line = "\(mark)  \(f.severity.rawValue.padding(toLength: 8, withPad: " ", startingAt: 0)) \(f.ruleID)"
            if f.managed { line += "  [managed by \(f.managedBy ?? "MDM")]" }
            if f.fixable { line += "  [fixable]" }
            if f.managementUnknown && f.status != .pass { line += "  [MDM profiles not checked]" }
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

    func run() throws {
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


// MARK: - farrier helper

struct Helper: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Manage and check the privileged helper (macOS, from Farrier.app only).",
        subcommands: [Status.self, Register.self, Unregister.self, Ping.self, WhoAmI.self]
    )

    static func macOnly() throws {
        #if !os(macOS)
        FileHandle.standardError.write(Data("the privileged helper exists only on macOS\n".utf8))
        throw ExitCode(2)
        #endif
    }

    struct Status: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Show the helper's registration status.")
        func run() throws {
            try Helper.macOnly()
            #if os(macOS)
            print("helper: \(HelperClient.status)")
            #endif
        }
    }

    struct Register: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Register the helper (macOS then asks you to approve it).")
        func run() throws {
            try Helper.macOnly()
            #if os(macOS)
            let (status, message) = HelperClient.register()
            print("helper: \(status)")
            if let message { print(message) }
            #endif
        }
    }

    struct Unregister: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Unregister the helper.")
        func run() throws {
            try Helper.macOnly()
            #if os(macOS)
            let (status, message) = HelperClient.unregister()
            print("helper: \(status)")
            if let message { print(message) }
            #endif
        }
    }

    struct Ping: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Talk to the helper: its version, and whether it runs as root.")
        func run() throws {
            try Helper.macOnly()
            #if os(macOS)
            do {
                let info = try HelperClient.hello()
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
        func run() throws {
            try Helper.macOnly()
            #if os(macOS)
            do {
                let d = try HelperClient.whoAmI()
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
