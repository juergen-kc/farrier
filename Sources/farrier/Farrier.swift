import ArgumentParser
import FarrierCore
import Foundation

@main
struct Farrier: ParsableCommand {
    static let version = "0.1.0-dev"

    static let configuration = CommandConfiguration(
        commandName: "farrier",
        abstract: "Keep your Mac sound: hygiene, posture, drift, patching and debugging.",
        discussion: "v0.1: rule packs, unprivileged fact collection and posture evaluation. The privileged helper and the MCP server follow.",
        version: version,
        subcommands: [Posture.self, Facts.self, Rules.self]
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

        @Argument(help: "Rule pack files or directories.")
        var paths: [String] = ["rules"]

        @Flag(help: "Treat the packs as user packs, with the stricter user-pack rules.")
        var user = false

        @Flag(help: "Output JSON.")
        var json = false

        func run() throws {
            let source: RulePack.Source = user ? .user : .bundled
            let (packs, loadIssues) = RuleLinter.loadPacks(at: paths, source: source)
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

        @Argument(help: "Rule pack files or directories.")
        var paths: [String] = ["rules"]

        @Flag(help: "Output JSON.")
        var json = false

        func run() throws {
            let (packs, issues) = RuleLinter.loadPacks(at: paths, source: .bundled)
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

    @Option(name: .customLong("rules"), help: "Rule pack files or directories.")
    var rulePaths: [String] = ["rules"]

    @Option(help: "JSON file with facts to use instead of collecting: { \"<fact id>\": <value>, … }")
    var facts: String?

    @Flag(help: "Output JSON.")
    var json = false

    func run() throws {
        let (packs, loadIssues) = RuleLinter.loadPacks(at: rulePaths, source: .bundled)
        // The same checks as `farrier rules lint`: duplicate ids and the like must stop evaluation too.
        let errors = (loadIssues + RuleLinter.lint(packs)).filter { $0.level == .error }
        guard errors.isEmpty else {
            for e in errors { FileHandle.standardError.write(Data("\(e)\n".utf8)) }
            throw ExitCode(2)
        }
        let store: StaticFactStore
        if let facts {
            store = try StaticFactStore(json: Data(contentsOf: URL(fileURLWithPath: facts)))
        } else {
            store = StaticFactStore(SystemCollectors().collect())
        }
        let report = PostureEngine.evaluate(packs, facts: store)

        if json {
            try Output.json(report)
            return
        }
        for f in report.findings {
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
            print(line)
            if let reason = f.reason { print("      \(reason)") }
        }
        let s = report.summary
        print("\(s["pass"] ?? 0) passed, \(s["fail"] ?? 0) failed, \(s["unknown"] ?? 0) unknown, \(s["managed"] ?? 0) managed by MDM")
    }
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
        let result = SystemCollectors().collect()
        if let save {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
            try encoder.encode(result.facts).write(to: URL(fileURLWithPath: save))
        }
        if json {
            try Output.json(FactsReport(facts: result.facts, notes: result.notes))
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

struct FactsReport: Encodable {
    let facts: [String: FactValue]
    let notes: [CollectionNote]
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
