import Foundation
import Yams

/// A problem found while loading or linting a rule pack.
public struct LintIssue: Sendable, Hashable, Codable, CustomStringConvertible {
    public enum Level: String, Sendable, Codable { case error, warning }

    public let level: Level
    public let file: String
    public let ruleID: String?
    public let message: String

    public init(_ level: Level, file: String, ruleID: String? = nil, _ message: String) {
        self.level = level
        self.file = file
        self.ruleID = ruleID
        self.message = message
    }

    public var description: String {
        "\(level.rawValue): \(file)\(ruleID.map { " [\($0)]" } ?? ""): \(message)"
    }
}

/// Turns a rule-pack YAML file into a `RulePack`. Structural problems become `LintIssue`s. A rule with errors is
/// skipped, so one bad rule never takes the rest of the pack down with it, and never loads half-parsed.
public enum RulePackParser {
    public struct Result: Sendable {
        public let pack: RulePack?
        public let issues: [LintIssue]
    }

    static let packKeys: Set<String> = ["id", "title", "version", "description"]
    static let commonRuleKeys: Set<String> = ["id", "title", "kind", "description"]
    static let checkKeys: Set<String> = ["severity", "collect", "expect", "managedBy", "remediation", "mappings"]
    static let cleanupKeys: Set<String> = [
        "tier", "targets", "regenerable", "minAge", "minSize", "when", "privileged", "evidence", "references",
    ]
    static let targetKeys: Set<String> = ["path", "fact", "type", "contains"]
    static let whenKeys: Set<String> = ["processNotRunning", "appInstalled", "appNotInstalled"]
    static let remediationKeys: Set<String> = ["automatic", "action", "guidance"]
    static let managedByKeys: Set<String> = ["payloadType", "declarationType"]

    public static func parse(file url: URL, source: RulePack.Source) -> Result {
        do {
            let text = try String(contentsOf: url, encoding: .utf8)
            return parse(yaml: text, file: url.lastPathComponent, source: source)
        } catch {
            return Result(pack: nil, issues: [LintIssue(.error, file: url.lastPathComponent, "cannot read file: \(error)")])
        }
    }

    public static func parse(yaml: String, file: String, source: RulePack.Source) -> Result {
        var issues: [LintIssue] = []
        let root: FactValue
        do {
            root = try FactValue.parseYAML(yaml)
        } catch {
            return Result(pack: nil, issues: [LintIssue(.error, file: file, "invalid YAML: \(error)")])
        }
        guard let top = root.object else {
            return Result(pack: nil, issues: [LintIssue(.error, file: file, "top level must be a mapping with `pack` and `rules`")])
        }
        for key in Set(top.keys).subtracting(["pack", "rules"]).sorted() {
            issues.append(LintIssue(.error, file: file, "unknown top-level key `\(key)`"))
        }
        guard let header = top["pack"]?.object else {
            issues.append(LintIssue(.error, file: file, "missing `pack` header"))
            return Result(pack: nil, issues: issues)
        }
        for key in Set(header.keys).subtracting(packKeys).sorted() {
            issues.append(LintIssue(.error, file: file, "unknown key `pack.\(key)`"))
        }
        guard let packID = header["id"]?.string, !packID.isEmpty else {
            issues.append(LintIssue(.error, file: file, "`pack.id` is required"))
            return Result(pack: nil, issues: issues)
        }
        let title = header["title"]?.string ?? packID
        var version = 1
        if let v = header["version"] {
            if case .int(let i) = v, i > 0 { version = i } else {
                issues.append(LintIssue(.error, file: file, "`pack.version` must be a positive integer"))
            }
        }
        guard let rawRules = top["rules"]?.array else {
            issues.append(LintIssue(.error, file: file, "`rules` must be a list"))
            return Result(pack: nil, issues: issues)
        }

        var rules: [Rule] = []
        for (index, raw) in rawRules.enumerated() {
            var ctx = Context(file: file, ruleID: nil, issues: [])
            if let rule = parseRule(raw, index: index, ctx: &ctx) { rules.append(rule) }
            issues += ctx.issues
        }
        let pack = RulePack(id: packID, title: title, version: version, rules: rules, source: source, file: file)
        return Result(pack: pack, issues: issues)
    }

    // MARK: - Rules

    struct Context {
        let file: String
        var ruleID: String?
        var issues: [LintIssue]
        var hasErrors: Bool { issues.contains { $0.level == .error } }

        mutating func error(_ message: String) { issues.append(LintIssue(.error, file: file, ruleID: ruleID, message)) }
        mutating func warning(_ message: String) { issues.append(LintIssue(.warning, file: file, ruleID: ruleID, message)) }

        mutating func unknownKeys(_ object: [String: FactValue], allowed: Set<String>, prefix: String = "") {
            for key in Set(object.keys).subtracting(allowed).sorted() { error("unknown key `\(prefix)\(key)`") }
        }

        mutating func string(_ object: [String: FactValue], _ key: String, required: Bool = true) -> String? {
            guard let v = object[key] else {
                if required { error("`\(key)` is required") }
                return nil
            }
            guard let s = v.string, !s.isEmpty else {
                // A typical cause: YAML 1.1 reads unquoted on/off/yes/no as booleans.
                error("`\(key)` must be a non-empty string, got \(v)\(v.isBool ? " (quote it: unquoted on/off/yes/no are booleans in YAML)" : "")")
                return nil
            }
            return s
        }

        mutating func bool(_ object: [String: FactValue], _ key: String, default value: Bool? = nil) -> Bool? {
            guard let v = object[key] else {
                if value == nil { error("`\(key)` is required") }
                return value
            }
            guard case .bool(let b) = v else { error("`\(key)` must be true or false, got \(v)"); return value }
            return b
        }

        mutating func strings(_ object: [String: FactValue], _ key: String) -> [String] {
            guard let v = object[key] else { return [] }
            guard let a = v.array, a.allSatisfy({ $0.string != nil }) else {
                error("`\(key)` must be a list of strings")
                return []
            }
            return a.compactMap(\.string)
        }
    }

    static func parseRule(_ raw: FactValue, index: Int, ctx: inout Context) -> Rule? {
        guard let r = raw.object else {
            ctx.error("rule #\(index + 1) is not a mapping")
            return nil
        }
        ctx.ruleID = r["id"]?.string
        guard let id = ctx.string(r, "id") else { return nil }
        let title = ctx.string(r, "title") ?? id
        guard let kind = ctx.string(r, "kind") else { return nil }

        switch kind {
        case "check":
            ctx.unknownKeys(r, allowed: commonRuleKeys.union(checkKeys))
            let rule = parseCheck(r, id: id, title: title, ctx: &ctx)
            return ctx.hasErrors ? nil : rule.map(Rule.check)
        case "cleanup":
            ctx.unknownKeys(r, allowed: commonRuleKeys.union(cleanupKeys))
            let rule = parseCleanup(r, id: id, title: title, ctx: &ctx)
            return ctx.hasErrors ? nil : rule.map(Rule.cleanup)
        default:
            ctx.error("`kind` must be `check` or `cleanup`, got `\(kind)`")
            return nil
        }
    }

    static func parseCheck(_ r: [String: FactValue], id: String, title: String, ctx: inout Context) -> CheckRule? {
        var severity: Severity?
        if let s = ctx.string(r, "severity") {
            severity = Severity(rawValue: s)
            if severity == nil { ctx.error("`severity` must be one of \(Severity.allCases.map(\.rawValue).joined(separator: ", "))") }
        }

        var fact: String?
        if let collect = r["collect"]?.object {
            ctx.unknownKeys(collect, allowed: ["fact"], prefix: "collect.")
            fact = ctx.string(collect, "fact")
        } else {
            ctx.error("`collect` with a `fact` is required")
        }

        var expect: Expectation?
        if let e = r["expect"] {
            do { expect = try Expectation.parse(e) } catch { ctx.error("`expect`: \(error)") }
        } else {
            ctx.error("`expect` is required")
        }

        var managedBy: [ManagedBy] = []
        if let m = r["managedBy"] {
            if let list = m.array {
                for item in list {
                    guard let o = item.object else { ctx.error("`managedBy` entries must be mappings"); continue }
                    ctx.unknownKeys(o, allowed: managedByKeys, prefix: "managedBy.")
                    let entry = ManagedBy(payloadType: o["payloadType"]?.string, declarationType: o["declarationType"]?.string)
                    if (entry.payloadType == nil) == (entry.declarationType == nil) {
                        ctx.error("each `managedBy` entry needs exactly one of `payloadType` or `declarationType`")
                    }
                    managedBy.append(entry)
                }
            } else {
                ctx.error("`managedBy` must be a list")
            }
        }

        var remediation: Remediation?
        if let rem = r["remediation"]?.object {
            ctx.unknownKeys(rem, allowed: remediationKeys, prefix: "remediation.")
            let automatic = ctx.bool(rem, "automatic") ?? false
            let action = ctx.string(rem, "action", required: false)
            let guidance = ctx.string(rem, "guidance", required: false)
            if automatic && action == nil { ctx.error("`remediation.action` is required when `automatic` is true") }
            if !automatic && guidance == nil { ctx.error("`remediation.guidance` is required when `automatic` is false") }
            remediation = Remediation(automatic: automatic, action: action, guidance: guidance)
        } else {
            ctx.error("`remediation` is required")
        }

        var mappings: [String: String] = [:]
        if let m = r["mappings"] {
            if let o = m.object {
                for (k, v) in o {
                    // Benchmark IDs like "2.6.6" must be quoted, or YAML may read them as numbers.
                    guard let s = v.string else { ctx.error("`mappings.\(k)` must be a string (quote benchmark IDs)"); continue }
                    mappings[k] = s
                }
            } else {
                ctx.error("`mappings` must be a mapping")
            }
        }

        guard let severity, let fact, let expect, let remediation else { return nil }
        return CheckRule(id: id, title: title, severity: severity, fact: fact, expect: expect,
                         managedBy: managedBy, remediation: remediation, mappings: mappings)
    }

    static func parseCleanup(_ r: [String: FactValue], id: String, title: String, ctx: inout Context) -> CleanupRule? {
        var tier: Tier?
        if let t = ctx.string(r, "tier") {
            tier = Tier(rawValue: t)
            if tier != .t2 && tier != .t3 { ctx.error("cleanup `tier` must be T2 (reversible) or T3 (irreversible), got `\(t)`") }
        }

        var targets: [CleanupTarget] = []
        if let list = r["targets"]?.array, !list.isEmpty {
            for item in list {
                guard let o = item.object else { ctx.error("`targets` entries must be mappings"); continue }
                ctx.unknownKeys(o, allowed: targetKeys, prefix: "targets.")
                let path = ctx.string(o, "path", required: false)
                let fact = ctx.string(o, "fact", required: false)
                if (path == nil) == (fact == nil) { ctx.error("each target needs exactly one of `path` or `fact`") }
                var type = CleanupTarget.Kind.any
                if let t = ctx.string(o, "type", required: false) {
                    if let k = CleanupTarget.Kind(rawValue: t) { type = k } else { ctx.error("target `type` must be file, directory or any") }
                }
                targets.append(CleanupTarget(path: path, fact: fact, type: type, contains: ctx.strings(o, "contains")))
            }
        } else {
            ctx.error("`targets` must be a non-empty list")
        }

        let regenerable = ctx.bool(r, "regenerable")
        var minAge: RuleDuration?
        if let s = ctx.string(r, "minAge", required: false) {
            minAge = RuleDuration(s)
            if minAge == nil { ctx.error("`minAge` must look like 30d, 12h, 2w (got `\(s)`)") }
        }
        var minSize: Int64?
        if let v = r["minSize"] {
            minSize = RuleSize.parse(v)
            if minSize == nil { ctx.error("`minSize` must be bytes or a size like 500MB (got \(v))") }
        }

        var when = CleanupConditions(processNotRunning: [], appInstalled: [], appNotInstalled: [])
        if let w = r["when"] {
            if let o = w.object {
                ctx.unknownKeys(o, allowed: whenKeys, prefix: "when.")
                when = CleanupConditions(processNotRunning: ctx.strings(o, "processNotRunning"),
                                         appInstalled: ctx.strings(o, "appInstalled"),
                                         appNotInstalled: ctx.strings(o, "appNotInstalled"))
            } else {
                ctx.error("`when` must be a mapping")
            }
        }

        let privileged = ctx.bool(r, "privileged", default: false) ?? false
        let evidence = ctx.string(r, "evidence")
        let references = ctx.strings(r, "references")

        guard let tier, let regenerable, let evidence else { return nil }
        return CleanupRule(id: id, title: title, tier: tier, targets: targets, regenerable: regenerable,
                           minAge: minAge, minSize: minSize, when: when, privileged: privileged,
                           evidence: evidence, references: references)
    }
}

extension FactValue {
    /// Parses YAML the way rule packs are parsed: YAML 1.1 scalars, quoting respected.
    public static func parseYAML(_ text: String) throws -> FactValue {
        fromYAML(try Yams.load(yaml: text))
    }

    var isBool: Bool {
        if case .bool = self { return true }
        return false
    }
}
