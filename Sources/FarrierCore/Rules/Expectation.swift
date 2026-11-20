import Foundation

/// The `expect` clause of a posture check (docs/RULE_PACKS.md).
public indirect enum Expectation: Sendable, Hashable {
    case equals(FactValue)
    case notEquals(FactValue)
    case oneOf([FactValue])          // `in`
    case matches(String)             // regular expression, whole-string match
    case lessThan(Double)            // `lt`
    case greaterThan(Double)         // `gt`
    case exists(Bool)
    case all([Expectation])
    case any([Expectation])
    case each(Expectation)           // every element of an array
    case at(path: String, Expectation) // `path` + one operator: applies to a key inside an object

    public static let operators: Set<String> = [
        "equals", "notEquals", "in", "matches", "lt", "gt", "exists", "all", "any", "each",
    ]

    /// Parses `{ equals: X }`, `{ path: a.b, equals: X }`, `{ all: [ … ] }` and so on.
    public static func parse(_ value: FactValue) throws -> Expectation {
        guard var object = value.object else {
            throw RuleError("expect must be a mapping, got \(value)")
        }
        if let path = object.removeValue(forKey: "path") {
            guard let p = path.string, !p.isEmpty else { throw RuleError("expect.path must be a non-empty string") }
            return .at(path: p, try parse(.object(object)))
        }
        let keys = Set(object.keys)
        let unknown = keys.subtracting(operators)
        guard unknown.isEmpty else {
            throw RuleError("unknown expect operator(s): \(unknown.sorted().joined(separator: ", "))")
        }
        guard keys.count == 1, let op = keys.first, let arg = object[op] else {
            throw RuleError("expect needs exactly one operator (plus optional path), got: \(keys.sorted().joined(separator: ", "))")
        }
        switch op {
        case "equals": return .equals(arg)
        case "notEquals": return .notEquals(arg)
        case "in":
            guard let a = arg.array else { throw RuleError("expect.in must be a list") }
            return .oneOf(a)
        case "matches":
            guard let pattern = arg.string else { throw RuleError("expect.matches must be a string") }
            do { _ = try NSRegularExpression(pattern: pattern) } catch {
                throw RuleError("expect.matches is not a valid regular expression: \(pattern)")
            }
            return .matches(pattern)
        case "lt":
            guard let n = arg.number else { throw RuleError("expect.lt must be a number") }
            return .lessThan(n)
        case "gt":
            guard let n = arg.number else { throw RuleError("expect.gt must be a number") }
            return .greaterThan(n)
        case "exists":
            guard case .bool(let b) = arg else { throw RuleError("expect.exists must be true or false") }
            return .exists(b)
        case "all", "any":
            guard let a = arg.array, !a.isEmpty else { throw RuleError("expect.\(op) must be a non-empty list") }
            let parts = try a.map(parse)
            return op == "all" ? .all(parts) : .any(parts)
        case "each":
            return .each(try parse(arg))
        default:
            throw RuleError("unknown expect operator \(op)")  // unreachable: checked above
        }
    }

    /// Evaluates against a value. `nil` means "not present" (for example a missing key inside an object).
    public func evaluate(_ value: FactValue?) -> Outcome {
        // Operators that handle a missing value themselves: `exists`, and the combinators and `path`, which pass it
        // on to their children (so `any: [{ exists: false }, …]` works on a missing value).
        switch self {
        case .exists(let shouldExist):
            let present = value.map { !$0.isNull } ?? false
            return present == shouldExist
                ? .pass
                : .fail(shouldExist ? "value is missing" : "value is present (\(value!))")
        case .all(let parts):
            return Outcome.combineAll(parts.map { $0.evaluate(value) })
        case .any(let parts):
            return Outcome.combineAny(parts.map { $0.evaluate(value) })
        case .at(let path, let inner):
            switch inner.evaluate(value?.value(at: path)) {
            case .pass: return .pass
            case .fail(let r): return .fail("\(path): \(r)")
            case .unknown(let r): return .unknown("\(path): \(r)")
            }
        default:
            break
        }
        guard let value else { return .fail("value is missing") }

        switch self {
        case .equals(let expected):
            return value.matches(expected) ? .pass : .fail("expected \(expected), got \(value)")
        case .notEquals(let unexpected):
            return value.matches(unexpected) ? .fail("must not be \(unexpected)") : .pass
        case .oneOf(let options):
            return options.contains(where: value.matches)
                ? .pass
                : .fail("expected one of \(FactValue.array(options)), got \(value)")
        case .matches(let pattern):
            guard let s = value.string else { return .fail("expected a string matching /\(pattern)/, got \(value)") }
            return Self.fullMatch(pattern, s) ? .pass : .fail("\"\(s)\" does not match /\(pattern)/")
        case .lessThan(let limit):
            guard let n = value.number else { return .fail("expected a number, got \(value)") }
            return n < limit ? .pass : .fail("expected < \(limit), got \(value)")
        case .greaterThan(let limit):
            guard let n = value.number else { return .fail("expected a number, got \(value)") }
            return n > limit ? .pass : .fail("expected > \(limit), got \(value)")
        case .each(let inner):
            guard let items = value.array else { return .fail("expected a list, got \(value)") }
            let outcomes = items.enumerated().map { index, item -> Outcome in
                switch inner.evaluate(item) {
                case .pass: return .pass
                case .fail(let r): return .fail("item \(index): \(r)")
                case .unknown(let r): return .unknown("item \(index): \(r)")
                }
            }
            return Outcome.combineAll(outcomes)
        case .exists, .all, .any, .at:
            return .pass  // handled above
        }
    }

    private static func fullMatch(_ pattern: String, _ s: String) -> Bool {
        // \A and \z: absolute start and end. `$` would also match before a trailing newline ("enabled\n").
        guard let re = try? NSRegularExpression(pattern: "\\A(?:\(pattern))\\z") else { return false }
        return re.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil
    }
}

/// The result of evaluating a check. `unknown` means it couldn't be decided (for example, the fact wasn't collected).
public enum Outcome: Sendable, Hashable {
    case pass
    case fail(String)
    case unknown(String)

    /// All must pass. Any failure fails; otherwise any unknown makes the whole unknown.
    static func combineAll(_ outcomes: [Outcome]) -> Outcome {
        var unknown: String?
        var failures: [String] = []
        for o in outcomes {
            switch o {
            case .pass: continue
            case .fail(let r): failures.append(r)
            case .unknown(let r): unknown = unknown ?? r
            }
        }
        if !failures.isEmpty { return .fail(failures.joined(separator: "; ")) }
        if let unknown { return .unknown(unknown) }
        return .pass
    }

    /// One must pass. Otherwise unknown if any is unknown, else fail.
    static func combineAny(_ outcomes: [Outcome]) -> Outcome {
        if outcomes.contains(.pass) { return .pass }
        if let u = outcomes.first(where: { if case .unknown = $0 { return true } else { return false } }) { return u }
        let reasons = outcomes.compactMap { if case .fail(let r) = $0 { return r } else { return nil } }
        return .fail("none matched: " + reasons.joined(separator: "; "))
    }
}
