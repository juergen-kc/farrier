import Foundation

/// A JSON-like value: facts collected from the system, and values written in rule packs.
public enum FactValue: Sendable, Hashable {
    case null
    case bool(Bool)
    case int(Int)
    case double(Double)
    case string(String)
    case array([FactValue])
    case object([String: FactValue])

    /// Numeric view, so that `1` and `1.0` compare equal and `lt`/`gt` work on both.
    public var number: Double? {
        switch self {
        case .int(let i): return Double(i)
        case .double(let d): return d
        default: return nil
        }
    }

    public var string: String? {
        if case .string(let s) = self { return s }
        return nil
    }

    public var array: [FactValue]? {
        if case .array(let a) = self { return a }
        return nil
    }

    public var object: [String: FactValue]? {
        if case .object(let o) = self { return o }
        return nil
    }

    public var isNull: Bool {
        if case .null = self { return true }
        return false
    }

    /// Looks up a dotted path ("signature.valid") in nested objects. Returns nil if any step is missing.
    public func value(at path: String) -> FactValue? {
        var current: FactValue = self
        for key in path.split(separator: ".", omittingEmptySubsequences: false) {
            guard let next = current.object?[String(key)] else { return nil }
            current = next
        }
        return current
    }

    /// Equality that treats int and double as the same number, without losing integer precision.
    public func matches(_ other: FactValue) -> Bool {
        switch (self, other) {
        case (.int(let a), .int(let b)): return a == b
        case (.int(let a), .double(let b)), (.double(let b), .int(let a)):
            // Exact: 2^53 + 1 must not equal 2^53 just because both round to the same Double.
            guard let exact = Int(exactly: b) else { return false }
            return exact == a
        default: return self == other
        }
    }

    /// Converts the output of `Yams.load(yaml:)` (Swift values, `[AnyHashable: Any]`, `NSNull`, `Date`).
    public static func fromYAML(_ any: Any?) -> FactValue {
        guard let any else { return .null }
        switch any {
        case is NSNull: return .null
        case let b as Bool: return .bool(b)
        case let i as Int: return .int(i)
        case let d as Double: return .double(d)
        case let s as String: return .string(s)
        case let date as Date: return .string(ISO8601DateFormatter().string(from: date))
        case let a as [Any]: return .array(a.map { fromYAML($0) })
        case let m as [AnyHashable: Any]:
            var o: [String: FactValue] = [:]
            for (k, v) in m { o[String(describing: k.base)] = fromYAML(v) }
            return .object(o)
        case let m as [String: Any]:
            return .object(m.mapValues { fromYAML($0) })
        default: return .string(String(describing: any))
        }
    }
}

extension FactValue: Codable {
    /// Used for JSON (fact files, `--json` output). YAML goes through `fromYAML`, because a typed YAML decoder
    /// would coerce scalars ("On" → true) regardless of quoting.
    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null; return }
        if let b = try? c.decode(Bool.self) { self = .bool(b); return }
        if let i = try? c.decode(Int.self) { self = .int(i); return }
        if let d = try? c.decode(Double.self) { self = .double(d); return }
        if let s = try? c.decode(String.self) { self = .string(s); return }
        if let a = try? c.decode([FactValue].self) { self = .array(a); return }
        if let o = try? c.decode([String: FactValue].self) { self = .object(o); return }
        throw DecodingError.dataCorruptedError(in: c, debugDescription: "unsupported fact value")
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .null: try c.encodeNil()
        case .bool(let b): try c.encode(b)
        case .int(let i): try c.encode(i)
        case .double(let d): try c.encode(d)
        case .string(let s): try c.encode(s)
        case .array(let a): try c.encode(a)
        case .object(let o): try c.encode(o)
        }
    }
}

extension FactValue: CustomStringConvertible {
    public var description: String {
        switch self {
        case .null: return "null"
        case .bool(let b): return String(b)
        case .int(let i): return String(i)
        case .double(let d): return String(d)
        case .string(let s): return "\"\(s)\""
        case .array(let a): return "[" + a.map(\.description).joined(separator: ", ") + "]"
        case .object(let o):
            return "{" + o.keys.sorted().map { "\($0): \(o[$0]!.description)" }.joined(separator: ", ") + "}"
        }
    }
}
