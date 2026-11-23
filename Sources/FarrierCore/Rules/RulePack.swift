import Foundation

/// A rule pack: one YAML file with a `pack` header and a list of `rules` (docs/RULE_PACKS.md).
public struct RulePack: Sendable {
    public enum Source: String, Sendable, Codable {
        case bundled  // shipped with Farrier and signed with the release
        case user     // ~/.config/farrier/rules; restricted (THREAT_MODEL.md, T-5)
    }

    public let id: String
    public let title: String
    public let version: Int
    public let rules: [Rule]
    public let source: Source
    public let file: String
}

public enum Rule: Sendable {
    case check(CheckRule)
    case cleanup(CleanupRule)

    public var id: String {
        switch self {
        case .check(let r): return r.id
        case .cleanup(let r): return r.id
        }
    }

    public var title: String {
        switch self {
        case .check(let r): return r.title
        case .cleanup(let r): return r.title
        }
    }

    public var kind: String {
        switch self {
        case .check: return "check"
        case .cleanup: return "cleanup"
        }
    }
}

public enum Severity: String, Sendable, Codable, CaseIterable, Comparable {
    case info, low, medium, high, critical

    public static func < (a: Severity, b: Severity) -> Bool {
        allCases.firstIndex(of: a)! < allCases.firstIndex(of: b)!
    }
}

/// Operation tiers (docs/ARCHITECTURE.md, "Operation tiers").
public enum Tier: String, Sendable, Codable, CaseIterable {
    case t0 = "T0", t1 = "T1", t2 = "T2", t3 = "T3", t4 = "T4"
}

/// What can enforce a rule's setting: a configuration profile payload, a DDM declaration, or managed preferences
/// (a preference domain, optionally only some of its keys, that any profile can set, e.g. with Custom Settings).
public struct ManagedBy: Sendable, Hashable, Codable {
    public let payloadType: String?
    public let declarationType: String?
    public let preference: String?
    /// With `preference`: only these keys count; nil or empty means any key of the domain.
    public let keys: [String]?

    public init(payloadType: String? = nil, declarationType: String? = nil, preference: String? = nil, keys: [String]? = nil) {
        self.payloadType = payloadType
        self.declarationType = declarationType
        self.preference = preference
        self.keys = keys
    }
}

public struct Remediation: Sendable, Hashable, Codable {
    public let automatic: Bool
    public let action: String?
    public let guidance: String?
}

public struct CheckRule: Sendable {
    public let id: String
    public let title: String
    public let severity: Severity
    public let fact: String
    public let expect: Expectation
    public let managedBy: [ManagedBy]
    public let remediation: Remediation
    public let mappings: [String: String]
}

public struct CleanupTarget: Sendable, Hashable {
    public enum Kind: String, Sendable { case file, directory, any }
    public let path: String?   // a glob; `~` is the user's home
    public let fact: String?   // targets supplied by a collector
    public let type: Kind
    public let contains: [String]
}

public struct CleanupConditions: Sendable, Hashable {
    public let processNotRunning: [String]
    public let appInstalled: [String]
    public let appNotInstalled: [String]
}

public struct CleanupRule: Sendable {
    public let id: String
    public let title: String
    public let tier: Tier
    public let targets: [CleanupTarget]
    public let regenerable: Bool
    public let minAge: RuleDuration?
    public let minSize: Int64?
    public let when: CleanupConditions
    public let privileged: Bool
    public let evidence: String
    public let references: [String]
}

/// A duration written as `<number><unit>`: s, m, h, d or w ("14d").
public struct RuleDuration: Sendable, Hashable, CustomStringConvertible {
    public let seconds: Int64
    public let text: String

    public init?(_ text: String) {
        let units: [Character: Int64] = ["s": 1, "m": 60, "h": 3_600, "d": 86_400, "w": 604_800]
        guard let unit = text.last, let factor = units[unit], let n = Int64(text.dropLast()), n > 0 else { return nil }
        let (seconds, overflow) = n.multipliedReportingOverflow(by: factor)
        guard !overflow else { return nil }  // unrepresentable: a lint error, never a crash
        self.seconds = seconds
        self.text = text
    }

    public var description: String { text }
}

/// Sizes written as bytes (`1048576`) or with a decimal suffix: KB, MB, GB (1000-based, like Finder).
public enum RuleSize {
    public static func parse(_ value: FactValue) -> Int64? {
        if case .int(let i) = value, i >= 0 { return Int64(i) }
        guard let s = value.string?.uppercased() else { return nil }
        let units: [(String, Int64)] = [("GB", 1_000_000_000), ("MB", 1_000_000), ("KB", 1_000), ("B", 1)]
        for (suffix, factor) in units where s.hasSuffix(suffix) {
            guard let n = Int64(s.dropLast(suffix.count).trimmingCharacters(in: .whitespaces)), n >= 0 else { return nil }
            let (bytes, overflow) = n.multipliedReportingOverflow(by: factor)
            return overflow ? nil : bytes
        }
        guard let n = Int64(s), n >= 0 else { return nil }  // a quoted "-1" must not slip through
        return n
    }
}

public struct RuleError: Error, CustomStringConvertible, Sendable {
    public let description: String
    public init(_ description: String) { self.description = description }
}
