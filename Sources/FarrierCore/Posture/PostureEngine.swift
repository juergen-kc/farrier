import Foundation

/// Where posture checks get their facts. Collectors (macOS only, later PR) produce these. For now they can be
/// loaded from a JSON file, which is also how the engine is tested.
public protocol FactStore: Sendable {
    func value(for fact: String) -> FactValue?
}

/// Facts from a JSON object `{ "<fact id>": <value>, … }`. Fact ids contain dots ("filevault.status") and are
/// looked up as whole keys, not as nested paths.
public struct StaticFactStore: FactStore {
    public let facts: [String: FactValue]

    public init(_ facts: [String: FactValue]) { self.facts = facts }

    public init(json data: Data) throws {
        let value = try JSONDecoder().decode(FactValue.self, from: data)
        guard let object = value.object else { throw RuleError("a fact file must contain a JSON object") }
        self.facts = object
    }

    public func value(for fact: String) -> FactValue? { facts[fact] }
}

/// Well-known facts the engine itself uses.
public enum CoreFacts {
    /// Payload types of installed configuration profiles (list of strings).
    public static let profilePayloadTypes = "mdm.payloadTypes"
    /// Active Declarative Device Management configuration types (list of strings).
    public static let declarationTypes = "mdm.declarationTypes"
    /// MDM enrollment state: { dep, mdm, userApproved }.
    public static let enrollment = "mdm.enrollment"
}

public struct Finding: Sendable, Codable, Hashable {
    public enum Status: String, Sendable, Codable { case pass, fail, unknown }

    public let ruleID: String
    public let title: String
    public let severity: Severity
    public let status: Status
    public let reason: String?
    /// True when an MDM profile or declaration enforces this setting. Farrier then reports it but never changes it.
    public let managed: Bool
    public let managedBy: String?
    /// True when the Mac is MDM-enrolled but the installed profiles couldn't be read (that needs the helper).
    /// Then Farrier can't rule out that MDM owns the setting, so nothing is fixable.
    public let managementUnknown: Bool
    /// Can Farrier fix it locally? Only if it fails, remediation is automatic, and it isn't MDM-managed.
    public let fixable: Bool
    public let guidance: String?
    public let mappings: [String: String]
}

public struct PostureReport: Sendable, Codable {
    public let findings: [Finding]
    public let summary: [String: Int]

    public init(findings: [Finding]) {
        self.findings = findings
        var s = ["pass": 0, "fail": 0, "unknown": 0, "managed": 0]
        for f in findings {
            s[f.status.rawValue, default: 0] += 1
            if f.managed { s["managed", default: 0] += 1 }
        }
        self.summary = s
    }
}

public enum PostureEngine {
    public static func evaluate(_ packs: [RulePack], facts: FactStore) -> PostureReport {
        let payloadFact = facts.value(for: CoreFacts.profilePayloadTypes)
        let declarationFact = facts.value(for: CoreFacts.declarationTypes)
        let payloads = Set(payloadFact?.array?.compactMap(\.string) ?? [])
        let declarations = Set(declarationFact?.array?.compactMap(\.string) ?? [])
        // Enrolled (or enrollment unknown) and the managed settings weren't collected → can't rule MDM out.
        let enrolled: Bool? = {
            guard let e = facts.value(for: CoreFacts.enrollment) else { return nil }
            if case .bool(let mdm) = e.value(at: "mdm") ?? .null { return mdm }
            return nil
        }()
        let managementUnknown = (payloadFact == nil || declarationFact == nil) && enrolled != false

        var findings: [Finding] = []
        for pack in packs {
            for case .check(let rule) in pack.rules {
                let outcome: Outcome
                if let value = facts.value(for: rule.fact) {
                    outcome = rule.expect.evaluate(value)
                } else {
                    outcome = .unknown("fact `\(rule.fact)` was not collected")
                }

                let manager = rule.managedBy.first { m in
                    (m.payloadType.map(payloads.contains) ?? false) || (m.declarationType.map(declarations.contains) ?? false)
                }
                let managedBy = manager.flatMap { $0.payloadType ?? $0.declarationType }

                let (status, reason): (Finding.Status, String?) = {
                    switch outcome {
                    case .pass: return (.pass, nil)
                    case .fail(let r): return (.fail, r)
                    case .unknown(let r): return (.unknown, r)
                    }
                }()
                findings.append(Finding(
                    ruleID: rule.id, title: rule.title, severity: rule.severity, status: status, reason: reason,
                    managed: managedBy != nil, managedBy: managedBy,
                    managementUnknown: managedBy == nil && managementUnknown,
                    fixable: status == .fail && rule.remediation.automatic && managedBy == nil && !managementUnknown,
                    guidance: status == .pass ? nil : rule.remediation.guidance,
                    mappings: rule.mappings
                ))
            }
        }
        // Most important first: failures by severity, then unknowns, then passes.
        let rank: [Finding.Status: Int] = [.fail: 0, .unknown: 1, .pass: 2]
        findings.sort {
            if rank[$0.status]! != rank[$1.status]! { return rank[$0.status]! < rank[$1.status]! }
            if $0.severity != $1.severity { return $0.severity > $1.severity }
            return $0.ruleID < $1.ruleID
        }
        return PostureReport(findings: findings)
    }
}
