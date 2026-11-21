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
    /// True when the rule can be MDM-managed but the profile and declaration inventories weren't collected (or are
    /// malformed). Farrier then can't rule out that a profile owns the setting, so the finding isn't fixable.
    /// Note: a profile can be installed without MDM enrollment, so "not enrolled" doesn't settle it either.
    public let managementUnknown: Bool
    /// Can Farrier fix it locally? Only if it fails, remediation is automatic, and it isn't MDM-managed.
    public let fixable: Bool
    public let guidance: String?
    public let mappings: [String: String]
    /// Items left out of the evaluation because an approved exception covers them (by label, or plist path).
    public let accepted: [String]?
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
    /// `exceptions`: approved exceptions (see `PostureException`). They only remove a vendor's items from list
    /// facts of the rules they name; they never turn an unknown into a pass or touch other rules.
    public static func evaluate(_ packs: [RulePack], facts: FactStore, exceptions: [PostureException] = []) -> PostureReport {
        // Inventories count only if they're present and valid lists of strings. Missing or malformed ≠ empty.
        func inventory(_ fact: String) -> Set<String>? {
            guard let list = facts.value(for: fact)?.array else { return nil }
            let strings = list.compactMap(\.string)
            return strings.count == list.count ? Set(strings) : nil
        }
        let payloads = inventory(CoreFacts.profilePayloadTypes)
        let declarations = inventory(CoreFacts.declarationTypes)

        var findings: [Finding] = []
        for pack in packs {
            for case .check(let rule) in pack.rules {
                let outcome: Outcome
                var accepted: [String]?
                if var value = facts.value(for: rule.fact) {
                    let applicable = exceptions.filter { $0.ruleID == rule.id }
                    if !applicable.isEmpty, let items = value.array {
                        // Only items that are known to FAIL the rule are accepted. An item the rule can't decide on
                        // (say, notarization unknown) stays, so an exception never turns unknown into pass.
                        let (covered, rest) = items.reduce(into: ([FactValue](), [FactValue]())) { acc, item in
                            let failsAlone: Bool = {
                                if case .fail = rule.expect.evaluate(.array([item])) { return true }
                                return false
                            }()
                            if failsAlone && applicable.contains(where: { $0.matches(item) }) { acc.0.append(item) } else { acc.1.append(item) }
                        }
                        if !covered.isEmpty {
                            accepted = covered.map { $0.object?["label"]?.string ?? $0.object?["plist"]?.string ?? "item" }
                            value = .array(rest)
                        }
                    }
                    outcome = rule.expect.evaluate(value)
                } else {
                    outcome = .unknown("fact `\(rule.fact)` was not collected")
                }

                let manager = rule.managedBy.first { m in
                    (m.payloadType.map { payloads?.contains($0) ?? false } ?? false)
                        || (m.declarationType.map { declarations?.contains($0) ?? false } ?? false)
                }
                let managedBy = manager.flatMap { $0.payloadType ?? $0.declarationType }
                // Only rules that MDM can manage need the inventories. Each selector type needs its own inventory.
                let needsPayloads = rule.managedBy.contains { $0.payloadType != nil }
                let needsDeclarations = rule.managedBy.contains { $0.declarationType != nil }
                let managementUnknown = managedBy == nil
                    && ((needsPayloads && payloads == nil) || (needsDeclarations && declarations == nil))

                let (status, reason): (Finding.Status, String?) = {
                    switch outcome {
                    case .pass: return (.pass, nil)
                    case .fail(let r): return (.fail, r)
                    case .unknown(let r): return (.unknown, r)
                    }
                }()
                findings.append(Finding(
                    ruleID: rule.id, title: rule.title, severity: rule.severity, status: status, reason: reason,
                    managed: managedBy != nil, managedBy: managedBy, managementUnknown: managementUnknown,
                    fixable: status == .fail && rule.remediation.automatic && managedBy == nil && !managementUnknown,
                    guidance: status == .pass ? nil : rule.remediation.guidance,
                    mappings: rule.mappings,
                    accepted: accepted
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
