import Foundation

extension Tier: Comparable {
    public static func < (a: Tier, b: Tier) -> Bool {
        allCases.firstIndex(of: a)! < allCases.firstIndex(of: b)!
    }

    /// T3 and T4 need an on-device approval that the helper verifies (docs/ARCHITECTURE.md, "Approve").
    public var needsApproval: Bool { self >= .t3 }
}

/// One change in a plan. It records what was observed when planning, so the reviewer sees why it's there and
/// the helper can tell when the Mac has changed since.
public struct PlanItem: Codable, Sendable, Equatable {
    public let ruleID: String
    /// A `RemediationCatalog` action, e.g. `firewall.enable`.
    public let action: String
    public let tier: Tier
    public let summary: String
    /// The fact the rule checks, and its value at planning time.
    public let fact: String
    public let observed: FactValue

    public init(ruleID: String, action: String, tier: Tier, summary: String, fact: String, observed: FactValue) {
        self.ruleID = ruleID
        self.action = action
        self.tier = tier
        self.summary = summary
        self.fact = fact
        self.observed = observed
    }
}

/// A reviewed, hashable list of changes (docs/ARCHITECTURE.md, "Plan, approve, apply").
///
/// `planHash` is the SHA-256 of the canonical encoding: JSON with sorted keys, no escaped slashes, times as
/// integer seconds. The helper re-encodes what it receives and refuses anything that isn't byte-identical, so
/// unknown keys or a different key order can't change what an approval covers.
public struct Plan: Codable, Sendable, Equatable {
    public static let currentFormat = 1
    public static let defaultTTL: Int64 = 15 * 60

    public let format: Int
    public let id: String
    public let createdAt: Int64
    public let expiresAt: Int64
    /// The Mac's hardware UUID: a plan never applies on another machine.
    public let host: String
    public let tier: Tier
    public let items: [PlanItem]

    public init(id: String, createdAt: Int64, expiresAt: Int64, host: String, items: [PlanItem]) {
        self.format = Plan.currentFormat
        self.id = id
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.host = host
        self.tier = items.map(\.tier).max() ?? .t0
        self.items = items
    }

    public func canonicalData() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(self)
    }

    public func hash() throws -> Data { FarrierCrypto.sha256(try canonicalData()) }

    /// Decodes a plan and checks that `data` is exactly its canonical encoding.
    public static func decodeCanonical(_ data: Data) throws -> Plan {
        let plan = try JSONDecoder().decode(Plan.self, from: data)
        guard try plan.canonicalData() == data else { throw PlanError("plan is not in canonical form") }
        guard plan.format == currentFormat else { throw PlanError("unsupported plan format \(plan.format)") }
        guard plan.tier == (plan.items.map(\.tier).max() ?? .t0) else { throw PlanError("plan tier does not match its items") }
        return plan
    }

    /// The first 8 hex characters of the hash: what prompts and listings show.
    public func shortHash() -> String { ((try? hash()) ?? Data()).hexString.prefix(8).description }
}

public struct PlanError: Error, CustomStringConvertible, Sendable {
    public let description: String
    public init(_ description: String) { self.description = description }
}

// MARK: - Remediation catalog

/// A change Farrier knows how to make. Only actions listed here can be planned, and the helper carries out only
/// these (by identifier; it takes no commands, paths or values from the client).
public struct RemediationAction: Sendable, Equatable {
    public let id: String
    public let tier: Tier
    /// The fact that shows whether the change is needed, and the values that mean "already compliant".
    public let fact: String
    public let compliantValues: [String]
    /// Payload types whose presence means MDM owns the setting: the helper then refuses to touch it.
    public let managedPayloadTypes: [String]
    public let summary: String
}

public enum RemediationCatalog {
    public static let firewallEnable = RemediationAction(
        id: "firewall.enable", tier: .t4, fact: "firewall.globalState", compliantValues: ["on", "blockAll"],
        managedPayloadTypes: ["com.apple.security.firewall"],
        summary: "Turn on the application firewall"
    )

    public static let all: [RemediationAction] = [firewallEnable]

    public static func action(_ id: String) -> RemediationAction? { all.first { $0.id == id } }
}

// MARK: - Planner

public struct PlanSkip: Codable, Sendable, Equatable {
    public let ruleID: String
    public let reason: String

    public init(ruleID: String, reason: String) {
        self.ruleID = ruleID
        self.reason = reason
    }
}

/// Turns failing, fixable findings into a plan. Everything left out is listed with the reason.
public enum Planner {
    public static func plan(report: PostureReport, packs: [RulePack], facts: FactStore, ruleIDs: Set<String>? = nil,
                            host: String, now: Date = Date(), ttl: Int64 = Plan.defaultTTL,
                            id: String = UUID().uuidString.lowercased()) -> (plan: Plan?, skipped: [PlanSkip]) {
        var rules: [String: CheckRule] = [:]
        for pack in packs {
            for case .check(let rule) in pack.rules { rules[rule.id] = rule }
        }
        var items: [PlanItem] = []
        var skipped: [PlanSkip] = []

        if let ruleIDs {
            let known = Set(report.findings.map(\.ruleID))
            for missing in ruleIDs.subtracting(known).sorted() {
                skipped.append(PlanSkip(ruleID: missing, reason: "no such posture rule"))
            }
        }
        for finding in report.findings {
            if let ruleIDs, !ruleIDs.contains(finding.ruleID) { continue }
            switch finding.status {
            case .pass:
                if ruleIDs != nil { skipped.append(PlanSkip(ruleID: finding.ruleID, reason: "already passes")) }
                continue
            case .unknown:
                skipped.append(PlanSkip(ruleID: finding.ruleID, reason: "status unknown: \(finding.reason ?? "not evaluated")"))
                continue
            case .fail:
                break
            }
            guard finding.fixable else {
                let reason: String
                if finding.managed {
                    reason = "managed by \(finding.managedBy ?? "MDM"): change it in your MDM"
                } else if finding.managementUnknown {
                    reason = "MDM profiles could not be checked (the privileged helper is needed), so Farrier won't change it"
                } else {
                    reason = "no automatic fix: \(finding.guidance?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "see the rule's guidance")"
                }
                skipped.append(PlanSkip(ruleID: finding.ruleID, reason: reason))
                continue
            }
            guard let rule = rules[finding.ruleID], let actionID = rule.remediation.action,
                  let action = RemediationCatalog.action(actionID) else {
                let actionID = rules[finding.ruleID]?.remediation.action ?? "?"
                skipped.append(PlanSkip(ruleID: finding.ruleID, reason: "the fix `\(actionID)` is not implemented yet"))
                continue
            }
            guard action.fact == rule.fact, let observed = facts.value(for: rule.fact) else {
                skipped.append(PlanSkip(ruleID: finding.ruleID, reason: "the fix `\(actionID)` does not match the rule's fact"))
                continue
            }
            items.append(PlanItem(ruleID: rule.id, action: action.id, tier: action.tier, summary: action.summary,
                                  fact: rule.fact, observed: observed))
        }
        guard !items.isEmpty else { return (nil, skipped) }
        let created = Int64(now.timeIntervalSince1970)
        return (Plan(id: id, createdAt: created, expiresAt: created + ttl, host: host, items: items), skipped)
    }
}
