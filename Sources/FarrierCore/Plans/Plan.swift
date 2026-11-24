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
    /// Only for actions that take them (exceptions: team ID, identifier, reason). Validated by the catalog when the
    /// plan is decoded and again by the helper; absent from the JSON otherwise, so older plans hash the same.
    public let parameters: [String: String]?

    public init(ruleID: String, action: String, tier: Tier, summary: String, fact: String, observed: FactValue,
                parameters: [String: String]? = nil) {
        self.ruleID = ruleID
        self.action = action
        self.tier = tier
        self.summary = summary
        self.fact = fact
        self.observed = observed
        self.parameters = parameters
    }

    /// What the item does, from the catalog and the validated parameters: the text for the listing and the prompt.
    public var description: String {
        guard let action = RemediationCatalog.action(self.action) else { return "unknown change \(self.action)" }
        if action.reverses != nil {
            guard let reverted = try? UndoRules.validate(parameters) else { return action.summary }
            return "\(action.summary) (undoes plan \(reverted.prefix(8)))"
        }
        if action.id == RemediationCatalog.cleanupQuarantine.id {
            guard let p = try? CleanupItemRules.validate(parameters) else { return action.summary }
            return "\(action.summary): \(p.path)"
        }
        guard action.takesParameters, let p = try? ExceptionRules.validate(ruleID: ruleID, parameters,
                                                                            requireReason: action.id == RemediationCatalog.exceptionAdd.id) else {
            return action.summary
        }
        let scope = "team \(p.teamID)" + (p.identifier.map { ", identifier \($0)" } ?? "")
        switch action.id {
        case RemediationCatalog.exceptionAdd.id:
            return "\(action.summary): accept items signed by \(scope) for \(ruleID) (\"\(p.reason)\")"
        default:
            return "\(action.summary): \(scope) for \(ruleID)"
        }
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
        guard !plan.items.isEmpty else { throw PlanError("plan has no items") }
        // Everything shown to the user (listing, prompt) must come from the catalog, not from the file: a process
        // that can edit a saved plan must not be able to describe one change and have another approved.
        for item in plan.items {
            guard let action = RemediationCatalog.action(item.action) else {
                throw PlanError("unknown action `\(item.action)`: the plan was probably made by a newer Farrier "
                                + "(this is \(FarrierVersion.string)); apply it with the farrier that made it")
            }
            guard item.tier == action.tier else {
                throw PlanError("`\(item.action)` is \(action.tier.rawValue), but the plan says \(item.tier.rawValue)")
            }
            guard item.summary == action.summary, item.fact == action.fact else {
                throw PlanError("`\(item.action)`'s description in the plan does not match Farrier's")
            }
            if action.reverses != nil {
                _ = try UndoRules.validate(item.parameters)
            } else if action.id == RemediationCatalog.cleanupQuarantine.id {
                _ = try CleanupItemRules.validate(item.parameters)
            } else if action.takesParameters {
                _ = try ExceptionRules.validate(ruleID: item.ruleID, item.parameters,
                                                requireReason: action.id == RemediationCatalog.exceptionAdd.id)
            } else if item.parameters != nil {
                throw PlanError("`\(item.action)` takes no parameters")
            }
        }
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
    /// Declaration types (Declarative Device Management) that can own the setting. Declarations can't be read yet,
    /// so the helper refuses these actions on any MDM-enrolled Mac (only MDM can deliver declarations).
    public let managedDeclarationTypes: [String]
    /// Managed preference keys that override the setting (any profile can set them, e.g. Custom Settings): the
    /// helper refuses when one is set.
    public let managedPreference: ManagedBy?
    public let summary: String
    /// For an undo action: the action it reverses. Undo actions only restore what the helper's journal says that
    /// action changed (the helper checks), so they can't be used to weaken a setting Farrier didn't change.
    public var reverses: String? = nil
    /// Exceptions carry their scope as parameters, undo actions the plan they reverse; everything else is fully
    /// described by the action.
    public var takesParameters: Bool { id.hasPrefix("exception.") || id.hasPrefix("cleanup.") || reverses != nil }
}

public enum RemediationCatalog {
    public static let firewallEnable = RemediationAction(
        id: "firewall.enable", tier: .t4, fact: "firewall.globalState", compliantValues: ["on", "blockAll"],
        managedPayloadTypes: ["com.apple.security.firewall"], managedDeclarationTypes: [],
        managedPreference: ManagedBy(preference: "com.apple.security.firewall", keys: ["EnableFirewall"]),
        summary: "Turn on the application firewall"
    )

    public static let firewallStealthEnable = RemediationAction(
        id: "firewall.stealthEnable", tier: .t4, fact: "firewall.stealthMode", compliantValues: ["on"],
        managedPayloadTypes: ["com.apple.security.firewall"], managedDeclarationTypes: [],
        managedPreference: ManagedBy(preference: "com.apple.security.firewall", keys: ["EnableStealthMode"]),
        summary: "Turn on the firewall's stealth mode (no replies to pings and probes)"
    )

    /// Accepting or withdrawing an exception changes what posture reports, so it's approved like a system setting.
    public static let exceptionAdd = RemediationAction(
        id: "exception.add", tier: .t4, fact: "launchd.items", compliantValues: [], managedPayloadTypes: [],
        managedDeclarationTypes: [], managedPreference: nil, summary: "Add a posture exception"
    )
    public static let exceptionRemove = RemediationAction(
        id: "exception.remove", tier: .t4, fact: "launchd.items", compliantValues: [], managedPayloadTypes: [],
        managedDeclarationTypes: [], managedPreference: nil, summary: "Remove a posture exception"
    )

    public static let gatekeeperEnable = RemediationAction(
        id: "gatekeeper.enable", tier: .t4, fact: "gatekeeper.assessments", compliantValues: ["enabled"],
        managedPayloadTypes: ["com.apple.systempolicy.control"], managedDeclarationTypes: [],
        managedPreference: ManagedBy(preference: "com.apple.systempolicy.control", keys: ["EnableAssessment"]),
        summary: "Turn on Gatekeeper (only run apps from the App Store and identified developers)"
    )

    /// Sets CriticalUpdateInstall and ConfigDataInstall in /Library/Preferences/com.apple.SoftwareUpdate.plist.
    public static let securityAutoInstall = RemediationAction(
        id: "softwareupdate.enableSecurityAutoInstall", tier: .t4, fact: "softwareupdate.prefs", compliantValues: [],
        managedPayloadTypes: ["com.apple.SoftwareUpdate"],
        managedDeclarationTypes: ["com.apple.configuration.softwareupdate.settings"],
        managedPreference: ManagedBy(preference: "com.apple.SoftwareUpdate", keys: ["CriticalUpdateInstall", "ConfigDataInstall"]),
        summary: "Install Security Responses and system data files automatically"
    )
    /// The keys `securityAutoInstall` sets to true.
    public static let securityAutoInstallKeys = ["CriticalUpdateInstall", "ConfigDataInstall"]

    // Undo: each restores the state recorded when the forward action was applied (T4 too, approved the same way).
    public static let firewallRestore = undo(firewallEnable, id: "firewall.restore",
                                             summary: "Undo: turn the application firewall off again")
    public static let firewallStealthRestore = undo(firewallStealthEnable, id: "firewall.stealthRestore",
                                                    summary: "Undo: turn the firewall's stealth mode off again")
    public static let securityAutoInstallRestore = undo(securityAutoInstall, id: "softwareupdate.restoreSecurityAutoInstall",
                                                        summary: "Undo: restore the previous automatic security update settings")

    private static func undo(_ forward: RemediationAction, id: String, summary: String) -> RemediationAction {
        var a = RemediationAction(id: id, tier: forward.tier, fact: forward.fact, compliantValues: [],
                                  managedPayloadTypes: forward.managedPayloadTypes,
                                  managedDeclarationTypes: forward.managedDeclarationTypes,
                                  managedPreference: forward.managedPreference, summary: summary)
        a.reverses = forward.id
        return a
    }

    /// Moves one cleanup candidate into the user's quarantine (restorable for 7 days). Applied in-process, not by the
    /// helper: it only moves the user's own files, and re-checks each against its cleanup rule first.
    public static let cleanupQuarantine = RemediationAction(
        id: "cleanup.quarantine", tier: .t2, fact: "cleanup.candidates", compliantValues: [], managedPayloadTypes: [],
        managedDeclarationTypes: [], managedPreference: nil, summary: "Move to Farrier's quarantine"
    )

    public static let all: [RemediationAction] = [firewallEnable, firewallStealthEnable, gatekeeperEnable, securityAutoInstall,
                                                  exceptionAdd, exceptionRemove, cleanupQuarantine,
                                                  firewallRestore, firewallStealthRestore, securityAutoInstallRestore]

    /// The undo action for `actionID`, if Farrier can undo it.
    public static func undo(of actionID: String) -> RemediationAction? { all.first { $0.reverses == actionID } }

    /// Why an applied action has no undo, in words for the user.
    public static func noUndoReason(_ actionID: String) -> String {
        switch actionID {
        case gatekeeperEnable.id:
            return "Farrier doesn't turn Gatekeeper off; if you need to, it's in System Settings → Privacy & Security"
        case exceptionAdd.id:
            return "withdraw the exception with `farrier exceptions remove`"
        case exceptionRemove.id:
            return "accept it again with `farrier exceptions add`"
        case cleanupQuarantine.id:
            return "put it back from the quarantine with `farrier restore`"
        default:
            return "Farrier can't undo `\(actionID)`"
        }
    }

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
        // Only packs that ship with Farrier can lead to a change; user packs can report, never fix.
        var rules: [String: CheckRule] = [:]
        var fromUserPacks: Set<String> = []
        for pack in packs {
            for case .check(let rule) in pack.rules {
                if pack.source == .bundled { rules[rule.id] = rule } else { fromUserPacks.insert(rule.id) }
            }
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
                    let profile = finding.managedByProfile.map { ", profile \($0)" } ?? ""
                    // A Mac that isn't MDM-enrolled can still have profiles installed by hand.
                    let enrolled = facts.value(for: CoreFacts.enrollment)?.object?["mdm"]
                    let where_ = enrolled == .bool(false)
                        ? "change or remove the profile (System Settings → General → Device Management)"
                        : "change it in your MDM"
                    reason = "managed by \(finding.managedBy ?? "MDM")\(profile): \(where_)"
                } else if finding.managementUnknown {
                    reason = "whether MDM manages it could not be checked (profiles need the privileged helper; declarations "
                        + "can't be read on an MDM-enrolled Mac yet), so Farrier won't change it"
                } else {
                    reason = "no automatic fix: \(finding.guidance?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "see the rule's guidance")"
                }
                skipped.append(PlanSkip(ruleID: finding.ruleID, reason: reason))
                continue
            }
            if fromUserPacks.contains(finding.ruleID) && rules[finding.ruleID] == nil {
                skipped.append(PlanSkip(ruleID: finding.ruleID, reason: "the rule comes from a user pack; only Farrier's own packs can plan fixes"))
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

    /// Why an action's setting mustn't be changed locally now (managed, or management can't be checked), from the
    /// same inventories the posture engine uses; nil if it may be. The helper checks again before acting.
    static func managementSkipReason(_ action: RemediationAction, _ facts: FactStore) -> String? {
        func inventory(_ fact: String) -> Set<String>? {
            guard let list = facts.value(for: fact)?.array else { return nil }
            let strings = list.compactMap(\.string)
            return strings.count == list.count ? Set(strings) : nil
        }
        let unknown = "whether MDM manages it could not be checked, so Farrier won't change it"
        if !action.managedPayloadTypes.isEmpty {
            guard let payloads = inventory(CoreFacts.profilePayloadTypes) else { return unknown }
            if let type = action.managedPayloadTypes.first(where: payloads.contains) {
                return "managed by \(type) now: change it in the profile or MDM"
            }
        }
        if !action.managedDeclarationTypes.isEmpty {
            guard let declarations = inventory(CoreFacts.declarationTypes) else { return unknown }
            if let type = action.managedDeclarationTypes.first(where: declarations.contains) {
                return "managed by \(type) now: change it in your MDM"
            }
        }
        if let mp = action.managedPreference, let domain = mp.preference {
            guard let prefs = PostureEngine.managedPreferences(facts) else { return unknown }
            let set = (mp.keys ?? []).filter { prefs[domain]?.contains($0) ?? false }
            if !set.isEmpty { return "managed preferences \(domain) (\(set.joined(separator: ", "))) now: change it in the profile" }
        }
        return nil
    }
}

// MARK: - Exception plans

extension Planner {
    /// Plans adding an exception. It must cover at least one current item that is validly signed by the team, and
    /// not exist already. `observed` records which items it covers, so the reviewer sees what they accept.
    public static func planException(ruleID: String, teamID: String, identifier: String?, reason: String,
                                     facts: FactStore, existing: [PostureException], host: String, now: Date = Date(),
                                     ttl: Int64 = Plan.defaultTTL, id: String = UUID().uuidString.lowercased()) throws -> Plan {
        let parameters = ExceptionRules.parameters(teamID: teamID, identifier: identifier, reason: reason)
        let p = try ExceptionRules.validate(ruleID: ruleID, parameters)
        let candidate = PostureException(ruleID: ruleID, teamID: p.teamID, identifier: p.identifier, reason: p.reason,
                                         acceptedAt: 0, planID: id)
        guard !existing.contains(where: { $0.sameScope(as: candidate) }) else {
            throw PlanError("that exception already exists")
        }
        let action = RemediationCatalog.exceptionAdd
        let items = facts.value(for: action.fact)?.array ?? []
        let covered = items.filter(candidate.matches)
        guard !covered.isEmpty else {
            throw PlanError("no current \(action.fact) item has a valid signature by team \(p.teamID)"
                            + (p.identifier.map { " with identifier \($0)" } ?? ""))
        }
        let labels = covered.map { FactValue.string($0.object?["label"]?.string ?? $0.object?["plist"]?.string ?? "item") }
        let item = PlanItem(ruleID: ruleID, action: action.id, tier: action.tier, summary: action.summary, fact: action.fact,
                            observed: .array(labels), parameters: parameters)
        let created = Int64(now.timeIntervalSince1970)
        return Plan(id: id, createdAt: created, expiresAt: created + ttl, host: host, items: [item])
    }

    /// Plans removing an existing exception.
    public static func planExceptionRemoval(ruleID: String, teamID: String, identifier: String?, existing: [PostureException],
                                            host: String, now: Date = Date(), ttl: Int64 = Plan.defaultTTL,
                                            id: String = UUID().uuidString.lowercased()) throws -> Plan {
        var parameters = ["teamID": teamID]
        if let identifier { parameters["identifier"] = identifier }
        let p = try ExceptionRules.validate(ruleID: ruleID, parameters, requireReason: false)
        guard let match = existing.first(where: { $0.ruleID == ruleID && $0.teamID == p.teamID && $0.identifier == p.identifier }) else {
            throw PlanError("no such exception")
        }
        let action = RemediationCatalog.exceptionRemove
        let item = PlanItem(ruleID: ruleID, action: action.id, tier: action.tier, summary: action.summary, fact: action.fact,
                            observed: .string(match.reason), parameters: parameters)
        let created = Int64(now.timeIntervalSince1970)
        return Plan(id: id, createdAt: created, expiresAt: created + ttl, host: host, items: [item])
    }
}

// MARK: - Undo

/// The one parameter an undo item takes: the id of the plan it reverses.
public enum UndoRules {
    public static func validate(_ parameters: [String: String]?) throws -> String {
        guard let parameters, parameters.count == 1, let planID = parameters["reverts"] else {
            throw PlanError("an undo item takes exactly one parameter, `reverts`")
        }
        guard planID.count == 36, UUID(uuidString: planID) != nil, planID == planID.lowercased() else {
            throw PlanError("`reverts` must be a plan id")
        }
        return planID
    }
}

extension Planner {
    /// Plans undoing what plan `planID` changed, from the helper's journal. Each change it applied that Farrier can
    /// undo becomes an undo item, observed at its current state; anything else is listed with the reason.
    public static func planUndo(planID: String, journal: [JournalRecord], facts: FactStore, host: String,
                                now: Date = Date(), ttl: Int64 = Plan.defaultTTL,
                                id: String = UUID().uuidString.lowercased()) throws -> (plan: Plan?, skipped: [PlanSkip]) {
        let applied = journal.filter { $0.planID == planID && $0.outcome == "applied" && $0.action != nil && $0.ruleID != nil }
        guard !applied.isEmpty else { throw PlanError("the helper's journal has no change applied by plan \(planID.prefix(8))") }
        var items: [PlanItem] = []
        var skipped: [PlanSkip] = []
        for record in applied {
            let ruleID = record.ruleID!, actionID = record.action!
            if let reverse = RemediationCatalog.action(actionID), reverse.reverses != nil {
                skipped.append(PlanSkip(ruleID: ruleID, reason: "this was itself an undo; plan the fix again instead"))
                continue
            }
            guard let undo = RemediationCatalog.undo(of: actionID) else {
                skipped.append(PlanSkip(ruleID: ruleID, reason: RemediationCatalog.noUndoReason(actionID)))
                continue
            }
            if journal.contains(where: { $0.reverts == planID && $0.ruleID == ruleID && $0.action == undo.id && $0.outcome == "applied" }) {
                skipped.append(PlanSkip(ruleID: ruleID, reason: "already undone"))
                continue
            }
            guard record.previous != nil else {
                skipped.append(PlanSkip(ruleID: ruleID, reason: "the journal has no earlier state for it (applied by an older Farrier)"))
                continue
            }
            if let reason = managementSkipReason(undo, facts) {
                skipped.append(PlanSkip(ruleID: ruleID, reason: reason))
                continue
            }
            guard let observed = facts.value(for: undo.fact) else {
                skipped.append(PlanSkip(ruleID: ruleID, reason: "`\(undo.fact)` could not be read"))
                continue
            }
            items.append(PlanItem(ruleID: ruleID, action: undo.id, tier: undo.tier, summary: undo.summary, fact: undo.fact,
                                  observed: observed, parameters: ["reverts": planID]))
        }
        guard !items.isEmpty else { return (nil, skipped) }
        let created = Int64(now.timeIntervalSince1970)
        return (Plan(id: id, createdAt: created, expiresAt: created + ttl, host: host, items: items), skipped)
    }
}
