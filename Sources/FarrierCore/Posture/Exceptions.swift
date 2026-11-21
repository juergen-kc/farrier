import Foundation

/// An accepted risk: the user decided that a vendor's signed items are acceptable for one rule, even though they
/// fail it (for example Parallels Guest Tools, which are Developer ID–signed but not notarized). Adding one is a T4
/// change, approved on the Mac and written by the helper into a root-owned file, so a process running as the user
/// can't accept its own code.
public struct PostureException: Codable, Sendable, Equatable {
    public let ruleID: String
    /// The Apple Team ID of the signing certificate. Only validly signed items can match.
    public let teamID: String
    /// Narrows it to one signing identifier of that team.
    public let identifier: String?
    public let reason: String
    public let acceptedAt: Int64
    public let planID: String

    public init(ruleID: String, teamID: String, identifier: String?, reason: String, acceptedAt: Int64, planID: String) {
        self.ruleID = ruleID
        self.teamID = teamID
        self.identifier = identifier
        self.reason = reason
        self.acceptedAt = acceptedAt
        self.planID = planID
    }

    /// Does this exception cover an item (a `launchd.items` element)? Only items with a valid signature by the team.
    public func matches(_ item: FactValue) -> Bool {
        guard let sig = item.object?["signature"]?.object, sig["valid"] == .bool(true),
              sig["teamID"]?.string == teamID else { return false }
        if let identifier { return sig["identifier"]?.string == identifier }
        return true
    }

    /// Same rule, team and identifier (the reason and time don't make a different exception).
    public func sameScope(as other: PostureException) -> Bool {
        ruleID == other.ruleID && teamID == other.teamID && identifier == other.identifier
    }
}

/// What an exception can be, checked the same way when it's planned and in the helper before it's stored.
public enum ExceptionRules {
    /// Rules whose fact is a list of signed items: an exception removes a vendor's items from the evaluation.
    public static let supportedRules: Set<String> = ["posture.core.unsigned-launch-items"]

    public struct Parameters: Sendable, Equatable {
        public let teamID: String
        public let identifier: String?
        public let reason: String
    }

    public static func parameters(teamID: String, identifier: String?, reason: String) -> [String: String] {
        var p = ["teamID": teamID, "reason": reason]
        if let identifier { p["identifier"] = identifier }
        return p
    }

    public static func validate(ruleID: String, _ p: [String: String]?, requireReason: Bool = true) throws -> Parameters {
        guard supportedRules.contains(ruleID) else {
            throw PlanError("exceptions aren't supported for \(ruleID) (only \(supportedRules.sorted().joined(separator: ", ")))")
        }
        guard let p else { throw PlanError("an exception needs a team ID and a reason") }
        let allowed: Set<String> = ["teamID", "identifier", "reason"]
        guard Set(p.keys).isSubset(of: allowed) else { throw PlanError("unknown exception parameter(s): \(Set(p.keys).subtracting(allowed).sorted())") }
        guard let team = p["teamID"], team.count == 10, team.allSatisfy({ ("A"..."Z").contains($0) || ("0"..."9").contains($0) }) else {
            throw PlanError("the team ID must be 10 uppercase letters or digits (as in codesign's TeamIdentifier)")
        }
        let identifier = p["identifier"]
        if let identifier {
            guard (1...200).contains(identifier.count),
                  identifier.unicodeScalars.allSatisfy({ CharacterSet.alphanumerics.contains($0) || ".-_".unicodeScalars.contains($0) }) else {
                throw PlanError("the signing identifier may only contain letters, digits, '.', '-' and '_'")
            }
        }
        let reason = p["reason"] ?? ""
        if requireReason {
            guard (3...200).contains(reason.count),
                  !reason.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) || CharacterSet.newlines.contains($0) }) else {
                throw PlanError("the reason must be 3–200 characters on one line")
            }
        }
        return Parameters(teamID: team, identifier: identifier, reason: reason)
    }
}

/// The exceptions file: root-owned, written only by the helper, readable by everyone.
public struct ExceptionStore: Sendable {
    public static let defaultPath = "/Library/Application Support/Farrier/exceptions.json"

    public let path: String
    /// A file that isn't owned by root, or that others can write, is ignored: anyone could have written it.
    public let requireRootOwned: Bool

    public init(path: String = ExceptionStore.defaultPath, requireRootOwned: Bool = true) {
        self.path = path
        self.requireRootOwned = requireRootOwned
    }

    /// The exceptions, or none with a problem. Ignoring a file that can't be trusted only makes posture stricter.
    public func load() -> (exceptions: [PostureException], problem: String?) {
        let fm = FileManager.default
        guard fm.fileExists(atPath: path) else { return ([], nil) }
        if requireRootOwned {
            guard let attrs = try? fm.attributesOfItem(atPath: path),
                  (attrs[.ownerAccountID] as? NSNumber)?.intValue == 0,
                  let mode = (attrs[.posixPermissions] as? NSNumber)?.intValue, mode & 0o022 == 0 else {
                return ([], "\(path) is not root-owned or is writable by others; its exceptions are ignored")
            }
        }
        guard let data = fm.contents(atPath: path) else { return ([], "cannot read \(path)") }
        guard let list = try? JSONDecoder().decode([PostureException].self, from: data) else {
            return ([], "cannot parse \(path); its exceptions are ignored")
        }
        return (list, nil)
    }

    public static func encode(_ exceptions: [PostureException]) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let sorted = exceptions.sorted { ($0.ruleID, $0.teamID, $0.identifier ?? "") < ($1.ruleID, $1.teamID, $1.identifier ?? "") }
        return try encoder.encode(sorted)
    }
}
