import FarrierCore
import Foundation

/// Identifiers shared by the CLI (the app's main executable) and the root helper.
public enum HelperConstants {
    public static let appIdentifier = "dev.farrier.app"        // signing identifier of the CLI / Farrier.app
    public static let helperIdentifier = "dev.farrier.helper"  // signing identifier of the helper
    public static let machService = "dev.farrier.helper"       // launchd label and Mach service
    public static let daemonPlist = "dev.farrier.helper.plist" // Farrier.app/Contents/Library/LaunchDaemons/
    /// Bumped when the XPC protocol changes incompatibly.
    public static let protocolVersion = 3
    /// What the version handshake compares: the build version AND the protocol, so a protocol change restarts a
    /// running helper even when the version string stays the same (as it does between development builds).
    public static var handshakeVersion: String { "\(FarrierVersion.string)+p\(protocolVersion)" }

    /// The helper's authorization right for enrolling or revoking the approval key (rule: authenticate-admin).
    public static let enrollRight = "dev.farrier.enroll-approval-key"
    /// Root-owned state: the enrolled public key and the helper's journal.
    public static let stateDirectory = "/Library/Application Support/Farrier"
    public static var approvalKeyPath: String { stateDirectory + "/approval-key.pub" }
    public static var helperJournalPath: String { stateDirectory + "/journal.jsonl" }
}

/// The code requirement each side pins its peer to: an Apple-issued certificate, the exact identifier, and the
/// same Team ID as the running binary (read from its own signature, so nothing is hardcoded).
public func codeRequirement(identifier: String, teamID: String) -> String {
    "anchor apple generic and identifier \"\(identifier)\" and certificate leaf[subject.OU] = \"\(teamID)\""
}

/// Facts the helper may read. A fixed allowlist: the helper takes fact identifiers, never paths
/// (THREAT_MODEL.md, T-2), and returns derived facts, never raw file contents.
public enum PrivilegedFact: String, CaseIterable, Sendable {
    /// Payload types of the computer-level configuration profiles (`profiles show` needs root).
    case mdmPayloadTypes = "mdm.payloadTypes"
    /// TCP ports listening on non-loopback addresses (`netstat` as root). Since macOS 27, an unprivileged
    /// third-party process sees only its own sockets, so the CLI's own attempt comes back empty.
    case listeningTCP = "network.listeningTCP"
    /// Whether Farrier.app has Full Disk Access (the helper opens a file only that grant allows).
    case fullDiskAccess = "helper.fullDiskAccess"
    /// Allowed grants for the most far-reaching privacy services, from the system TCC.db (`PrivacyGrants`).
    case tccGrants = "tcc.grants"

    /// Facts the helper can only read with Full Disk Access. Without it they're reported as missing for that
    /// reason (never as an empty value), so rules that use them come out unknown rather than passed.
    public var needsFullDiskAccess: Bool {
        switch self {
        case .tccGrants: return true
        case .mdmPayloadTypes, .listeningTCP, .fullDiskAccess: return false
        }
    }
}

// MARK: - Wire format (JSON over XPC)

public struct HelperInfo: Codable, Sendable {
    public let version: String
    public let protocolVersion: Int
    public let pid: Int
    public let euid: Int
    /// True when the client's version differs: the helper replies, then exits, and launchd starts the new one.
    public let willExit: Bool

    public init(version: String, protocolVersion: Int, pid: Int, euid: Int, willExit: Bool) {
        self.version = version
        self.protocolVersion = protocolVersion
        self.pid = pid
        self.euid = euid
        self.willExit = willExit
    }
}

/// How the helper sees the caller, and whether it accepts it (console-session check).
public struct SessionDecision: Codable, Sendable {
    public let accepted: Bool
    public let reasons: [String]
    public let callerEUID: Int
    public let consoleUser: String
    public let sessionBits: String

    public init(accepted: Bool, reasons: [String], callerEUID: Int, consoleUser: String, sessionBits: String) {
        self.accepted = accepted
        self.reasons = reasons
        self.callerEUID = callerEUID
        self.consoleUser = consoleUser
        self.sessionBits = sessionBits
    }
}

public struct PrivilegedReply: Codable, Sendable {
    public let fact: String
    public let value: FactValue?
    /// Set when the helper refused (unknown fact, wrong session) or the read failed.
    public let error: String?
    /// True when the fact needs Full Disk Access and Farrier.app doesn't have it (`error` says so too).
    public let needsFullDiskAccess: Bool?

    public init(fact: String, value: FactValue?, error: String?, needsFullDiskAccess: Bool? = nil) {
        self.fact = fact
        self.value = value
        self.error = error
        self.needsFullDiskAccess = needsFullDiskAccess
    }
}

/// `approvalKeyStatus`: is a key enrolled, and which one (SHA-256 of its DER encoding).
public struct ApprovalKeyStatus: Codable, Sendable {
    public let enrolled: Bool
    public let fingerprint: String?
    public let error: String?

    public init(enrolled: Bool, fingerprint: String?, error: String?) {
        self.enrolled = enrolled
        self.fingerprint = fingerprint
        self.error = error
    }
}

/// `beginApproval`: a grant, or why there is none.
public struct BeginApprovalReply: Codable, Sendable {
    public let grant: ApprovalGrant?
    public let error: String?

    public init(grant: ApprovalGrant?, error: String?) {
        self.grant = grant
        self.error = error
    }
}

public struct ItemResult: Codable, Sendable, Equatable {
    public enum Outcome: String, Codable, Sendable {
        case applied, alreadyCompliant, refused, failed
    }
    public let ruleID: String
    public let action: String
    public let outcome: Outcome
    public let detail: String?

    public init(ruleID: String, action: String, outcome: Outcome, detail: String?) {
        self.ruleID = ruleID
        self.action = action
        self.outcome = outcome
        self.detail = detail
    }
}

/// `applyPlan`: per-item results, or why the whole plan was refused (then `results` is empty).
public struct ApplyReply: Codable, Sendable {
    public let planID: String
    public let results: [ItemResult]
    public let error: String?

    public init(planID: String, results: [ItemResult], error: String?) {
        self.planID = planID
        self.results = results
        self.error = error
    }
}

public enum HelperWire {
    public static func encode<T: Encodable>(_ value: T) -> Data {
        (try? JSONEncoder().encode(value)) ?? Data("{}".utf8)
    }

    public static func decode<T: Decodable>(_ type: T.Type, _ data: Data) -> T? {
        try? JSONDecoder().decode(type, from: data)
    }
}

#if os(macOS)
/// The XPC interface. Every call carries the client's version (handshake). Replies are JSON (`HelperWire`).
@objc public protocol FarrierHelperProtocol {
    func hello(clientVersion: String, reply: @escaping (Data) -> Void)
    func whoAmI(clientVersion: String, reply: @escaping (Data) -> Void)
    func readPrivileged(fact: String, clientVersion: String, reply: @escaping (Data) -> Void)

    // Approval key (docs/ARCHITECTURE.md, "Enrollment"). `authorization` is an AuthorizationExternalForm; the helper
    // asks for `HelperConstants.enrollRight` with interaction allowed, which shows the admin dialog.
    func approvalKeyStatus(clientVersion: String, reply: @escaping (Data) -> Void)
    func enrollApprovalKey(publicKey: Data, authorization: Data, clientVersion: String, reply: @escaping (Data) -> Void)
    func revokeApprovalKey(authorization: Data, clientVersion: String, reply: @escaping (Data) -> Void)

    // Plans (docs/ARCHITECTURE.md, "Approval flow"). `applyPlan` takes the plan's canonical bytes, the signed
    // payload and its signature, and carries out only `RemediationCatalog` actions. Verifying and applying are one
    // call, so an approval can never be detached from the plan it covers.
    func beginApproval(planHash: Data, clientVersion: String, reply: @escaping (Data) -> Void)
    func applyPlan(plan: Data, payload: Data, signature: Data, clientVersion: String, reply: @escaping (Data) -> Void)
}
#endif
