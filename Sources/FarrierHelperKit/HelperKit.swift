import FarrierCore
import Foundation

/// Identifiers shared by the CLI (the app's main executable) and the root helper.
public enum HelperConstants {
    public static let appIdentifier = "dev.farrier.app"        // signing identifier of the CLI / Farrier.app
    public static let helperIdentifier = "dev.farrier.helper"  // signing identifier of the helper
    public static let machService = "dev.farrier.helper"       // launchd label and Mach service
    public static let daemonPlist = "dev.farrier.helper.plist" // Farrier.app/Contents/Library/LaunchDaemons/
    /// Bumped when the XPC protocol changes incompatibly.
    public static let protocolVersion = 1
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

    public init(fact: String, value: FactValue?, error: String?) {
        self.fact = fact
        self.value = value
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
}
#endif
