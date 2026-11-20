import CryptoKit
import Foundation
import Security

// MARK: - Constants

public enum Spike {
    public static let appBundleID = "dev.farrier.spike.app"          // the client (app main executable)
    public static let helperID = "dev.farrier.spike.helper"          // the helper's signing identifier
    public static let machService = "dev.farrier.spike.helper"       // launchd label and Mach service name
    public static let daemonPlist = "dev.farrier.spike.helper.plist" // in Contents/Library/LaunchDaemons
    public static let enrollRight = "dev.farrier.spike.enroll-approval-key"
    public static let keychainService = "dev.farrier.spike2.approval"
    public static let keychainAccount = "approval"
    public static let keychainLabel = "Farrier spike approval key — Farrier never asks for this. Click Deny."
    public static let stateDir = "/Library/Application Support/FarrierSpike"
    public static var enrolledKeyPath: String { stateDir + "/approval-key.pub" }
    public static let approvalTTL: Int64 = 60  // seconds; short so the expiry test is quick
}

// MARK: - XPC protocol

/// Every reply is a JSON object encoded as Data. That keeps the protocol trivial to extend and to log.
@objc public protocol HelperProtocol {
    func ping(reply: @escaping (Data) -> Void)
    /// How the helper sees the caller: pid, euid, audit session, and the console-session decision.
    func whoAmI(reply: @escaping (Data) -> Void)
    /// Registers the approval public key. Needs admin authorization (AuthorizationExternalForm from the client).
    func enroll(publicKey: Data, authorization: Data, reply: @escaping (Data) -> Void)
    /// Issues a one-time nonce for one approval of `planHash`.
    func beginApproval(planHash: Data, reply: @escaping (Data) -> Void)
    /// Verifies a signed approval payload against the enrolled key and the issued nonce.
    func submitApproval(payload: Data, signature: Data, reply: @escaping (Data) -> Void)
    /// Removes the enrolled key. Needs admin authorization.
    func reset(authorization: Data, reply: @escaping (Data) -> Void)
    /// Runs the TCC probe as the root helper (MCP SDK spike, test M7). `home` is the caller's home directory.
    func tccProbe(home: String, reply: @escaping (Data) -> Void)
}

// MARK: - JSON

public func encodeJSON(_ d: [String: Any]) -> Data {
    (try? JSONSerialization.data(withJSONObject: d, options: [.sortedKeys]))
        ?? Data("{\"ok\":false,\"error\":\"unserializable reply\"}".utf8)
}

public func decodeJSON(_ data: Data) -> [String: Any] {
    ((try? JSONSerialization.jsonObject(with: data)) as? [String: Any]) ?? ["ok": false, "error": "undecodable reply"]
}

public func printJSON(_ step: String, _ d: [String: Any]) {
    var o = d
    o["step"] = step
    print(String(decoding: encodeJSON(o), as: UTF8.self))
}

// MARK: - Errors

public struct SpikeError: Error, CustomStringConvertible {
    public let description: String
    public init(_ description: String) { self.description = description }
}

public struct OSStatusError: Error, CustomStringConvertible {
    public let status: OSStatus
    public let context: String
    public init(_ status: OSStatus, _ context: String) { self.status = status; self.context = context }
    public var description: String {
        let msg = (SecCopyErrorMessageString(status, nil) as String?) ?? "unknown"
        return "\(context): OSStatus \(status) (\(msg))"
    }
}

public func describe(_ error: Error) -> [String: Any] {
    var d: [String: Any] = ["ok": false, "error": String(describing: error)]
    if let e = error as? OSStatusError { d["osstatus"] = Int(e.status) }
    else if !(error is SpikeError) { let ns = error as NSError; d["domain"] = ns.domain; d["code"] = ns.code }
    return d
}

// MARK: - Data helpers

extension Data {
    public var hex: String { map { String(format: "%02x", $0) }.joined() }

    public init?(hex: String) {
        let chars = Array(hex.utf8)
        guard chars.count % 2 == 0 else { return nil }
        var bytes = [UInt8]()
        var i = 0
        while i < chars.count {
            guard let b = UInt8(String(decoding: chars[i..<(i + 2)], as: UTF8.self), radix: 16) else { return nil }
            bytes.append(b)
            i += 2
        }
        self.init(bytes)
    }

    public static func random(_ count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        precondition(SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess)
        return Data(bytes)
    }
}

public func sha256Hex(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

// MARK: - Code signing

public struct SigningIdentity {
    public let identifier: String?
    public let teamID: String?

    /// The signing identifier and Team ID of the running binary.
    public static func current() -> SigningIdentity {
        var code: SecCode?
        var staticCode: SecStaticCode?
        var cfInfo: CFDictionary?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
              SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &cfInfo) == errSecSuccess,
              let info = cfInfo as? [String: Any]
        else { return SigningIdentity(identifier: nil, teamID: nil) }
        return SigningIdentity(
            identifier: info[kSecCodeInfoIdentifier as String] as? String,
            teamID: info[kSecCodeInfoTeamIdentifier as String] as? String
        )
    }
}

/// The code requirement each side pins its peer to: Apple-issued certificate, exact identifier, same Team ID.
/// The Team ID comes from the running binary's own signature, so nothing is hardcoded.
public func codeRequirement(identifier: String, teamID: String) -> String {
    "anchor apple generic and identifier \"\(identifier)\" and certificate leaf[subject.OU] = \"\(teamID)\""
}

// MARK: - Approval payload (same format as the Secure Enclave spike)

public enum ApprovalPayload {
    public static let domain = "farrier-plan-approval-v1"

    public static func build(planHash: Data, nonce: Data, expiresAt: Int64) -> Data {
        var d = Data(domain.utf8)
        d.append(0)
        d.append(planHash)
        d.append(nonce)
        withUnsafeBytes(of: expiresAt.bigEndian) { d.append(contentsOf: $0) }
        return d
    }

    public static func parse(_ data: Data) throws -> (planHash: Data, nonce: Data, expiresAt: Int64) {
        let prefix = Data(domain.utf8) + Data([0])
        guard data.count == prefix.count + 32 + 32 + 8, data.prefix(prefix.count) == prefix else {
            throw SpikeError("payload has the wrong domain or length")
        }
        var i = data.startIndex + prefix.count
        let planHash = Data(data[i..<(i + 32)]); i += 32
        let nonce = Data(data[i..<(i + 32)]); i += 32
        let exp = data[i..<(i + 8)].reduce(Int64(0)) { ($0 << 8) | Int64($1) }
        return (planHash, nonce, exp)
    }
}

// MARK: - Authorization Services

/// Asks the authorization system for one right. With `.interactionAllowed`, this shows the admin dialog.
public func copyRight(_ ref: AuthorizationRef, _ name: String, _ flags: AuthorizationFlags) -> OSStatus {
    name.withCString { cName in
        var item = AuthorizationItem(name: cName, valueLength: 0, value: nil, flags: 0)
        return withUnsafeMutablePointer(to: &item) { itemPtr in
            var rights = AuthorizationRights(count: 1, items: itemPtr)
            return AuthorizationCopyRights(ref, &rights, nil, flags, nil)
        }
    }
}
