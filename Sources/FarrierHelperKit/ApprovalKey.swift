#if os(macOS)
import CryptoKit
import FarrierCore
import Foundation
import LocalAuthentication
import Security

/// The approval key (docs/ARCHITECTURE.md, "The approval key"; the Secure Enclave spike's Approach C).
///
/// A Secure Enclave P-256 key with `.userPresence`: every signature asks for Touch ID or the login password. Its
/// encrypted blob lives in the **login keychain**, in an item whose access list trusts only Farrier's signing
/// identity, so another binary gets a keychain dialog (and a password request) before it can even reach the
/// signing prompt. The item APIs used here (SecAccess, SecTrustedApplication) are deprecated but still work and
/// need no entitlement.
public enum ApprovalKey {
    static let service = "dev.farrier.approval"
    static let account = "approval"
    /// A new key waits here until the helper has enrolled it, so a cancelled or failed enrollment leaves the
    /// working key (the one the helper trusts) in place.
    static let pendingAccount = "approval.pending"
    /// Keychain dialogs show the label, so it carries the warning (Secure Enclave spike, finding F2).
    static let label = "Farrier approval key — Farrier never asks for this. Click Deny."

    private static func query(_ account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: false,
        ]
    }

    private static var baseQuery: [String: Any] { query(account) }

    public static var isAvailable: Bool { SecureEnclave.isAvailable }

    public static var exists: Bool {
        var q = baseQuery
        q[kSecReturnAttributes as String] = true
        return SecItemCopyMatching(q as CFDictionary, nil) == errSecSuccess
    }

    /// Creates a new key as the PENDING key (replacing an earlier pending one, never the working key) and returns
    /// its public key (DER). `promotePending()` makes it the working key once the helper has enrolled it.
    public static func createPending() throws -> Data {
        guard SecureEnclave.isAvailable else { throw ApprovalKeyError("this Mac has no Secure Enclave") }
        var cfError: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                       [.privateKeyUsage, .userPresence], &cfError) else {
            throw cfError!.takeRetainedValue() as Error
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey(compactRepresentable: false, accessControl: ac)
        _ = SecItemDelete(query(pendingAccount) as CFDictionary)
        try store(key.dataRepresentation, account: pendingAccount)
        return key.publicKey.derRepresentation
    }

    /// Replaces the working key with the pending one. Reading our own item doesn't prompt.
    public static func promotePending() throws {
        let data = try blob(pendingAccount)
        _ = SecItemDelete(baseQuery as CFDictionary)
        try store(data, account: account)
        _ = SecItemDelete(query(pendingAccount) as CFDictionary)
    }

    public static func discardPending() {
        _ = SecItemDelete(query(pendingAccount) as CFDictionary)
    }

    /// Adds the blob as a generic password whose access list trusts only this application.
    private static func store(_ data: Data, account: String) throws {
        var selfApp: SecTrustedApplication?
        var st = SecTrustedApplicationCreateFromPath(nil, &selfApp)  // nil: this application
        guard st == errSecSuccess, let selfApp else { throw ApprovalKeyError(st, "SecTrustedApplicationCreateFromPath") }
        var access: SecAccess?
        st = SecAccessCreate(label as CFString, [selfApp] as CFArray, &access)
        guard st == errSecSuccess, let access else { throw ApprovalKeyError(st, "SecAccessCreate") }

        var attrs = query(account)
        attrs[kSecAttrLabel as String] = label
        attrs[kSecValueData as String] = data
        attrs[kSecAttrAccess as String] = access
        st = SecItemAdd(attrs as CFDictionary, nil)
        guard st == errSecSuccess else { throw ApprovalKeyError(st, "SecItemAdd") }
    }

    public static func delete() throws {
        discardPending()
        let st = SecItemDelete(baseQuery as CFDictionary)
        guard st == errSecSuccess || st == errSecItemNotFound else { throw ApprovalKeyError(st, "SecItemDelete") }
    }

    private static func blob(_ account: String = ApprovalKey.account) throws -> Data {
        var q = query(account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let st = SecItemCopyMatching(q as CFDictionary, &item)
        if st == errSecItemNotFound { throw ApprovalKeyError("no approval key; run `farrier setup`") }
        guard st == errSecSuccess, let data = item as? Data else { throw ApprovalKeyError(st, "reading the approval key") }
        return data
    }

    /// The public key (DER). Loading the key doesn't prompt; only signing does.
    public static func publicKey() throws -> Data {
        try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: try blob()).publicKey.derRepresentation
    }

    /// Signs with user presence. `reason` must be derived from the plan by the caller, never from arguments or
    /// agent text: the prompt reads "farrier is trying to <reason>".
    public static func sign(_ payload: Data, reason: String) throws -> Data {
        let context = LAContext()
        context.localizedReason = reason
        context.touchIDAuthenticationAllowableReuseDuration = 0
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: try blob(), authenticationContext: context)
        return try key.signature(for: payload).derRepresentation
    }

    // MARK: - Integrity check

    /// The access list must let only Farrier use the secret, and no application change the list. Anything else
    /// (for example after someone clicked "Always Allow" in another program's dialog) means the blob may have left
    /// the keychain, so the key must be rotated. Fails closed: an unreadable list is a problem too.
    public static func integrityProblems() -> [String] {
        var q = baseQuery
        q[kSecReturnRef as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var ref: CFTypeRef?
        var st = SecItemCopyMatching(q as CFDictionary, &ref)
        guard st == errSecSuccess, let ref else {
            return ["could not look up the key item (\(st))"]
        }
        let item = ref as! SecKeychainItem  // swiftlint:disable:this force_cast
        var access: SecAccess?
        st = SecKeychainItemCopyAccess(item, &access)
        guard st == errSecSuccess, let access else { return ["could not read the access list (\(st))"] }
        var list: CFArray?
        st = SecAccessCopyACLList(access, &list)
        guard st == errSecSuccess, let list else { return ["could not read the access list entries (\(st))"] }

        // The keychain records the trusted app as the bundle path, so both paths count as Farrier.
        let selfPaths: Set<String> = [Bundle.main.executablePath ?? "", Bundle.main.bundlePath]
        var problems: [String] = []
        for entry in (list as NSArray) {
            let acl = entry as! SecACL  // swiftlint:disable:this force_cast
            var apps: CFArray?
            var description: CFString?
            var selector = SecKeychainPromptSelector()
            _ = SecACLCopyContents(acl, &apps, &description, &selector)
            let auths = ((SecACLCopyAuthorizations(acl) as NSArray) as? [String]) ?? []
            let sensitive = auths.contains { a in ["Decrypt", "Derive", "Export", "Sign", "MAC", "Any"].contains { a.contains($0) } }
            let changesACL = auths.contains { $0.contains("ChangeACL") }
            guard let apps else {
                if sensitive || changesACL { problems.append("any application may \(auths.joined(separator: ","))") }
                continue
            }
            let paths = (apps as NSArray).map { appPath($0 as! SecTrustedApplication) }  // swiftlint:disable:this force_cast
            if changesACL {
                problems += paths.map { "\($0) may change the access list" }
            } else if sensitive {
                // Only Farrier itself. A `group://` entry is not exempt: its members can't be verified here, so
                // it counts as someone else and leads to rotation.
                problems += paths.filter { !selfPaths.contains($0) }.map { "\($0) may use the key" }
            }
        }
        return problems
    }

    private static func appPath(_ app: SecTrustedApplication) -> String {
        var data: CFData?
        guard SecTrustedApplicationCopyData(app, &data) == errSecSuccess, let d = data as Data? else { return "?" }
        return String(decoding: d.prefix { $0 != 0 }, as: UTF8.self)
    }
}

public struct ApprovalKeyError: Error, CustomStringConvertible {
    public let description: String

    init(_ description: String) { self.description = description }

    init(_ status: OSStatus, _ context: String) {
        let message = (SecCopyErrorMessageString(status, nil) as String?) ?? "OSStatus \(status)"
        self.description = "\(context): \(message) (\(status))"
    }
}
#endif
