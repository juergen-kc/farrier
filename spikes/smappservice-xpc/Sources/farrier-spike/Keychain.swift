import CryptoKit
import Foundation
import LocalAuthentication
import Security
import SpikeShared

/// The approval key, stored the way the Secure Enclave spike's Approach C does it: the Secure Enclave
/// key blob sits in the login keychain, in an item that trusts only this binary.
/// This version adds an access-list dump (for the integrity check from finding F2).
enum Keychain {
    private static var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Spike.keychainService,
            kSecAttrAccount as String: Spike.keychainAccount,
            kSecUseDataProtectionKeychain as String: false,
        ]
    }

    static func create() throws -> [String: Any] {
        guard SecureEnclave.isAvailable else { throw SpikeError("SecureEnclave.isAvailable is false") }
        var err: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                       [.privateKeyUsage, .userPresence], &err) else {
            throw err!.takeRetainedValue() as Error
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey(compactRepresentable: false, accessControl: ac)
        _ = SecItemDelete(baseQuery as CFDictionary)

        var selfApp: SecTrustedApplication?
        var st = SecTrustedApplicationCreateFromPath(nil, &selfApp)
        guard st == errSecSuccess, let selfApp else { throw OSStatusError(st, "SecTrustedApplicationCreateFromPath") }
        var access: SecAccess?
        st = SecAccessCreate(Spike.keychainLabel as CFString, [selfApp] as CFArray, &access)
        guard st == errSecSuccess, let access else { throw OSStatusError(st, "SecAccessCreate") }

        var attrs = baseQuery
        attrs[kSecAttrLabel as String] = Spike.keychainLabel
        attrs[kSecValueData as String] = key.dataRepresentation
        attrs[kSecAttrAccess as String] = access
        st = SecItemAdd(attrs as CFDictionary, nil)
        guard st == errSecSuccess else { throw OSStatusError(st, "SecItemAdd") }
        return ["ok": true, "label": Spike.keychainLabel, "publicKeyFingerprint": sha256Hex(key.publicKey.derRepresentation)]
    }

    static func readBlob() throws -> Data {
        var q = baseQuery
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let st = SecItemCopyMatching(q as CFDictionary, &item)
        guard st == errSecSuccess, let data = item as? Data else { throw OSStatusError(st, "keychain read") }
        return data
    }

    /// The public key, derived from the blob. Loading the key should NOT prompt; only signing does.
    static func publicKey() throws -> Data {
        try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: try readBlob()).publicKey.derRepresentation
    }

    /// Signs with user presence. `reason` is built by the caller from the plan, never from arguments.
    static func sign(_ payload: Data, reason: String) throws -> Data {
        let ctx = LAContext()
        ctx.localizedReason = reason
        ctx.touchIDAuthenticationAllowableReuseDuration = 0
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: try readBlob(), authenticationContext: ctx)
        return try key.signature(for: payload).derRepresentation
    }

    static func delete() -> [String: Any] {
        let st = SecItemDelete(baseQuery as CFDictionary)
        return ["ok": st == errSecSuccess || st == errSecItemNotFound, "deleted": st == errSecSuccess, "osstatus": Int(st)]
    }

    /// Lists the item's access-control entries and the applications each one trusts.
    /// Expected: the "decrypt" entry trusts only FarrierSpike. Anything else means someone clicked "Always Allow".
    static func accessList() throws -> [String: Any] {
        var q = baseQuery
        q[kSecReturnRef as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var ref: CFTypeRef?
        var st = SecItemCopyMatching(q as CFDictionary, &ref)
        guard st == errSecSuccess, let ref else { throw OSStatusError(st, "keychain lookup") }
        let item = ref as! SecKeychainItem  // swiftlint:disable:this force_cast

        var access: SecAccess?
        st = SecKeychainItemCopyAccess(item, &access)
        guard st == errSecSuccess, let access else { throw OSStatusError(st, "SecKeychainItemCopyAccess") }
        var list: CFArray?
        st = SecAccessCopyACLList(access, &list)
        guard st == errSecSuccess, let list else { throw OSStatusError(st, "SecAccessCopyACLList") }

        let selfPath = Bundle.main.executablePath ?? ""
        var entries: [[String: Any]] = []
        var foreign: [String] = []
        for aclObj in (list as NSArray) {
            let acl = aclObj as! SecACL  // swiftlint:disable:this force_cast
            var apps: CFArray?
            var desc: CFString?
            var selector = SecKeychainPromptSelector()
            _ = SecACLCopyContents(acl, &apps, &desc, &selector)
            let auths = ((SecACLCopyAuthorizations(acl) as NSArray) as? [String]) ?? []
            var entry: [String: Any] = ["authorizations": auths]
            if let apps {
                let paths = (apps as NSArray).map { appPath($0 as! SecTrustedApplication) }  // swiftlint:disable:this force_cast
                entry["trustedApps"] = paths
                if auths.contains(where: { $0.contains("Decrypt") || $0.contains("Any") }) {
                    foreign += paths.filter { $0 != selfPath && !$0.hasPrefix("group://") }
                }
            } else {
                entry["trustedApps"] = "ANY application"
            }
            entries.append(entry)
        }
        return ["ok": true, "self": selfPath, "foreignTrustedApps": foreign, "integrityOK": foreign.isEmpty, "entries": entries]
    }

    private static func appPath(_ app: SecTrustedApplication) -> String {
        var data: CFData?
        guard SecTrustedApplicationCopyData(app, &data) == errSecSuccess, let d = data as Data? else { return "?" }
        return String(decoding: d.prefix { $0 != 0 }, as: UTF8.self)
    }
}
