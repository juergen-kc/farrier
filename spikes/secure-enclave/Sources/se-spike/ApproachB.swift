import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// Approach B: a Security-framework Secure Enclave key stored as a permanent item in the
/// data-protection keychain.
///
/// Expectation: this needs a `keychain-access-groups` (or application-identifier) entitlement.
/// On macOS that may require a provisioning profile, which Developer ID command-line tools don't
/// normally have. The spike records exactly where it fails: at launch (killed by AMFI), at key
/// creation (errSecMissingEntitlement, -34018), or not at all.
enum ApproachB {
    static func tag(_ label: String) -> Data { Data("dev.farrier.spike.\(label)".utf8) }

    static func create(policy: Policy, label: String, accessGroup: String?) throws -> [String: Any] {
        var priv: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: tag(label),
            kSecAttrAccessControl as String: try policy.accessControl(),
            kSecAttrLabel as String: "Farrier spike \(label)",
        ]
        if let accessGroup { priv[kSecAttrAccessGroup as String] = accessGroup }
        var attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecUseDataProtectionKeychain as String: true,
            kSecPrivateKeyAttrs as String: priv,
        ]
        if let accessGroup { attrs[kSecAttrAccessGroup as String] = accessGroup }

        var err: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &err) else {
            throw cfError(err, "SecKeyCreateRandomKey")
        }
        let pub = try publicKeyDER(of: key)
        return [
            "ok": true,
            "policy": policy.rawValue,
            "label": label,
            "accessGroup": accessGroup ?? "(default)",
            "publicKeyFingerprint": sha256Hex(pub),
        ]
    }

    static func sign(label: String, payload: Data, reason: String) throws -> (signature: Data, publicKey: Data, seconds: Double) {
        let ctx = LAContext()
        ctx.localizedReason = reason
        ctx.touchIDAuthenticationAllowableReuseDuration = 0
        let key = try find(label: label, context: ctx)
        let start = Date()
        var err: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, payload as CFData, &err) as Data? else {
            throw cfError(err, "SecKeyCreateSignature")
        }
        return (sig, try publicKeyDER(of: key), Date().timeIntervalSince(start))
    }

    static func delete(label: String) throws -> [String: Any] {
        let q: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag(label),
            kSecUseDataProtectionKeychain as String: true,
        ]
        let st = SecItemDelete(q as CFDictionary)
        guard st == errSecSuccess || st == errSecItemNotFound else { throw OSStatusError(status: st, context: "SecItemDelete") }
        return ["ok": true, "deleted": st == errSecSuccess]
    }

    private static func find(label: String, context: LAContext) throws -> SecKey {
        let q: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag(label),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecUseDataProtectionKeychain as String: true,
            kSecUseAuthenticationContext as String: context,
            kSecReturnRef as String: true,
        ]
        var item: CFTypeRef?
        let st = SecItemCopyMatching(q as CFDictionary, &item)
        guard st == errSecSuccess, let item else { throw OSStatusError(status: st, context: "SecItemCopyMatching") }
        return item as! SecKey  // swiftlint:disable:this force_cast
    }

    private static func publicKeyDER(of key: SecKey) throws -> Data {
        guard let pub = SecKeyCopyPublicKey(key) else { throw SpikeError("SecKeyCopyPublicKey returned nil") }
        var err: Unmanaged<CFError>?
        guard let x963 = SecKeyCopyExternalRepresentation(pub, &err) as Data? else {
            throw cfError(err, "SecKeyCopyExternalRepresentation")
        }
        return try P256.Signing.PublicKey(x963Representation: x963).derRepresentation
    }
}
