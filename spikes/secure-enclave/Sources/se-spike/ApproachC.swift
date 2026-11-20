import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// Approach C: the same CryptoKit Secure Enclave key as Approach A, but its blob is stored in the
/// **login (file-based) keychain** as a generic password. The item's access list trusts only the
/// binary that created it.
///
/// This addresses finding F1. In Approach A, any process running as the same user can read the blob file and
/// request a signature. Here, a different binary trying to read the blob should trigger a keychain
/// access dialog that names it. Even Apple's own `security` tool should trigger that dialog.
///
/// The file-based keychain needs no entitlement. Its APIs (SecAccess, SecTrustedApplication) are
/// deprecated but still work, so expect compiler warnings.
enum ApproachC {
    static let service = "dev.farrier.spike.c"

    static func create(policy: Policy, label: String, pubURL: URL) throws -> [String: Any] {
        guard SecureEnclave.isAvailable else { throw SpikeError("SecureEnclave.isAvailable is false") }
        let key = try SecureEnclave.P256.Signing.PrivateKey(
            compactRepresentable: false,
            accessControl: try policy.accessControl()
        )
        _ = try? delete(label: label)

        let attrs: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: label,
            kSecAttrLabel as String: "Farrier spike approval key (\(label))",
            kSecValueData as String: key.dataRepresentation,
            kSecAttrAccess as String: try makeAccess(label: label),
            kSecUseDataProtectionKeychain as String: false,
        ]
        let st = SecItemAdd(attrs as CFDictionary, nil)
        guard st == errSecSuccess else { throw OSStatusError(status: st, context: "SecItemAdd") }

        try writeFile(key.publicKey.derRepresentation, to: pubURL, mode: 0o644)
        return [
            "ok": true,
            "policy": policy.rawValue,
            "label": label,
            "keychainService": service,
            "publicKey": pubURL.path,
            "publicKeyFingerprint": sha256Hex(key.publicKey.derRepresentation),
        ]
    }

    /// Reads the blob from the keychain, then signs with it. A binary the item doesn't trust should get
    /// a keychain dialog at the read step, BEFORE any Touch ID or password prompt.
    static func sign(label: String, payload: Data, reason: String) throws -> (signature: Data, publicKey: Data, seconds: Double) {
        let readStart = Date()
        let blob = try readBlob(label: label)
        let readSeconds = Date().timeIntervalSince(readStart)
        if readSeconds > 0.5 {
            // A slow read means a keychain dialog was shown and someone approved it.
            FileHandle.standardError.write(Data("note: keychain read took \(String(format: "%.2f", readSeconds)) s (a keychain dialog was probably shown)\n".utf8))
        }
        let ctx = LAContext()
        ctx.localizedReason = reason
        ctx.touchIDAuthenticationAllowableReuseDuration = 0
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob, authenticationContext: ctx)
        let start = Date()
        let sig = try key.signature(for: payload)
        return (sig.derRepresentation, key.publicKey.derRepresentation, Date().timeIntervalSince(start))
    }

    static func delete(label: String) throws -> [String: Any] {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: label,
            kSecUseDataProtectionKeychain as String: false,
        ]
        let st = SecItemDelete(q as CFDictionary)
        guard st == errSecSuccess || st == errSecItemNotFound else { throw OSStatusError(status: st, context: "SecItemDelete") }
        return ["ok": true, "deleted": st == errSecSuccess]
    }

    private static func readBlob(label: String) throws -> Data {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: label,
            kSecUseDataProtectionKeychain as String: false,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let st = SecItemCopyMatching(q as CFDictionary, &item)
        guard st == errSecSuccess, let data = item as? Data else {
            throw OSStatusError(status: st, context: "SecItemCopyMatching (keychain read)")
        }
        return data
    }

    /// An access list that trusts only the calling binary (matched by its designated requirement).
    private static func makeAccess(label: String) throws -> SecAccess {
        var selfApp: SecTrustedApplication?
        var st = SecTrustedApplicationCreateFromPath(nil, &selfApp)  // nil means "the calling application"
        guard st == errSecSuccess, let selfApp else {
            throw OSStatusError(status: st, context: "SecTrustedApplicationCreateFromPath")
        }
        var access: SecAccess?
        st = SecAccessCreate("Farrier spike approval key (\(label))" as CFString, [selfApp] as CFArray, &access)
        guard st == errSecSuccess, let access else { throw OSStatusError(status: st, context: "SecAccessCreate") }
        return access
    }
}
