import CryptoKit
import Foundation
import LocalAuthentication

/// Approach A: a CryptoKit `SecureEnclave.P256` key. The key is NOT stored in the keychain.
/// We keep its `dataRepresentation`, a blob that only this Mac's Secure Enclave can use, in a file.
///
/// Hypothesis: no keychain entitlement is needed, so it works with plain Developer ID signing
/// (no provisioning profile). If so, this is Farrier's preferred design.
enum ApproachA {
    static func create(policy: Policy, keyURL: URL) throws -> [String: Any] {
        guard SecureEnclave.isAvailable else { throw SpikeError("SecureEnclave.isAvailable is false") }
        let key = try SecureEnclave.P256.Signing.PrivateKey(
            compactRepresentable: false,
            accessControl: try policy.accessControl()
        )
        let pubURL = keyURL.appendingPathExtension("pub")
        try writeFile(key.dataRepresentation, to: keyURL, mode: 0o600)
        try writeFile(key.publicKey.derRepresentation, to: pubURL, mode: 0o644)
        return [
            "ok": true,
            "policy": policy.rawValue,
            "keyBlob": keyURL.path,
            "keyBlobBytes": key.dataRepresentation.count,
            "publicKey": pubURL.path,
            "publicKeyFingerprint": sha256Hex(key.publicKey.derRepresentation),
        ]
    }

    /// Signs the payload. This is where Touch ID or password should be required, every time.
    static func sign(keyURL: URL, payload: Data, reason: String) throws -> (signature: Data, publicKey: Data, seconds: Double) {
        let blob = try Data(contentsOf: keyURL)
        let ctx = LAContext()
        ctx.localizedReason = reason
        ctx.touchIDAuthenticationAllowableReuseDuration = 0  // never reuse an earlier unlock
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob, authenticationContext: ctx)
        let start = Date()
        let sig = try key.signature(for: payload)
        return (sig.derRepresentation, key.publicKey.derRepresentation, Date().timeIntervalSince(start))
    }
}
