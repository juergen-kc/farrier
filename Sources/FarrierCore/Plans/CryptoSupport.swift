#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation

/// The few cryptographic primitives Farrier needs, in one place so that only this file depends on CryptoKit
/// (macOS) or swift-crypto (Linux, where CI tests the approval and journal code).
public enum FarrierCrypto {
    public static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    /// `count` bytes from the system's cryptographically secure generator.
    public static func randomBytes(_ count: Int) -> Data {
        var rng = SystemRandomNumberGenerator()
        return Data((0..<count).map { _ in UInt8.random(in: .min ... .max, using: &rng) })
    }

    /// Is `publicKeyDER` a P-256 public key (SubjectPublicKeyInfo, DER)?
    public static func isP256PublicKey(_ publicKeyDER: Data) -> Bool {
        (try? P256.Signing.PublicKey(derRepresentation: publicKeyDER)) != nil
    }

    /// Verifies an ECDSA P-256 signature (DER) over `message` (hashed with SHA-256, as CryptoKit signs it).
    /// Anything malformed is simply invalid.
    public static func isValidSignature(_ signatureDER: Data, for message: Data, publicKeyDER: Data) -> Bool {
        guard let key = try? P256.Signing.PublicKey(derRepresentation: publicKeyDER),
              let signature = try? P256.Signing.ECDSASignature(derRepresentation: signatureDER) else { return false }
        return key.isValidSignature(signature, for: message)
    }
}

extension Data {
    /// Lowercase hex.
    public var hexString: String { map { String(format: "%02x", $0) }.joined() }

    /// Parses lowercase or uppercase hex; nil for an odd length or a non-hex character.
    public init?(hexString: String) {
        // Nibble by nibble: `UInt8(_:radix:)` would also accept a sign ("+f").
        func nibble(_ c: UInt8) -> UInt8? {
            switch c {
            case UInt8(ascii: "0")...UInt8(ascii: "9"): return c - UInt8(ascii: "0")
            case UInt8(ascii: "a")...UInt8(ascii: "f"): return c - UInt8(ascii: "a") + 10
            case UInt8(ascii: "A")...UInt8(ascii: "F"): return c - UInt8(ascii: "A") + 10
            default: return nil
            }
        }
        let chars = Array(hexString.utf8)
        guard chars.count % 2 == 0 else { return nil }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(chars.count / 2)
        var i = 0
        while i < chars.count {
            guard let hi = nibble(chars[i]), let lo = nibble(chars[i + 1]) else { return nil }
            bytes.append(hi << 4 | lo)
            i += 2
        }
        self.init(bytes)
    }
}
