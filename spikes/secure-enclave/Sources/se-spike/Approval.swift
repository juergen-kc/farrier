import CryptoKit
import Foundation

/// The exact bytes the user approves with Touch ID, and that the root helper verifies.
///
/// Layout (fixed lengths, so the encoding can't be ambiguous):
///   "farrier-plan-approval-v1" || 0x00 || planHash[32] || nonce[32] || expiresAt[int64, big-endian]
///
/// - planHash: SHA-256 of the canonical plan JSON (computed by the user process).
/// - nonce:    issued by the helper for this approval, so an approval can't be replayed.
/// - expiresAt: Unix seconds. The helper rejects expired approvals.
struct ApprovalPayload {
    static let domain = "farrier-plan-approval-v1"

    let planHash: Data
    let nonce: Data
    let expiresAt: Int64

    init(planHash: Data, nonce: Data, expiresAt: Int64) throws {
        guard planHash.count == 32 else { throw SpikeError("planHash must be 32 bytes, got \(planHash.count)") }
        guard nonce.count == 32 else { throw SpikeError("nonce must be 32 bytes, got \(nonce.count)") }
        self.planHash = planHash
        self.nonce = nonce
        self.expiresAt = expiresAt
    }

    var bytes: Data {
        var d = Data(Self.domain.utf8)
        d.append(0)
        d.append(planHash)
        d.append(nonce)
        withUnsafeBytes(of: expiresAt.bigEndian) { d.append(contentsOf: $0) }
        return d
    }

    static func parse(_ data: Data) throws -> ApprovalPayload {
        let prefix = Data(domain.utf8) + Data([0])
        guard data.count == prefix.count + 32 + 32 + 8, data.prefix(prefix.count) == prefix else {
            throw SpikeError("payload has the wrong domain or length")
        }
        var i = data.startIndex + prefix.count
        let planHash = data[i..<(i + 32)]; i += 32
        let nonce = data[i..<(i + 32)]; i += 32
        let exp = data[i..<(i + 8)].reduce(Int64(0)) { ($0 << 8) | Int64($1) }
        return try ApprovalPayload(planHash: Data(planHash), nonce: Data(nonce), expiresAt: exp)
    }
}

/// What a signing run writes to disk, and what `verify` reads (the helper's view).
struct ApprovalRecord: Codable {
    var approach: String
    var payloadHex: String
    var signatureHex: String
    var publicKeyFingerprint: String
}

enum Verifier {
    /// This is all the root helper has to do. It's pure CryptoKit and needs no Secure Enclave access.
    static func verify(publicKeyDER: Data, record: ApprovalRecord, tamper: Bool) throws -> [String: Any] {
        guard var payload = Data(hex: record.payloadHex), let sigDER = Data(hex: record.signatureHex) else {
            throw SpikeError("bad hex in approval record")
        }
        if tamper { payload[payload.startIndex + payload.count - 9] ^= 0x01 }  // flip a nonce bit

        let parsed = try ApprovalPayload.parse(payload)
        let pub = try P256.Signing.PublicKey(derRepresentation: publicKeyDER)
        let sig = try P256.Signing.ECDSASignature(derRepresentation: sigDER)
        let valid = pub.isValidSignature(sig, for: payload)
        let now = Int64(Date().timeIntervalSince1970)
        return [
            "ok": valid && parsed.expiresAt > now,
            "signatureValid": valid,
            "expired": parsed.expiresAt <= now,
            "tampered": tamper,
            "fingerprintMatches": sha256Hex(publicKeyDER) == record.publicKeyFingerprint,
            "planHash": parsed.planHash.hex,
        ]
    }
}
