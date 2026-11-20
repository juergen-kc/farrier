import CryptoKit
import Foundation
import Security
import SpikeShared

/// The helper's verbs. Each one first decides who is calling (console-session check), then acts.
final class HelperService: NSObject, HelperProtocol {
    private static let lock = NSLock()
    private static var nonces: [Data: (planHash: Data, expiresAt: Int64)] = [:]

    // MARK: - Caller

    private func caller() -> [String: Any] {
        guard let c = NSXPCConnection.current() else { return ["sessionOK": false, "error": "no current XPC connection"] }
        var d = SessionCheck.evaluate(asid: c.auditSessionIdentifier, euid: c.effectiveUserIdentifier)
        d["callerPid"] = Int(c.processIdentifier)
        return d
    }

    private func refuse(_ reason: String, _ extra: [String: Any] = [:], _ reply: (Data) -> Void) {
        var d = extra
        d["ok"] = false
        d["refused"] = reason
        helperLog("refused: \(reason)")
        reply(encodeJSON(d))
    }

    // MARK: - Verbs

    func ping(reply: @escaping (Data) -> Void) {
        reply(encodeJSON([
            "ok": true,
            "helperPID": Int(getpid()),  // renamed from helperPid for the update test (X29)
            "helperEuid": Int(geteuid()),
            "helperIdentifier": me.identifier ?? "(none)",
            "helperTeamID": me.teamID ?? "(none)",
        ]))
    }

    func whoAmI(reply: @escaping (Data) -> Void) {
        var d = caller()
        d["ok"] = true
        reply(encodeJSON(d))
    }

    func enroll(publicKey: Data, authorization: Data, reply: @escaping (Data) -> Void) {
        let who = caller()
        guard who["sessionOK"] as? Bool == true else { return refuse("caller is not in the console session", ["caller": who], reply) }
        let auth = Authz.check(authorization)
        guard auth == errAuthorizationSuccess else {
            return refuse("admin authorization failed", ["authStatus": Int(auth)], reply)
        }
        guard (try? P256.Signing.PublicKey(derRepresentation: publicKey)) != nil else {
            return refuse("not a P-256 public key", [:], reply)
        }
        do {
            try FileManager.default.createDirectory(atPath: Spike.stateDir, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: NSNumber(value: Int16(0o755))])
            try publicKey.write(to: URL(fileURLWithPath: Spike.enrolledKeyPath), options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: NSNumber(value: Int16(0o644))],
                                                  ofItemAtPath: Spike.enrolledKeyPath)
        } catch {
            return refuse("could not store the key: \(error)", [:], reply)
        }
        helperLog("enrolled approval key \(sha256Hex(publicKey))")
        reply(encodeJSON(["ok": true, "enrolledKey": Spike.enrolledKeyPath, "publicKeyFingerprint": sha256Hex(publicKey)]))
    }

    func beginApproval(planHash: Data, reply: @escaping (Data) -> Void) {
        let who = caller()
        guard who["sessionOK"] as? Bool == true else { return refuse("caller is not in the console session", ["caller": who], reply) }
        guard planHash.count == 32 else { return refuse("planHash must be 32 bytes", [:], reply) }
        let nonce = Data.random(32)
        let exp = Int64(Date().timeIntervalSince1970) + Spike.approvalTTL
        Self.lock.lock()
        Self.nonces[nonce] = (planHash, exp)
        Self.lock.unlock()
        reply(encodeJSON(["ok": true, "nonce": nonce.hex, "expiresAt": exp, "ttl": Spike.approvalTTL]))
    }

    func submitApproval(payload: Data, signature: Data, reply: @escaping (Data) -> Void) {
        let who = caller()
        guard who["sessionOK"] as? Bool == true else { return refuse("caller is not in the console session", ["caller": who], reply) }
        guard let pubData = FileManager.default.contents(atPath: Spike.enrolledKeyPath),
              let pub = try? P256.Signing.PublicKey(derRepresentation: pubData) else {
            return refuse("no approval key enrolled", [:], reply)
        }
        guard let parsed = try? ApprovalPayload.parse(payload) else { return refuse("malformed payload", [:], reply) }

        // A nonce is consumed by ANY submission, valid or not, so it can't be retried or replayed.
        Self.lock.lock()
        let stored = Self.nonces.removeValue(forKey: parsed.nonce)
        Self.lock.unlock()

        guard let stored else { return refuse("unknown or already used nonce (replay?)", [:], reply) }
        guard stored.planHash == parsed.planHash else { return refuse("plan hash does not match the issued nonce", [:], reply) }
        guard stored.expiresAt == parsed.expiresAt else { return refuse("expiry does not match the issued nonce", [:], reply) }
        guard parsed.expiresAt > Int64(Date().timeIntervalSince1970) else { return refuse("approval expired", [:], reply) }
        guard let sig = try? P256.Signing.ECDSASignature(derRepresentation: signature),
              pub.isValidSignature(sig, for: payload) else {
            return refuse("invalid signature", [:], reply)
        }
        helperLog("approved plan \(parsed.planHash.hex)")
        reply(encodeJSON(["ok": true, "approved": true, "planHash": parsed.planHash.hex]))
    }

    func reset(authorization: Data, reply: @escaping (Data) -> Void) {
        let who = caller()
        guard who["sessionOK"] as? Bool == true else { return refuse("caller is not in the console session", ["caller": who], reply) }
        let auth = Authz.check(authorization)
        guard auth == errAuthorizationSuccess else { return refuse("admin authorization failed", ["authStatus": Int(auth)], reply) }
        try? FileManager.default.removeItem(atPath: Spike.enrolledKeyPath)
        Self.lock.lock()
        Self.nonces.removeAll()
        Self.lock.unlock()
        helperLog("reset: enrolled key removed")
        reply(encodeJSON(["ok": true, "reset": true]))
    }
}
