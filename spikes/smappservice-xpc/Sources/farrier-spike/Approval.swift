import Foundation
import SpikeShared

/// The full approval round trip, shared by the CLI (`approve`) and the MCP tool (`approve_test_plan`).
enum Approval {
    /// Returns the steps in order as (name, result) pairs: "begin", "submit", and optionally "replay".
    static func run(expectID: String, tamper: Bool = false, replay: Bool = false, delay: UInt32? = nil) -> [(String, [String: Any])] {
        var steps: [(String, [String: Any])] = []
        // A random hash stands in for the SHA-256 of a real plan.
        let planHash = Data.random(32)
        let begin = Helper.call(expectID: expectID) { h, r in h.beginApproval(planHash: planHash, reply: r) }
        steps.append(("begin", begin))
        guard begin["ok"] as? Bool == true,
              let nonce = (begin["nonce"] as? String).flatMap({ Data(hex: $0) }),
              let exp = (begin["expiresAt"] as? NSNumber)?.int64Value else { return steps }

        let payload = ApprovalPayload.build(planHash: planHash, nonce: nonce, expiresAt: exp)
        // The prompt text is derived from the plan inside Farrier, never taken from arguments.
        let reason = "approve Farrier plan \(planHash.prefix(4).hex)…: 3 items, 1.2 GB, irreversible"
        var signature: Data
        do {
            signature = try Keychain.sign(payload, reason: reason)
        } catch {
            steps.append(("sign", describe(error)))
            return steps
        }
        if tamper { signature[signature.index(before: signature.endIndex)] ^= 0x01 }
        if let delay { sleep(delay) }

        steps.append(("submit", Helper.call(expectID: expectID) { h, r in
            h.submitApproval(payload: payload, signature: signature, reply: r)
        }))
        if replay {
            steps.append(("replay", Helper.call(expectID: expectID) { h, r in
                h.submitApproval(payload: payload, signature: signature, reply: r)
            }))
        }
        return steps
    }
}
