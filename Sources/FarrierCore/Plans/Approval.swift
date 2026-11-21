import Foundation

/// The bytes the approval key signs (docs/ARCHITECTURE.md, "Approval flow"):
/// `"farrier-plan-approval-v1" 0x00 | planHash (32) | nonce (32) | expiresAt (int64, big-endian)`.
public enum ApprovalPayload {
    public static let domain = "farrier-plan-approval-v1"

    public struct Parsed: Sendable, Equatable {
        public let planHash: Data
        public let nonce: Data
        public let expiresAt: Int64
    }

    public static func build(planHash: Data, nonce: Data, expiresAt: Int64) -> Data {
        var d = Data(domain.utf8)
        d.append(0)
        d.append(planHash)
        d.append(nonce)
        withUnsafeBytes(of: expiresAt.bigEndian) { d.append(contentsOf: $0) }
        return d
    }

    public static func parse(_ data: Data) -> Parsed? {
        let prefix = Data(domain.utf8) + Data([0])
        let bytes = Data(data)  // re-based, so indices start at 0
        guard bytes.count == prefix.count + 32 + 32 + 8, bytes.prefix(prefix.count) == prefix else { return nil }
        var i = prefix.count
        let planHash = bytes[i..<(i + 32)]; i += 32
        let nonce = bytes[i..<(i + 32)]; i += 32
        let expiresAt = bytes[i..<(i + 8)].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        return Parsed(planHash: Data(planHash), nonce: Data(nonce), expiresAt: Int64(bitPattern: expiresAt))
    }
}

/// What `beginApproval` hands out: a one-time nonce for one plan hash, valid until `expiresAt`.
public struct ApprovalGrant: Codable, Sendable, Equatable {
    public let nonce: String      // hex, 32 bytes
    public let expiresAt: Int64   // Unix seconds

    public init(nonce: String, expiresAt: Int64) {
        self.nonce = nonce
        self.expiresAt = expiresAt
    }
}

/// The helper's in-memory nonces. Losing them (the helper exits) only makes pending approvals fail.
public final class ApprovalBook: @unchecked Sendable {
    public static let defaultTTL: Int64 = 5 * 60

    private let lock = NSLock()
    private var issued: [Data: (planHash: Data, expiresAt: Int64)] = [:]
    public let ttl: Int64

    public init(ttl: Int64 = ApprovalBook.defaultTTL) { self.ttl = ttl }

    public func issue(planHash: Data, now: Int64) -> ApprovalGrant {
        let nonce = FarrierCrypto.randomBytes(32)
        let expiresAt = now + ttl
        lock.lock()
        issued = issued.filter { $0.value.expiresAt > now }
        issued[nonce] = (planHash, expiresAt)
        lock.unlock()
        return ApprovalGrant(nonce: nonce.hexString, expiresAt: expiresAt)
    }

    /// Is any grant still unexpired? The helper stays running while one is, so a user who takes a while at the
    /// prompt doesn't find their approval gone with an idle-exited helper.
    public func hasOutstanding(now: Int64) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return issued.values.contains { $0.expiresAt > now }
    }

    /// Removes and returns the nonce's record. Every submission consumes its nonce, valid or not.
    public func consume(_ nonce: Data) -> (planHash: Data, expiresAt: Int64)? {
        lock.lock()
        defer { lock.unlock() }
        return issued.removeValue(forKey: nonce)
    }
}

/// Everything the helper checks before it carries out a plan that needs approval. The helper trusts nothing the
/// client says about the plan beyond these bytes and the signature over their hash.
public enum PlanApproval {
    public static func verify(planData: Data, payload: Data, signature: Data, publicKeyDER: Data?,
                              book: ApprovalBook, host: String, now: Int64) -> Result<Plan, PlanError> {
        guard let parsed = ApprovalPayload.parse(payload) else { return .failure(PlanError("malformed approval payload")) }
        // Consume first, so a failed attempt can never be retried with the same nonce.
        guard let record = book.consume(parsed.nonce) else {
            return .failure(PlanError("unknown or already used approval nonce"))
        }
        guard record.planHash == parsed.planHash, record.expiresAt == parsed.expiresAt else {
            return .failure(PlanError("approval does not match the nonce the helper issued"))
        }
        guard now < parsed.expiresAt else { return .failure(PlanError("approval expired")) }
        guard let publicKeyDER else { return .failure(PlanError("no approval key is enrolled; run `farrier setup`")) }
        guard FarrierCrypto.isValidSignature(signature, for: payload, publicKeyDER: publicKeyDER) else {
            return .failure(PlanError("invalid approval signature"))
        }
        guard FarrierCrypto.sha256(planData) == parsed.planHash else {
            return .failure(PlanError("the plan does not match the approved hash"))
        }
        let plan: Plan
        do { plan = try Plan.decodeCanonical(planData) } catch {
            return .failure(error as? PlanError ?? PlanError("undecodable plan: \(error)"))
        }
        guard plan.host == host else { return .failure(PlanError("the plan was made for another Mac")) }
        guard now < plan.expiresAt else { return .failure(PlanError("the plan expired; make a new one")) }
        for item in plan.items {
            guard let action = RemediationCatalog.action(item.action) else {
                return .failure(PlanError("unknown action `\(item.action)`"))
            }
            guard item.tier == action.tier else {
                return .failure(PlanError("`\(item.action)` is \(action.tier.rawValue), but the plan says \(item.tier.rawValue)"))
            }
        }
        return .success(plan)
    }
}
