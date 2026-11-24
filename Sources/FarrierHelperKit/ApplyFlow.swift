#if os(macOS)
import FarrierCore
import Foundation
import LocalAuthentication
import Security

// MARK: - Helper calls for the approval key and plans

extension HelperClient {
    static func decode<T: Decodable>(_ type: T.Type, _ data: Data) throws -> T {
        guard let value = HelperWire.decode(type, data) else { throw HelperUnavailable.connection("bad reply") }
        return value
    }

    public static func approvalKeyStatus() throws -> ApprovalKeyStatus {
        try decode(ApprovalKeyStatus.self, try call { h, r in h.approvalKeyStatus(clientVersion: HelperConstants.handshakeVersion, reply: r) })
    }

    /// Shows the admin dialog (from the helper's authorization request).
    public static func enrollApprovalKey(_ publicKey: Data) throws -> ApprovalKeyStatus {
        let auth = try AdminAuthorization.externalForm()
        return try decode(ApprovalKeyStatus.self, try call { h, r in
            h.enrollApprovalKey(publicKey: publicKey, authorization: auth, clientVersion: HelperConstants.handshakeVersion, reply: r)
        })
    }

    public static func revokeApprovalKey() throws -> ApprovalKeyStatus {
        let auth = try AdminAuthorization.externalForm()
        return try decode(ApprovalKeyStatus.self, try call { h, r in
            h.revokeApprovalKey(authorization: auth, clientVersion: HelperConstants.handshakeVersion, reply: r)
        })
    }

    public static func beginApproval(planHash: Data) throws -> BeginApprovalReply {
        try decode(BeginApprovalReply.self, try call { h, r in
            h.beginApproval(planHash: planHash, clientVersion: HelperConstants.handshakeVersion, reply: r)
        })
    }

    public static func applyPlan(_ plan: Data, payload: Data, signature: Data) throws -> ApplyReply {
        try decode(ApplyReply.self, try call { h, r in
            h.applyPlan(plan: plan, payload: payload, signature: signature, clientVersion: HelperConstants.handshakeVersion, reply: r)
        })
    }
}

/// An empty AuthorizationRef, passed to the helper as an external form. The helper asks for its right with it,
/// which is what shows the admin dialog. The ref is deliberately not freed while this process runs.
enum AdminAuthorization {
    static func externalForm() throws -> Data {
        var ref: AuthorizationRef?
        var st = AuthorizationCreate(nil, nil, [], &ref)
        guard st == errAuthorizationSuccess, let ref else { throw ApprovalKeyError(st, "AuthorizationCreate") }
        var form = AuthorizationExternalForm()
        st = AuthorizationMakeExternalForm(ref, &form)
        guard st == errAuthorizationSuccess else { throw ApprovalKeyError(st, "AuthorizationMakeExternalForm") }
        return withUnsafeBytes(of: &form) { Data($0) }
    }
}

// MARK: - Setup

public struct SetupReport: Sendable {
    public var steps: [String] = []
    public var fingerprint: String?
    /// When the key in use was enrolled (now, if this run enrolled one).
    public var enrolledAt: Int64?
}

public enum ApprovalSetup {
    /// Makes sure an intact approval key exists and is the one the helper has enrolled. Creates or rotates it as
    /// needed; enrolling shows the admin dialog. `rotate` forces a new key.
    public static func run(rotate: Bool = false) throws -> SetupReport {
        var report = SetupReport()
        guard ApprovalKey.isAvailable else { throw ApprovalKeyError("this Mac has no Secure Enclave, so plans that need approval can't be applied") }
        try HelperClient.ensureCurrent()
        let status = try HelperClient.approvalKeyStatus()
        if let error = status.error { throw ApprovalKeyError(error) }

        var reason: String?
        if rotate {
            reason = "rotation requested"
        } else if !ApprovalKey.exists {
            reason = "no approval key yet"
        } else {
            let problems = ApprovalKey.integrityProblems()
            if !problems.isEmpty { reason = "integrity check failed: \(problems.joined(separator: "; "))" }
        }
        // Periodic rotation: a key that's due (or past due) is replaced now, not when an approval is refused.
        if reason == nil, status.enrolled, let enrolledAt = status.enrolledAt {
            switch ApprovalKeyPolicy.age(enrolledAt: enrolledAt, now: Int64(Date().timeIntervalSince1970)) {
            case .fresh: break
            case .dueSoon, .expired:
                let days = Int((Int64(Date().timeIntervalSince1970) - enrolledAt) / 86_400)
                reason = "periodic rotation: the key is \(days) days old (replaced every \(ApprovalKeyPolicy.maxAgeDays) days)"
            }
        }
        report.enrolledAt = status.enrolledAt

        // A new key is staged and becomes the working key only after the helper has enrolled it: cancelling the
        // admin dialog leaves everything as it was.
        let publicKey: Data
        if let reason {
            report.steps.append("creating a new approval key (\(reason))")
            publicKey = try ApprovalKey.createPending()
        } else {
            publicKey = try ApprovalKey.publicKey()
            report.steps.append("approval key present, access list intact")
        }
        let fingerprint = FarrierCrypto.sha256(publicKey).hexString
        report.fingerprint = fingerprint

        if status.enrolled && status.fingerprint == fingerprint && reason == nil {
            report.steps.append("enrolled with the helper")
            return report
        }
        report.steps.append("enrolling with the helper (an admin dialog will appear)")
        do {
            let enrolled = try HelperClient.enrollApprovalKey(publicKey)
            if let error = enrolled.error { throw ApprovalKeyError("enrollment failed: \(error)") }
            guard enrolled.fingerprint == fingerprint else { throw ApprovalKeyError("the helper enrolled a different key") }
        } catch {
            if reason != nil { ApprovalKey.discardPending() }
            throw error
        }
        if reason != nil {
            let replacing = ApprovalKey.exists
            try ApprovalKey.promotePending()
            if replacing { report.steps.append("the new key replaced the old one") }
        }
        report.steps.append("enrolled \(fingerprint.prefix(16))…")
        report.enrolledAt = Int64(Date().timeIntervalSince1970)
        return report
    }
}

// MARK: - Apply

public enum PlanApplyError: Error, CustomStringConvertible {
    case expired
    case otherHost
    case notReady(String)
    case refused(String)

    public var description: String {
        switch self {
        case .expired: return "the plan expired; make a new one"
        case .otherHost: return "the plan was made on another Mac"
        case .notReady(let m): return m
        case .refused(let m): return "the helper refused the plan: \(m)"
        }
    }
}

public enum PlanApplier {
    /// The prompt text, derived from the plan only: "farrier is trying to <this>".
    public static func promptReason(for plan: Plan) -> String {
        // From the catalog, never from the plan's own text (decodeCanonical also rejects plans where they differ).
        // `description` is built from the catalog and the validated parameters (decodeCanonical rejects anything else).
        let changes = plan.items.map(\.description).joined(separator: "; ")
        let what = plan.items.count == 1 ? changes : "\(plan.items.count) changes: \(changes)"
        return "apply Farrier plan \(plan.shortHash()) (\(plan.tier.rawValue)): \(what)"
    }

    /// Checks the key, gets a nonce, asks the user (Touch ID or password), and hands the plan to the helper.
    public static func apply(_ plan: Plan, now: Date = Date()) throws -> ApplyReply {
        guard Int64(now.timeIntervalSince1970) < plan.expiresAt else { throw PlanApplyError.expired }
        guard plan.host == HostIdentity.hardwareUUID() else { throw PlanApplyError.otherHost }
        guard plan.tier.needsApproval else { throw PlanApplyError.notReady("only plans that need approval (T3/T4) go to the helper") }

        try HelperClient.ensureCurrent()
        let status = try HelperClient.approvalKeyStatus()
        if let error = status.error { throw PlanApplyError.notReady(error) }
        guard status.enrolled, ApprovalKey.exists else {
            throw PlanApplyError.notReady("no approval key is set up; run `farrier setup`")
        }
        // A key someone else can use must not approve anything: rotate it first (setup does, with admin approval).
        let problems = ApprovalKey.integrityProblems()
        guard problems.isEmpty else {
            throw PlanApplyError.notReady("the approval key's access list is not intact (\(problems.joined(separator: "; "))). "
                                          + "Run `farrier setup --rotate` now: until then the helper still trusts the old key")
        }
        guard status.fingerprint == FarrierCrypto.sha256(try ApprovalKey.publicKey()).hexString else {
            throw PlanApplyError.notReady("the helper has a different approval key enrolled; run `farrier setup`")
        }

        let data = try plan.canonicalData()
        _ = try Plan.decodeCanonical(data)  // the same checks the helper makes, before anything is shown or signed
        let hash = FarrierCrypto.sha256(data)
        let begin = try HelperClient.beginApproval(planHash: hash)
        guard let grant = begin.grant, let nonce = Data(hexString: grant.nonce) else {
            throw PlanApplyError.refused(begin.error ?? "no approval nonce")
        }
        let payload = ApprovalPayload.build(planHash: hash, nonce: nonce, expiresAt: grant.expiresAt)
        let signature: Data
        do {
            signature = try ApprovalKey.sign(payload, reason: promptReason(for: plan))
        } catch let error as LAError where [.userCancel, .appCancel, .systemCancel].contains(error.code) {
            throw PlanApplyError.notReady("the approval prompt was cancelled; nothing changed")
        }
        let reply = try HelperClient.applyPlan(data, payload: payload, signature: signature)
        // Refused outright → throw. Stopped partway (results plus an error) → return both, so nothing done is hidden.
        if let error = reply.error, reply.results.isEmpty { throw PlanApplyError.refused(error) }
        return reply
    }
}
#endif
