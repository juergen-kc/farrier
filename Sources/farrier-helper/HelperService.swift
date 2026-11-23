#if os(macOS)
import FarrierCore
import FarrierHelperKit
import Foundation
import SQLite3

func helperLog(_ message: String) {
    FileHandle.standardError.write(Data("\(ISO8601DateFormatter().string(from: Date())) \(message)\n".utf8))
}

/// Exits the helper when it's no longer wanted, so nothing runs between uses and updates take effect:
/// after `idleTimeout` seconds without connections, or right after replying to a client of another version.
final class Lifecycle: @unchecked Sendable {
    private let lock = NSLock()
    private var openConnections = 0
    private var lastActivity = Date()
    private let idleTimeout: TimeInterval
    private var timer: DispatchSourceTimer?

    /// Returns true while the helper must not exit even when idle (an approval grant is outstanding).
    private let keepAlive: () -> Bool

    init(idleTimeout: TimeInterval, keepAlive: @escaping () -> Bool = { false }) {
        self.idleTimeout = idleTimeout
        self.keepAlive = keepAlive
    }

    func connectionOpened() { lock.withLock { openConnections += 1; lastActivity = Date() } }
    func connectionClosed() { lock.withLock { openConnections -= 1; lastActivity = Date() } }
    func touch() { lock.withLock { lastActivity = Date() } }

    func startIdleTimer() {
        let t = DispatchSource.makeTimerSource(queue: .global())
        t.schedule(deadline: .now() + 10, repeating: 10)
        t.setEventHandler { [weak self] in
            guard let self else { return }
            let idle = self.lock.withLock { self.openConnections <= 0 && Date().timeIntervalSince(self.lastActivity) > self.idleTimeout }
            if idle && !self.keepAlive() {
                helperLog("idle for \(Int(self.idleTimeout)) s, exiting")
                exit(0)
            }
        }
        t.resume()
        timer = t
    }

    /// The client runs a different version: reply first, then exit so launchd starts the installed binary.
    func exitSoonForVersionMismatch(_ clientVersion: String) {
        helperLog("client version \(clientVersion) != helper \(HelperConstants.handshakeVersion), exiting after reply")
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.5) { exit(0) }
    }
}

/// The helper's verbs. Each one checks the caller's session first where it matters (THREAT_MODEL.md, T-2/T-3).
final class HelperService: NSObject, FarrierHelperProtocol {
    let lifecycle: Lifecycle

    init(lifecycle: Lifecycle) { self.lifecycle = lifecycle }

    /// Handshake: returns `willExit = true` and exits shortly after if the client is another version.
    private func handshake(_ clientVersion: String) -> Bool {
        lifecycle.touch()
        guard clientVersion != HelperConstants.handshakeVersion else { return false }
        lifecycle.exitSoonForVersionMismatch(clientVersion)
        return true
    }

    private func callerDecision() -> SessionDecision {
        guard let c = NSXPCConnection.current() else {
            return SessionDecision(accepted: false, reasons: ["no current XPC connection"], callerEUID: -1, consoleUser: "?", sessionBits: "?")
        }
        return SessionCheck.evaluate(asid: c.auditSessionIdentifier, euid: c.effectiveUserIdentifier)
    }

    func hello(clientVersion: String, reply: @escaping (Data) -> Void) {
        let willExit = handshake(clientVersion)
        reply(HelperWire.encode(HelperInfo(version: FarrierVersion.string, protocolVersion: HelperConstants.protocolVersion,
                                           pid: Int(getpid()), euid: Int(geteuid()), willExit: willExit)))
    }

    func whoAmI(clientVersion: String, reply: @escaping (Data) -> Void) {
        _ = handshake(clientVersion)
        reply(HelperWire.encode(callerDecision()))
    }

    func readPrivileged(fact: String, clientVersion: String, reply: @escaping (Data) -> Void) {
        if handshake(clientVersion) {
            // A stale helper must not answer with possibly outdated logic: refuse, and let the new one start.
            return reply(HelperWire.encode(PrivilegedReply(fact: fact, value: nil, error: "helper restarting after update; retry")))
        }
        let decision = callerDecision()
        guard decision.accepted else {
            helperLog("refused readPrivileged(\(fact)): \(decision.reasons.joined(separator: "; "))")
            return reply(HelperWire.encode(PrivilegedReply(fact: fact, value: nil,
                                                            error: "caller is not in the console session: \(decision.reasons.joined(separator: "; "))")))
        }
        guard let known = PrivilegedFact(rawValue: fact) else {
            return reply(HelperWire.encode(PrivilegedReply(fact: fact, value: nil, error: "not an allowed fact")))
        }
        if known.needsFullDiskAccess, PrivilegedFacts.fullDiskAccess() == .denied {
            return reply(HelperWire.encode(PrivilegedReply(fact: fact, value: nil, error: FullDiskAccess.missingHint,
                                                            needsFullDiskAccess: true)))
        }
        let (value, error) = PrivilegedFacts.read(known)
        reply(HelperWire.encode(PrivilegedReply(fact: fact, value: value, error: error)))
    }
}

// MARK: - Approval key and plans

extension HelperService {
    /// Shared by all connections: nonces must survive a reconnect between `beginApproval` and `applyPlan`.
    static let approvals = ApprovalBook()
    static let journal = Journal(url: URL(fileURLWithPath: HelperConstants.helperJournalPath), mode: 0o644)

    /// The checks every state-changing verb starts with: same version, console session. Nil means "go ahead".
    private func gate(_ clientVersion: String, _ verb: String) -> String? {
        if handshake(clientVersion) { return "helper restarting after update; retry" }
        let decision = callerDecision()
        guard decision.accepted else {
            helperLog("refused \(verb): \(decision.reasons.joined(separator: "; "))")
            return "caller is not in the console session: \(decision.reasons.joined(separator: "; "))"
        }
        return nil
    }

    private static func enrolledKey() -> Data? {
        FileManager.default.contents(atPath: HelperConstants.approvalKeyPath)
    }

    /// Appends to the helper's journal. Returns the error, if any: callers that change the Mac must not go on
    /// without a record (a full disk or a damaged journal stops remediation).
    @discardableResult
    private static func record(_ planID: String, _ planHash: String, _ outcome: String, ruleID: String? = nil,
                               action: String? = nil, detail: String? = nil) -> Error? {
        let r = JournalRecord(time: Int64(Date().timeIntervalSince1970), actor: "helper", planID: planID, planHash: planHash,
                              ruleID: ruleID, action: action, outcome: outcome, detail: detail)
        do {
            try journal.append(r)
            return nil
        } catch {
            helperLog("journal append failed: \(error)")
            return error
        }
    }

    func approvalKeyStatus(clientVersion: String, reply: @escaping (Data) -> Void) {
        if let refusal = gate(clientVersion, "approvalKeyStatus") {
            return reply(HelperWire.encode(ApprovalKeyStatus(enrolled: false, fingerprint: nil, error: refusal)))
        }
        guard let key = Self.enrolledKey() else {
            return reply(HelperWire.encode(ApprovalKeyStatus(enrolled: false, fingerprint: nil, error: nil)))
        }
        reply(HelperWire.encode(ApprovalKeyStatus(enrolled: true, fingerprint: FarrierCrypto.sha256(key).hexString, error: nil)))
    }

    func enrollApprovalKey(publicKey: Data, authorization: Data, clientVersion: String, reply: @escaping (Data) -> Void) {
        func fail(_ message: String) {
            helperLog("enrollApprovalKey refused: \(message)")
            reply(HelperWire.encode(ApprovalKeyStatus(enrolled: Self.enrolledKey() != nil, fingerprint: nil, error: message)))
        }
        if let refusal = gate(clientVersion, "enrollApprovalKey") { return fail(refusal) }
        guard FarrierCrypto.isP256PublicKey(publicKey) else { return fail("not a P-256 public key") }
        let auth = Authz.check(authorization)
        guard auth == errAuthorizationSuccess else { return fail(Authz.describe(auth)) }
        let fingerprint = FarrierCrypto.sha256(publicKey).hexString
        do {
            try Self.writeRootFile(publicKey, to: HelperConstants.approvalKeyPath)
        } catch {
            return fail("could not store the key: \(error)")
        }
        helperLog("enrolled approval key \(fingerprint)")
        Self.record("-", "-", "keyEnrolled", detail: fingerprint)
        reply(HelperWire.encode(ApprovalKeyStatus(enrolled: true, fingerprint: fingerprint, error: nil)))
    }

    func revokeApprovalKey(authorization: Data, clientVersion: String, reply: @escaping (Data) -> Void) {
        func fail(_ message: String) {
            helperLog("revokeApprovalKey refused: \(message)")
            reply(HelperWire.encode(ApprovalKeyStatus(enrolled: Self.enrolledKey() != nil, fingerprint: nil, error: message)))
        }
        if let refusal = gate(clientVersion, "revokeApprovalKey") { return fail(refusal) }
        let auth = Authz.check(authorization)
        guard auth == errAuthorizationSuccess else { return fail(Authz.describe(auth)) }
        do {
            if FileManager.default.fileExists(atPath: HelperConstants.approvalKeyPath) {
                try FileManager.default.removeItem(atPath: HelperConstants.approvalKeyPath)
            }
        } catch {
            return fail("could not remove the key: \(error)")
        }
        helperLog("approval key revoked")
        Self.record("-", "-", "keyRevoked")
        reply(HelperWire.encode(ApprovalKeyStatus(enrolled: false, fingerprint: nil, error: nil)))
    }

    func beginApproval(planHash: Data, clientVersion: String, reply: @escaping (Data) -> Void) {
        if let refusal = gate(clientVersion, "beginApproval") {
            return reply(HelperWire.encode(BeginApprovalReply(grant: nil, error: refusal)))
        }
        guard planHash.count == 32 else { return reply(HelperWire.encode(BeginApprovalReply(grant: nil, error: "planHash must be 32 bytes"))) }
        guard Self.enrolledKey() != nil else {
            return reply(HelperWire.encode(BeginApprovalReply(grant: nil, error: "no approval key is enrolled; run `farrier setup`")))
        }
        let grant = Self.approvals.issue(planHash: planHash, now: Int64(Date().timeIntervalSince1970))
        reply(HelperWire.encode(BeginApprovalReply(grant: grant, error: nil)))
    }

    func applyPlan(plan: Data, payload: Data, signature: Data, clientVersion: String, reply: @escaping (Data) -> Void) {
        let hashHex = FarrierCrypto.sha256(plan).hexString
        let planID = (try? JSONDecoder().decode(Plan.self, from: plan))?.id ?? "?"
        func refuse(_ message: String) {
            helperLog("applyPlan \(planID) refused: \(message)")
            Self.record(planID, hashHex, "refused", detail: message)
            reply(HelperWire.encode(ApplyReply(planID: planID, results: [], error: message)))
        }
        if let refusal = gate(clientVersion, "applyPlan") { return refuse(refusal) }
        guard let host = HostIdentity.hardwareUUID() else { return refuse("could not read this Mac's hardware UUID") }

        let verified = PlanApproval.verify(planData: plan, payload: payload, signature: signature,
                                           publicKeyDER: Self.enrolledKey(), book: Self.approvals, host: host,
                                           now: Int64(Date().timeIntervalSince1970))
        let approved: Plan
        switch verified {
        case .failure(let error): return refuse(error.description)
        case .success(let p): approved = p
        }
        if let error = Self.record(approved.id, hashHex, "approved", detail: "\(approved.items.count) item(s), \(approved.tier.rawValue)") {
            return reply(HelperWire.encode(ApplyReply(planID: approved.id, results: [],
                                                      error: "nothing changed: the helper's journal can't be written (\(error))")))
        }

        var results: [ItemResult] = []
        for item in approved.items {
            lifecycle.touch()
            let r = Remediator.apply(item, planID: approved.id)
            helperLog("plan \(approved.id) \(item.action): \(r.outcome.rawValue) \(r.detail ?? "")")
            results.append(r)
            if let error = Self.record(approved.id, hashHex, r.outcome.rawValue, ruleID: item.ruleID, action: item.action, detail: r.detail) {
                // The change is done but unrecorded: say so, and change nothing more.
                let left = approved.items.count - results.count
                return reply(HelperWire.encode(ApplyReply(planID: approved.id, results: results,
                                                          error: "the helper's journal can't be written (\(error)); \(left) remaining item(s) not applied")))
            }
        }
        reply(HelperWire.encode(ApplyReply(planID: approved.id, results: results, error: nil)))
    }

    /// Writes root:wheel 0644 explicitly (in the spike, the group was otherwise inherited as admin), in a
    /// root:wheel 0755 directory.
    static func writeRootFile(_ data: Data, to path: String) throws {
        let fm = FileManager.default
        let dir = (path as NSString).deletingLastPathComponent
        let owner: [FileAttributeKey: Any] = [.ownerAccountID: NSNumber(value: 0), .groupOwnerAccountID: NSNumber(value: 0)]
        try fm.createDirectory(atPath: dir, withIntermediateDirectories: true)
        try fm.setAttributes(owner.merging([.posixPermissions: NSNumber(value: 0o755)]) { $1 }, ofItemAtPath: dir)
        try data.write(to: URL(fileURLWithPath: path), options: .atomic)
        try fm.setAttributes(owner.merging([.posixPermissions: NSNumber(value: 0o644)]) { $1 }, ofItemAtPath: path)
    }
}

/// The T1 facts themselves. Fixed commands, absolute paths, parsed into derived facts (no raw content returned).
enum PrivilegedFacts {
    static func read(_ fact: PrivilegedFact) -> (FactValue?, String?) {
        switch fact {
        case .mdmPayloadTypes:
            guard let result = ProcessRunner().run("/usr/bin/profiles", ["show", "-output", "stdout-xml"], timeout: 20) else {
                return (nil, "/usr/bin/profiles not found")
            }
            if result.timedOut { return (nil, "profiles timed out") }
            if let value = Parsers.profilePayloadTypes(Data(result.stdout.utf8)) { return (value, nil) }
            let snippet = result.combined.trimmingCharacters(in: .whitespacesAndNewlines).prefix(160)
            return (nil, "unrecognised profiles output (exit \(result.status)): \(snippet)")
        case .mdmProfiles:
            guard let result = ProcessRunner().run("/usr/bin/profiles", ["show", "-output", "stdout-xml"], timeout: 20) else {
                return (nil, "/usr/bin/profiles not found")
            }
            if result.timedOut { return (nil, "profiles timed out") }
            if let value = Parsers.profileSummaries(Data(result.stdout.utf8)) { return (value, nil) }
            let snippet = result.combined.trimmingCharacters(in: .whitespacesAndNewlines).prefix(160)
            return (nil, "unrecognised profiles output (exit \(result.status)): \(snippet)")
        case .listeningTCP:
            guard let result = ProcessRunner().run("/usr/sbin/netstat", ["-anp", "tcp"], timeout: 15) else {
                return (nil, "/usr/sbin/netstat not found")
            }
            if result.timedOut { return (nil, "netstat timed out") }
            if let value = Parsers.listeningTCPPorts(result.stdout) { return (value, nil) }
            let snippet = result.combined.trimmingCharacters(in: .whitespacesAndNewlines).prefix(160)
            return (nil, "unrecognised netstat output (exit \(result.status)): \(snippet)")
        case .fullDiskAccess:
            switch fullDiskAccess() {
            case .granted: return (.bool(true), nil)
            case .denied: return (.bool(false), nil)
            case .undetermined(let reason): return (nil, reason)
            }
        case .tccGrants:
            return TCCDatabase.grants(path: FullDiskAccess.probePaths[0])
        }
    }

    /// Opens (never reads) a file only Full Disk Access allows, as root.
    static func fullDiskAccess() -> FullDiskAccess.ProbeResult {
        FullDiskAccess.probe { path in
            let fd = open(path, O_RDONLY)
            if fd < 0 { return errno }
            close(fd)
            return 0
        }
    }
}

/// The system TCC.db, read-only, through SQLite. Only the columns `PrivacyGrants` needs, only its services.
enum TCCDatabase {
    static func grants(path: String) -> (FactValue?, String?) {
        var db: OpaquePointer?
        defer { sqlite3_close(db) }
        guard sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK else {
            return (nil, "can't open the TCC database: \(String(cString: sqlite3_errmsg(db)))")
        }
        sqlite3_busy_timeout(db, 2000)
        // The service names are Farrier's own constants, not input.
        let list = PrivacyGrants.services.keys.sorted().map { "'\($0)'" }.joined(separator: ",")
        let sql = "SELECT service, client, client_type, auth_value FROM access WHERE service IN (\(list))"
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            return (nil, "unrecognised TCC database layout: \(String(cString: sqlite3_errmsg(db)))")
        }
        var rows: [PrivacyGrants.Row] = []
        while true {
            let step = sqlite3_step(stmt)
            if step == SQLITE_DONE { break }
            guard step == SQLITE_ROW else { return (nil, "reading the TCC database failed: \(String(cString: sqlite3_errmsg(db)))") }
            func text(_ i: Int32) -> String { sqlite3_column_text(stmt, i).map { String(cString: $0) } ?? "" }
            rows.append(PrivacyGrants.Row(service: text(0), client: text(1), clientType: Int(sqlite3_column_int(stmt, 2)),
                                          authValue: Int(sqlite3_column_int(stmt, 3))))
        }
        return (PrivacyGrants.fact(rows), nil)
    }
}
#endif
