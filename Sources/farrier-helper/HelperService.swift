#if os(macOS)
import FarrierCore
import FarrierHelperKit
import Foundation

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

    init(idleTimeout: TimeInterval) { self.idleTimeout = idleTimeout }

    func connectionOpened() { lock.withLock { openConnections += 1; lastActivity = Date() } }
    func connectionClosed() { lock.withLock { openConnections -= 1; lastActivity = Date() } }
    func touch() { lock.withLock { lastActivity = Date() } }

    func startIdleTimer() {
        let t = DispatchSource.makeTimerSource(queue: .global())
        t.schedule(deadline: .now() + 10, repeating: 10)
        t.setEventHandler { [weak self] in
            guard let self else { return }
            let idle = self.lock.withLock { self.openConnections <= 0 && Date().timeIntervalSince(self.lastActivity) > self.idleTimeout }
            if idle {
                helperLog("idle for \(Int(self.idleTimeout)) s, exiting")
                exit(0)
            }
        }
        t.resume()
        timer = t
    }

    /// The client runs a different version: reply first, then exit so launchd starts the installed binary.
    func exitSoonForVersionMismatch(_ clientVersion: String) {
        helperLog("client version \(clientVersion) != helper \(FarrierVersion.string), exiting after reply")
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
        guard clientVersion != FarrierVersion.string else { return false }
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
        let (value, error) = PrivilegedFacts.read(known)
        reply(HelperWire.encode(PrivilegedReply(fact: fact, value: value, error: error)))
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
        }
    }
}
#endif
