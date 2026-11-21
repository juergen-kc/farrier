#if os(macOS)
import FarrierCore
import Foundation
import Security
import ServiceManagement

/// The signing identifier and Team ID of the running binary.
public struct SigningIdentity: Sendable {
    public let identifier: String?
    public let teamID: String?

    public static func current() -> SigningIdentity {
        var code: SecCode?
        var staticCode: SecStaticCode?
        var cfInfo: CFDictionary?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
              SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &cfInfo) == errSecSuccess,
              let info = cfInfo as? [String: Any]
        else { return SigningIdentity(identifier: nil, teamID: nil) }
        return SigningIdentity(
            identifier: info[kSecCodeInfoIdentifier as String] as? String,
            teamID: info[kSecCodeInfoTeamIdentifier as String] as? String
        )
    }
}

/// Why the helper can't be used right now. Shown to the user as is.
public enum HelperUnavailable: Error, CustomStringConvertible {
    case notInAppBundle
    case unsigned
    case notRegistered(String)
    case connection(String)

    public var description: String {
        switch self {
        case .notInAppBundle:
            return "the privileged helper is only available when farrier runs from Farrier.app"
        case .unsigned:
            return "this farrier binary has no Team ID, so it can't verify the helper"
        case .notRegistered(let status):
            return "the privileged helper is not enabled (\(status)); run `farrier helper register`"
        case .connection(let message):
            return "could not talk to the privileged helper: \(message)"
        }
    }
}

/// Registration of the LaunchDaemon (SMAppService) and calls to it over XPC, with the helper's signature pinned.
public enum HelperClient {
    static var service: SMAppService { SMAppService.daemon(plistName: HelperConstants.daemonPlist) }

    public static var isInAppBundle: Bool { Bundle.main.bundlePath.hasSuffix(".app") }

    public static var status: String {
        guard isInAppBundle else { return "unavailable (not running from Farrier.app)" }
        switch service.status {
        case .notRegistered: return "notRegistered"
        case .enabled: return "enabled"
        case .requiresApproval: return "requiresApproval"
        case .notFound: return "notFound"
        @unknown default: return "unknown(\(service.status.rawValue))"
        }
    }

    /// Registers the helper. `register()` throws while the status becomes `requiresApproval`; that's the API's
    /// way of saying "waiting for the user", so it is reported as such, with System Settings opened.
    public static func register() -> (status: String, message: String?) {
        guard isInAppBundle else { return (status, HelperUnavailable.notInAppBundle.description) }
        var message: String?
        do { try service.register() } catch { message = "\(error)" }
        if service.status == .requiresApproval {
            SMAppService.openSystemSettingsLoginItems()
            message = "approve Farrier under System Settings → General → Login Items (Background App Activity), then run `farrier helper status`"
        }
        return (status, message)
    }

    public static func unregister() -> (status: String, message: String?) {
        guard isInAppBundle else { return (status, HelperUnavailable.notInAppBundle.description) }
        let done = DispatchSemaphore(value: 0)
        var message: String?
        service.unregister { error in
            if let error { message = "\(error)" }
            done.signal()
        }
        done.wait()
        return (status, message)
    }

    /// One synchronous XPC call. The helper must be signed with `helperIdentifier` and our own Team ID.
    static func call(_ body: (FarrierHelperProtocol, @escaping (Data) -> Void) -> Void) throws -> Data {
        guard isInAppBundle else { throw HelperUnavailable.notInAppBundle }
        guard let team = SigningIdentity.current().teamID else { throw HelperUnavailable.unsigned }
        guard service.status == .enabled else { throw HelperUnavailable.notRegistered(status) }

        let connection = NSXPCConnection(machServiceName: HelperConstants.machService, options: .privileged)
        connection.remoteObjectInterface = NSXPCInterface(with: FarrierHelperProtocol.self)
        connection.setCodeSigningRequirement(codeRequirement(identifier: HelperConstants.helperIdentifier, teamID: team))
        connection.resume()
        defer { connection.invalidate() }

        var result: Data?
        var failure: String?
        let proxy = connection.synchronousRemoteObjectProxyWithErrorHandler { error in
            let ns = error as NSError
            failure = "\(ns.localizedDescription) (\(ns.domain) \(ns.code))"
        }
        guard let helper = proxy as? FarrierHelperProtocol else { throw HelperUnavailable.connection("no proxy") }
        body(helper) { data in result = data }
        if let failure { throw HelperUnavailable.connection(failure) }
        guard let result else { throw HelperUnavailable.connection("no reply") }
        return result
    }

    public static func hello() throws -> HelperInfo {
        let data = try call { h, r in h.hello(clientVersion: HelperConstants.handshakeVersion, reply: r) }
        guard let info = HelperWire.decode(HelperInfo.self, data) else { throw HelperUnavailable.connection("bad reply") }
        return info
    }

    /// Makes sure the running helper is the installed one before using verbs an older helper may not have.
    /// `hello` exists in every protocol version; a helper of another version answers it, exits, and launchd starts
    /// the installed binary on the next connection.
    public static func ensureCurrent() throws {
        for attempt in 0..<6 {
            let info = try hello()
            if !info.willExit {
                guard info.protocolVersion == HelperConstants.protocolVersion else {
                    throw HelperUnavailable.connection("the helper speaks protocol \(info.protocolVersion), this farrier \(HelperConstants.protocolVersion); reinstall Farrier.app")
                }
                return
            }
            Thread.sleep(forTimeInterval: attempt == 0 ? 1.0 : 2.0)  // give the old helper time to exit
        }
        throw HelperUnavailable.connection("the old helper did not restart; try again, or `sudo launchctl kickstart -k system/\(HelperConstants.machService)`")
    }

    public static func whoAmI() throws -> SessionDecision {
        let data = try call { h, r in h.whoAmI(clientVersion: HelperConstants.handshakeVersion, reply: r) }
        guard let d = HelperWire.decode(SessionDecision.self, data) else { throw HelperUnavailable.connection("bad reply") }
        return d
    }

    public static func readPrivileged(_ fact: PrivilegedFact) throws -> PrivilegedReply {
        let data = try call { h, r in h.readPrivileged(fact: fact.rawValue, clientVersion: HelperConstants.handshakeVersion, reply: r) }
        guard let reply = HelperWire.decode(PrivilegedReply.self, data) else { throw HelperUnavailable.connection("bad reply") }
        return reply
    }

    /// T1 facts for `farrier facts` / `farrier posture`, with a note for each. Never throws: a helper that isn't
    /// available just makes those facts unavailable (and the posture engine treats them as unknown).
    public static func collectPrivilegedFacts() -> CollectionResult {
        var facts: [String: FactValue] = [:]
        var notes: [CollectionNote] = []
        for fact in PrivilegedFact.allCases {
            do {
                let reply = try readPrivileged(fact)
                if let value = reply.value {
                    facts[fact.rawValue] = value
                    notes.append(CollectionNote(fact: fact.rawValue, status: .collected, source: "helper", detail: nil))
                } else {
                    notes.append(CollectionNote(fact: fact.rawValue, status: .failed, source: "helper", detail: reply.error))
                }
            } catch {
                notes.append(CollectionNote(fact: fact.rawValue, status: .unavailable, source: "helper", detail: "\(error)"))
            }
        }
        return CollectionResult(facts: facts, notes: notes)
    }
}
#endif
