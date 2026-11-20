import Foundation
import Security
import ServiceManagement
import SpikeShared

/// Talks to the helper over XPC, pinning the helper's code signature.
enum Helper {
    /// Makes one synchronous call. `expectID` is the identifier the helper must be signed with.
    static func call(expectID: String = Spike.helperID,
                     _ body: (HelperProtocol, @escaping (Data) -> Void) -> Void) -> [String: Any] {
        var result: [String: Any] = ["ok": false, "error": "no reply"]
        let c = NSXPCConnection(machServiceName: Spike.machService, options: .privileged)
        c.remoteObjectInterface = NSXPCInterface(with: HelperProtocol.self)
        if let team = SigningIdentity.current().teamID {
            c.setCodeSigningRequirement(codeRequirement(identifier: expectID, teamID: team))
            result["pinnedHelper"] = true
        } else {
            // An unsigned or ad hoc client can't pin the helper. Used for the attacker tests, where the
            // HELPER must reject the client.
            result["pinnedHelper"] = false
        }
        c.resume()
        let proxy = c.synchronousRemoteObjectProxyWithErrorHandler { error in
            let ns = error as NSError
            result = ["ok": false, "xpcError": ns.localizedDescription, "domain": ns.domain, "code": ns.code]
        }
        if let helper = proxy as? HelperProtocol {
            body(helper) { data in result = decodeJSON(data) }
        } else {
            result = ["ok": false, "error": "proxy does not conform to HelperProtocol"]
        }
        c.invalidate()
        return result
    }
}

/// Registration of the LaunchDaemon with SMAppService.
enum Daemon {
    static let service = SMAppService.daemon(plistName: Spike.daemonPlist)

    static func status() -> String {
        switch service.status {
        case .notRegistered: return "notRegistered"
        case .enabled: return "enabled"
        case .requiresApproval: return "requiresApproval"
        case .notFound: return "notFound"
        @unknown default: return "unknown(\(service.status.rawValue))"
        }
    }

    static func register() -> [String: Any] {
        var d: [String: Any] = [:]
        do {
            try service.register()
            d["ok"] = true
        } catch {
            d = describe(error)
        }
        d["status"] = status()
        if service.status == .requiresApproval {
            d["hint"] = "approve FarrierSpike in System Settings → General → Login Items & Extensions, then run status"
            SMAppService.openSystemSettingsLoginItems()
        }
        return d
    }

    static func openSettings() { SMAppService.openSystemSettingsLoginItems() }

    static func unregister() -> [String: Any] {
        let sem = DispatchSemaphore(value: 0)
        var d: [String: Any] = ["ok": true]
        service.unregister { error in
            if let error { d = describe(error) }
            sem.signal()
        }
        sem.wait()
        d["status"] = status()
        return d
    }
}

/// Admin authorization from the client side: an empty AuthorizationRef, passed to the helper as an
/// external form. The helper asks for the right, which is what shows the admin dialog.
enum ClientAuth {
    static func externalForm() throws -> Data {
        var ref: AuthorizationRef?
        var st = AuthorizationCreate(nil, nil, [], &ref)
        guard st == errAuthorizationSuccess, let ref else { throw OSStatusError(st, "AuthorizationCreate") }
        // `ref` is intentionally not freed: the helper uses it through the external form while this process runs.
        var form = AuthorizationExternalForm()
        st = AuthorizationMakeExternalForm(ref, &form)
        guard st == errAuthorizationSuccess else { throw OSStatusError(st, "AuthorizationMakeExternalForm") }
        return withUnsafeBytes(of: &form) { Data($0) }
    }
}
