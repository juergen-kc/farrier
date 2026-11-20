import Foundation
import SpikeShared

// farrier-spike-helper: the root LaunchDaemon. launchd starts it on demand when a client connects to
// the Mach service. It must not be started by hand.
//
// Log: /Library/Logs/farrier-spike-helper.log (stderr, set in the LaunchDaemon plist).

setvbuf(stderr, nil, _IONBF, 0)

func helperLog(_ s: String) {
    FileHandle.standardError.write(Data("\(ISO8601DateFormatter().string(from: Date())) \(s)\n".utf8))
}

let me = SigningIdentity.current()
guard let team = me.teamID else {
    helperLog("refusing to start: the helper has no Team ID, so it can't pin its clients")
    exit(1)
}
let clientRequirement = codeRequirement(identifier: Spike.appBundleID, teamID: team)
helperLog("starting pid=\(getpid()) euid=\(geteuid()) id=\(me.identifier ?? "?") team=\(team)")
helperLog("authorization right: \(Authz.ensureRight())")
helperLog("client requirement: \(clientRequirement)")

final class ListenerDelegate: NSObject, NSXPCListenerDelegate {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection c: NSXPCConnection) -> Bool {
        // The system enforces this on every message. A caller that doesn't match gets its
        // connection invalidated, and our methods are never invoked.
        c.setCodeSigningRequirement(clientRequirement)
        c.exportedInterface = NSXPCInterface(with: HelperProtocol.self)
        c.exportedObject = HelperService()
        let pid = c.processIdentifier
        c.invalidationHandler = { helperLog("connection from pid \(pid) invalidated") }
        c.resume()
        helperLog("connection from pid=\(pid) euid=\(c.effectiveUserIdentifier) asid=\(c.auditSessionIdentifier); code requirement enforced")
        return true
    }
}

let delegate = ListenerDelegate()
let listener = NSXPCListener(machServiceName: Spike.machService)
listener.delegate = delegate
listener.resume()
dispatchMain()
