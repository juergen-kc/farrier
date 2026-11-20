// farrier-helper: Farrier's root LaunchDaemon. launchd starts it on demand when the CLI connects to its Mach
// service; it must never be started by hand. Design: docs/ARCHITECTURE.md, "farrier-helper".
// Logs: /Library/Logs/farrier-helper.log (stderr, set in the LaunchDaemon plist).

#if os(macOS)
import FarrierCore
import FarrierHelperKit
import Foundation

setvbuf(stderr, nil, _IONBF, 0)

let identity = SigningIdentity.current()
guard let team = identity.teamID else {
    helperLog("refusing to start: no Team ID, so clients can't be pinned")
    exit(1)
}
let clientRequirement = codeRequirement(identifier: HelperConstants.appIdentifier, teamID: team)
helperLog("starting version=\(FarrierVersion.string) pid=\(getpid()) id=\(identity.identifier ?? "?") team=\(team)")

helperLog(Authz.ensureRight())

let lifecycle = Lifecycle(idleTimeout: 60) {
    HelperService.approvals.hasOutstanding(now: Int64(Date().timeIntervalSince1970))
}

final class ListenerDelegate: NSObject, NSXPCListenerDelegate {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection c: NSXPCConnection) -> Bool {
        // Enforced by the system on every message: a caller that doesn't match never reaches our methods.
        c.setCodeSigningRequirement(clientRequirement)
        c.exportedInterface = NSXPCInterface(with: FarrierHelperProtocol.self)
        c.exportedObject = HelperService(lifecycle: lifecycle)
        lifecycle.connectionOpened()
        c.invalidationHandler = { lifecycle.connectionClosed() }
        c.resume()
        return true
    }
}

let delegate = ListenerDelegate()
let listener = NSXPCListener(machServiceName: HelperConstants.machService)
listener.delegate = delegate
listener.resume()
lifecycle.startIdleTimer()
dispatchMain()

#else
import Foundation
FileHandle.standardError.write(Data("farrier-helper only runs on macOS\n".utf8))
exit(1)
#endif
