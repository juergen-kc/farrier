import Foundation
import SpikeShared

// farrier-spike: the client side of the SMAppService + XPC spike. See CHECKLIST.md.
// Run it from inside the installed app bundle:
//   /Applications/FarrierSpike.app/Contents/MacOS/farrier-spike <command>

let usage = """
usage: farrier-spike <command> [options]

  info                       this binary's signature, bundle and daemon status
  register | status | unregister | open-settings
                             SMAppService registration of the root helper

  ping [--expect-helper-id ID]
                             call the helper (pins the helper's signature; ID defaults to \(Spike.helperID))
  whoami                     how the helper sees this caller, and its console-session decision

  key-create | key-acl | key-delete
                             the approval key in the login keychain (Approach C) and its access list
  enroll                     register the approval public key with the helper (admin authorization)
  approve [--tamper] [--replay] [--delay SECONDS]
                             full approval round trip: nonce, Touch ID or password, helper verification
  reset                      remove the enrolled key from the helper (admin authorization)

  tcc-probe [--user-folders] try to read TCC-protected locations from this process
  helper-tcc-probe           the same probe, run by the root helper
  mcp                        run as a stdio MCP server (MCP SDK spike)
"""

var args = Array(CommandLine.arguments.dropFirst())
guard let command = args.first else { print(usage); exit(2) }
args.removeFirst()

func opt(_ name: String) -> String? {
    guard let i = args.firstIndex(of: "--\(name)"), i + 1 < args.count else { return nil }
    return args[i + 1]
}

func flag(_ name: String) -> Bool { args.contains("--\(name)") }

func finish(_ step: String, _ d: [String: Any]) -> Never {
    printJSON(step, d)
    exit(d["ok"] as? Bool == true ? 0 : 1)
}

let expectID = opt("expect-helper-id") ?? Spike.helperID

do {
    switch command {
    case "info":
        let me = SigningIdentity.current()
        finish("info", [
            "ok": true,
            "identifier": me.identifier ?? "(none)",
            "teamID": me.teamID ?? "(none)",
            "bundlePath": Bundle.main.bundlePath,
            "bundleID": Bundle.main.bundleIdentifier ?? "(none)",
            "executable": Bundle.main.executablePath ?? CommandLine.arguments[0],
            "daemonStatus": Daemon.status(),
            "sshSession": ProcessInfo.processInfo.environment["SSH_CONNECTION"] != nil,
        ])

    case "register": finish("register", Daemon.register())
    case "status": finish("status", ["ok": true, "status": Daemon.status()])
    case "unregister": finish("unregister", Daemon.unregister())
    case "open-settings":
        Daemon.openSettings()
        finish("open-settings", ["ok": true])

    case "ping": finish("ping", Helper.call(expectID: expectID) { h, r in h.ping(reply: r) })
    case "whoami": finish("whoami", Helper.call(expectID: expectID) { h, r in h.whoAmI(reply: r) })

    case "key-create": finish("key-create", try Keychain.create())
    case "key-acl": finish("key-acl", try Keychain.accessList())
    case "key-delete": finish("key-delete", Keychain.delete())

    case "enroll":
        let pub = try Keychain.publicKey()
        let auth = try ClientAuth.externalForm()
        var d = Helper.call(expectID: expectID) { h, r in h.enroll(publicKey: pub, authorization: auth, reply: r) }
        d["localPublicKeyFingerprint"] = sha256Hex(pub)
        finish("enroll", d)

    case "reset":
        let auth = try ClientAuth.externalForm()
        finish("reset", Helper.call(expectID: expectID) { h, r in h.reset(authorization: auth, reply: r) })

    case "approve":
        let steps = Approval.run(expectID: expectID, tamper: flag("tamper"), replay: flag("replay"),
                                 delay: opt("delay").flatMap { UInt32($0) })
        for (name, d) in steps { printJSON(name, d) }
        exit(steps.last(where: { $0.0 == "submit" })?.1["ok"] as? Bool == true ? 0 : 1)

    case "tcc-probe":
        // The same probe as the MCP tool, run directly from the CLI (Terminal is the responsible process here).
        finish("tcc-probe", ["ok": true, "results": TCCProbe.run(home: NSHomeDirectory(), includeUserFolders: flag("user-folders"))])

    case "helper-tcc-probe":
        finish("helper-tcc-probe", Helper.call(expectID: expectID) { h, r in
            h.tccProbe(home: NSHomeDirectory(), reply: r)
        })

    case "mcp":
        // stdio MCP server. Nothing else may write to stdout in this mode.
        try await FarrierMCP.run()
        exit(0)

    default:
        print(usage)
        exit(2)
    }
} catch {
    finish(command, describe(error))
}
