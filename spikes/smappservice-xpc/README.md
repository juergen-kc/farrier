# Spike: privileged helper via SMAppService and XPC

The second v0.0 spike. It builds a minimal version of Farrier's trust boundary and tests it end to end:
**a signed client, a root helper, and an approval the helper verifies itself.**

## Questions it answers

1. **Registration.** Can a CLI inside an app bundle register a LaunchDaemon with
   `SMAppService.daemon(plistName:)`? What does the user see when approving it in System Settings? Does the
   daemon survive an app update?
2. **Mutual code-signing pinning.** Does `NSXPCConnection.setCodeSigningRequirement` reject clients that
   aren't Farrier (ad hoc, or same team with another identifier)? Does the client reject a helper that isn't
   the expected one?
3. **Console-session check (finding F4).** Can the root helper tell whether the caller is in the session at
   the screen or in an SSH session? It uses the caller's audit session ID from XPC and `SessionGetInfo`.
4. **Enrollment with admin authorization.** Can the helper require admin credentials (Authorization Services,
   with its own right using the rule `authenticate-admin`) before accepting an approval public key? Where does
   the dialog appear?
5. **The full approval round trip.** The helper issues a nonce, the client signs with the Approach C key
   (Touch ID or password), and the helper verifies the signature, nonce, plan hash and expiry. Are replay,
   tampering and expiry rejected?
6. **The access-list integrity check (finding F2).** Can Farrier read its key item's access list and detect an
   extra trusted application (for example, after someone clicked "Always Allow")?

## Layout

```
Package.swift
Sources/SpikeShared/Shared.swift       constants, XPC protocol, payload format, code requirement, auth helper
Sources/farrier-spike/                 client CLI (the app's main executable)
  main.swift                           commands
  Helper.swift                         XPC client (pins the helper), SMAppService, client authorization
  Keychain.swift                       approval key (Approach C) and access-list dump
Sources/farrier-spike-helper/          root LaunchDaemon
  main.swift                           NSXPCListener, client pinning
  HelperService.swift                  verbs: ping, whoAmI, enroll, beginApproval, submitApproval, reset
  SessionCheck.swift                   console-session decision
  Authz.swift                          authorization right and check
support/Info.plist                     bundle id dev.farrier.spike.app
support/dev.farrier.spike.helper.plist LaunchDaemon definition (BundleProgram, MachServices)
scripts/build-app.sh                   build, assemble, sign; also builds two attacker copies
CHECKLIST.md / RESULTS.md
```

```
FarrierSpike.app/Contents/
  Info.plist
  MacOS/farrier-spike                  client      (identifier dev.farrier.spike.app)
  MacOS/farrier-spike-helper           root helper (identifier dev.farrier.spike.helper)
  Library/LaunchDaemons/dev.farrier.spike.helper.plist
```

## Notes

- **The Team ID isn't hardcoded.** Each side reads its own Team ID from its signature and requires the peer to have
  the same Team ID plus the exact expected identifier.
- **Logging.** The helper logs to `/Library/Logs/farrier-spike-helper.log`.
- **Not compiled yet.** This code was written without a macOS toolchain. Step 0 is to build it and fix compile
  errors. Expect deprecation warnings from the file-based keychain APIs. These are the calls I'm least sure
  of: `SessionGetInfo` (how Swift imports its types), the `SecACL` functions, and
  `SMAppService.unregister(completionHandler:)`.
- **Nonces live in the helper's memory.** If launchd stops the idle helper between `beginApproval` and
  `submitApproval`, the approval fails, which is safe. The real product may want a different lifetime.
