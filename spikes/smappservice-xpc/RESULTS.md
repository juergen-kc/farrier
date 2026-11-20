# Results

Fill this in while working through [CHECKLIST.md](CHECKLIST.md). Pasting JSON lines is fine.

## Test machine

| | |
|---|---|
| Date | 2026-11-20 |
| Mac model / VM | VirtualMac2,1 (macOS VM, Parallels) |
| macOS version | 27.2.1 (26B131) |
| Signing identity | Apple Development (Team E89Q3796E9) |
| Compile fixes needed (X0) | none. It compiled on the first try, with only deprecation warnings (SecKeychain/SecACL APIs). The app was installed with a non-sudo `ditto`, so the bundle is owned by the user, not root. |

## 1. Registration

| Test | Result | notes |
|---|---|---|
| X1 info | ✅ | identifier `dev.farrier.spike.app`, team E89Q3796E9. `daemonStatus` before registering: **`notFound`** (not `notRegistered`) |
| X2 register → requiresApproval, Settings opens | ✅ | `register()` **throws** `SMAppServiceErrorDomain` 1 "Operation not permitted" while the status becomes `requiresApproval`. That's the API's way of saying "needs approval", so Farrier must treat it as such, not as a failure. Settings opened on Login Items. |
| X3 enabled after approval | ✅ | |
| X4 launchctl print | ✅ | `managed_by = com.apple.xpc.ServiceManagement`, `state = not running` (on demand). **launchd attaches a launch constraint (LWCR):** signing-identifier `dev.farrier.spike.helper` + team-identifier `E89Q3796E9`, validation-category 3. So a modified or swapped helper won't launch. |
| X5 works from Terminal / needs `open` | ✅ from Terminal | no `open` needed |

What the user sees (X2):
- **Notification:** *"App Background Activity — 'FarrierSpike' can run in the background for all users. Do you want to allow…"*,
  with Options → Allow / Don't Allow.
- **System Settings → General → Login Items:** under **Background App Activity**, the entry **FarrierSpike** (the bundle
  name) has a **generic icon**, says "Not running in background", and is **off** until approved.
- For the product: ship a real app icon and a clear bundle name, because that's all the user sees when deciding.

## 2. XPC and pinning

| Test | Result | notes |
|---|---|---|
| X6 ping (euid 0, identifier) | ✅ | `helperEuid: 0`, `helperIdentifier: dev.farrier.spike.helper`. The log shows "starting", "right created (authenticate-admin)", and the client requirement. |
| X7 ad hoc client rejected | ✅ | `NSCocoaErrorDomain` **4097**. The helper log shows the connection, then "invalidated", with no reply. A helper-side rejection reaches the client as 4097 (connection interrupted), a client-side one (X9) as 4102. |
| X8 same team, other identifier rejected | ✅ | 4097, as in X7. Pinning is per identifier, not just per team. |
| X9 client rejects unexpected helper | ✅ | `NSCocoaErrorDomain` **4102** "Couldn't communicate with a helper application." The helper log shows the connection, then "invalidated". |
| X10 same binary outside the bundle | **killed** | `cp $F /tmp/fs-copy && /tmp/fs-copy ping` → `zsh: killed`. The main executable's signature also covers the bundle (Info.plist), so a copy outside it is invalid, and macOS kills it on launch. Good for security. It means the CLI must run **from inside the bundle**. |
| X10b symlink to the binary in the bundle | ✅ with a caveat | `ping` works (the helper checks the real binary's signature), and `daemonStatus` is `enabled`. But `Bundle.main` resolves from the symlink: `bundlePath: /tmp`, `bundleID: (none)`. **Product:** have Homebrew install a wrapper script (`exec /Applications/Farrier.app/Contents/MacOS/farrier "$@"`), not a symlink, or resolve the real path at startup. |

## 3. Console-session check

| Test | sessionOK | bits | graphic | remote | notes |
|---|---|---|---|---|---|
| X11 local | ✅ true | 0x6030 | yes | no | `sessionGetInfoStatus: 0`: **SessionGetInfo works from root for another process's session.** asid 100013, consoleUser juergen. Bits 0x6030 = graphic (0x10) + TTY (0x20) + 0x2000 (presumably console access) + 0x4000 (presumably authenticated) |
| X12 sudo | ✅ false | 0x6030 | yes | no | refused: "caller euid 0 is not the console user". **sudo keeps the same audit session (asid 100013)**, so the session bits alone would accept it. The euid check is essential. |
| X13 SSH | ✅ **false** | 0x5020 | **no** | **yes** | different audit session (asid **100636** vs 100013 in the console). Reasons: "session has no graphics access" and "session is remote". **SessionGetInfo + console-user check reliably distinguish SSH from the console session (F4).** |
| X14 Claude Code | | | | | |

## 4. Enrollment

| Test | Result | notes |
|---|---|---|
| X15 key-create, no prompt | | |
| X16 key-acl integrityOK | | |
| X17 enroll: admin dialog | | dialog names: ; loading the key prompted? |
| X18 key file root:wheel 0644 | | |
| X19 cancel → refused | | authStatus: |
| X20 SSH enroll refused before dialog | ✅ (earlier) | didn't reach the helper: keychain read failed with -25300 (item not found, since the key wasn't created yet). With the key present, the keychain blocks SSH with -25308 (first spike, C7). Nothing appeared on screen. |
| X21 authorizationdb rule | | |

## 5. Approval round trip

| Test | Result | notes |
|---|---|---|
| X22 approve | | |
| X23 replay refused | | |
| X24 tamper refused | | |
| X25 expiry refused | | expired / unknown nonce: |
| X26 SSH approve refused | ✅ | the helper refused at `beginApproval`: "caller is not in the console session" (bits 0x5020, remote). Refused before any signing, so no prompt is possible. |
| X27 attacker rejected | | |

## 6. Integrity check

| Test | Result | notes |
|---|---|---|
| X28 "Always Allow" detected | | |

## 7. Updates

| Test | Result | notes |
|---|---|---|
| X29 status after update | | |
| X29 new helper answers | | kickstart needed? |
| X29 key and enrollment kept | | |

## Conclusions

- Registration and update behaviour:
- Pinning works in both directions: [ ]
- Console-session check method confirmed: [ ] `SessionGetInfo` / [ ] needs an alternative
- Enrollment with admin authorization: [ ]
- Approval round trip: [ ]
- Integrity check: [ ]

ARCHITECTURE.md and THREAT_MODEL.md updated: [ ]
