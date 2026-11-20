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
| X15 key-create, no prompt | ✅ | |
| X16 key-acl integrityOK | ✅ (after fix) | The access list is exactly as intended: Decrypt/Derive/Export/MAC/**Sign** trust only `/Applications/FarrierSpike.app`; Encrypt, Integrity and PartitionID: any app; **ChangeACL: no app** (`[]`). The check reported `integrityOK: false` because the keychain records the **bundle path**, while the check compared against the executable path. Fixed (both paths count as self); after the update: `integrityOK: true`, `foreignTrustedApps: []`. |
| X17 enroll: admin dialog | ✅ | Dialog: **"enroll a Farrier approval key — Enter your password to continue with 'FarrierSpike'."** It's credited to the **client app** (not the helper), appears in the user's session, and the user name is prefilled. The text is the right's `default-prompt`. A second enroll asked again (no silent credential reuse). Fingerprints match. No separate Touch ID or password prompt for loading the key. |
| X18 key file root:wheel 0644 | ✅ (group admin) | `-rw-r--r-- root admin`. The group is inherited from `/Library/Application Support`; the product should set `root:wheel` explicitly. |
| X19 cancel → refused | ✅ | `authStatus: -60006` (errAuthorizationCanceled) |
| X20 SSH enroll refused before dialog | ✅ (earlier) | didn't reach the helper: keychain read failed with -25300 (item not found, since the key wasn't created yet). With the key present, the keychain blocks SSH with -25308 (first spike, C7). Nothing appeared on screen. |
| X21 authorizationdb rule | ✅ | `rule: authenticate-admin`, `default-prompt` as above. macOS also stored the **creator's identity**: `identifier dev.farrier.spike.helper`, plus a requirement tied to the Apple Development certificate (`leaf[subject.CN]`). The right persists in the database until it's removed (see clean up). |

## 5. Approval round trip

| Test | Result | notes |
|---|---|---|
| X22 approve | ✅ | begin (nonce, ttl 60), prompt, `approved: true`. Helper log: "approved plan 310d1c39…" |
| X23 replay refused | ✅ | the second submission was refused: "unknown or already used nonce (replay?)" |
| X24 tamper refused | ✅ | "invalid signature" |
| X25 expiry refused | ✅ | **"approval expired"**. The helper stayed alive for the 65 s; the nonce was still known. |
| X26 SSH approve refused | ✅ | the helper refused at `beginApproval`: "caller is not in the console session" (bits 0x5020, remote). Refused before any signing, so no prompt is possible. |
| X27 attacker rejected | | |

## 6. Integrity check

| Test | Result | notes |
|---|---|---|
| X28 "Always Allow" detected | ✅ | After "Always Allow" for `security find-generic-password -w`, the Decrypt/Sign entry trusts `/usr/bin/security` too; `key-acl` reports `integrityOK: false`, `foreignTrustedApps: ["/usr/bin/security"]`. **Also:** `security` printed the key **blob**. Whoever holds the blob can use the key from any process (as in Approach A, F1). The keychain protects reading the blob, not using it, and user presence is still required per signature. **Design rule: a failed integrity check means rotating the key (delete, create, re-enroll with admin approval), not just warning.** Done here: new key, re-enrolled, `integrityOK: true`. |

## 7. Updates

| Test | Result | notes |
|---|---|---|
| X29 status after update | ✅ | still `enabled` after reinstalling a new build (client, helper and version changed). No new approval, no notification noticed. |
| X29 new helper answers | ⚠️ **no, until restarted** | `ping` after the update still returned `helperPid` (old key) from pid 13324: **the old helper process keeps running**. `sudo launchctl kickstart -k system/dev.farrier.spike.helper` started the new one (log: "starting pid=15170", "right … exists"). **Product:** the client sends its version; on a mismatch, the helper replies and then exits so launchd starts the new binary on the next connection. The helper also exits when idle. |
| X29 key and enrollment kept | ✅ | `approve` succeeded after the update. The new client read the key (the keychain access list still trusts it), and the enrollment was kept. |

## Conclusions

(VM, Apple Development build. To repeat with Developer ID on a physical Mac.)

- **Registration and update behaviour:** registration works from the CLI inside the bundle (`register()` throws
  while the status becomes `requiresApproval`). An update keeps the registration, key and enrollment, but the
  **running old helper is not replaced**, so the helper needs a version handshake and an idle exit.
- Pinning works in both directions: [x]
- Console-session check method confirmed: [x] `SessionGetInfo` + console UID / [ ] needs an alternative
- Enrollment with admin authorization: [x]
- Approval round trip: [x] (replay, tamper and expiry refused)
- Integrity check: [x] (detects "Always Allow"; failure must rotate the key)
- Packaging: the CLI only runs inside the bundle; use a wrapper script, not a symlink; root-owned bundle;
  real icon and name.

ARCHITECTURE.md and THREAT_MODEL.md updated: [x]
