# Fact catalog

Facts are what collectors read from the system and what posture rules check (`collect.fact` in a rule pack).
`farrier facts` shows every fact this Mac produces, and why any are missing.

Rules of the road:
- **Parsers never guess.** An output they don't recognise makes the fact *unknown* (`unparsed` in `farrier facts`).
  It never becomes a pass or a fail. Every parser has golden tests (`Tests/FarrierCoreTests/ParserTests.swift`). When a
  macOS version changes an output, add a case.
- **Commands run without a shell**, by absolute path, with fixed arguments, `LANG=C`, and a 10 s timeout.
- **Tier T0** facts are read by the CLI itself, unprivileged. **Tier T1** facts need root or Full Disk Access and
  come from the helper's `readPrivileged` (planned).
- A missing key inside an object fact (for example a software update setting that was never changed) is reported as
  *unknown* by the posture engine, not as a failure: Apple often omits a setting and uses its default.

## T0: collected today

| Fact | Source | Values |
|---|---|---|
| `os.version` | `/usr/bin/sw_vers` | `{ productName, productVersion, buildVersion }` |
| `filevault.status` | `/usr/bin/fdesetup status` | `On`, `Off`, `Encrypting`, `Decrypting` |
| `sip.status` | `/usr/bin/csrutil status` | `enabled`, `disabled`, `custom` |
| `gatekeeper.assessments` | `/usr/sbin/spctl --status` | `enabled`, `disabled` |
| `firewall.globalState` | `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate` | `off`, `on`, `blockAll` |
| `mdm.enrollment` | `/usr/bin/profiles status -type enrollment` | `{ dep, mdm, userApproved }` (booleans) |
| `softwareupdate.prefs` | `/Library/Preferences/com.apple.SoftwareUpdate.plist`, overridden by `/Library/Managed Preferences/com.apple.SoftwareUpdate.plist` | `{ AutomaticCheckEnabled, AutomaticDownload, CriticalUpdateInstall, ConfigDataInstall, AutomaticallyInstallMacOSUpdates, AutomaticallyInstallAppUpdates }`; only the keys that are set |
| `softwareupdate.managedKeys` | the managed preferences above | the keys a profile sets |
| `launchd.items` | the plists in `/Library/LaunchDaemons`, `/Library/LaunchAgents` and `~/Library/LaunchAgents`, and the code signature of each job's program (Security framework, in-process) | a list of `{ label, plist, scope, program, programExists, runAtLoad, keepAlive, disabled, script, inlineCommand, signature: { valid, notarized, appleSigned, adhoc, teamID, identifier, error }, error }` |

About `launchd.items`:
- `signature.notarized` is true for notarized code **and for Apple's own code** (which isn't notarized but is trusted
  the same way). It's missing when it couldn't be determined, which makes the rule *unknown*, never a pass.
- `signature.source` says it in Gatekeeper's words: `Apple`, `Notarized Developer ID`, `Unnotarized Developer ID`,
  `Ad hoc`, `Unsigned`, … (checked against `spctl --assess` on a macOS 27.2.1 VM: Parallels Guest Tools'
  `prltoolsd` is an unnotarized Developer ID binary, GoogleUpdater a notarized one).
- A job whose program no longer exists is reported with `valid: false`: a leftover that should be reviewed.
- Plists launchd can't run (no `Program`, `ProgramArguments` or `BundleProgram`, such as the empty placeholders
  GoogleUpdater leaves for Keystone) aren't jobs: they're left out and counted in the collection note.
- When the program is an interpreter (`sh`, `python3`, `osascript`, …), the script it runs is in `script` (or
  `inlineCommand: true`). The signature is the interpreter's; scripts can't be signed. A rule for scripted jobs is
  planned. A script that launchd runs directly (through its `#!` line) is reported in `script` with `valid: false`
  and the reason, so it gets reviewed.
- Not checked yet, so their items carry an `error` and make the rule unknown: programs inside an app
  (`BundleProgram`), programs in privacy-protected folders (Desktop, Documents, Downloads, …; reading them could
  prompt), and plists that can't be read. Apps' embedded jobs registered with SMAppService live in the Background
  Task Management database instead and need the helper (planned).
- Only the executable and its signature are validated strictly, not every resource of an app bundle (which takes
  seconds for large apps).

## T1: via the privileged helper

Collected when `farrier` runs from `Farrier.app`, the helper is enabled (`farrier helper register`), and the
caller is in the console session. Otherwise `farrier facts` lists them as `unavailable`, with the reason.

| Fact | Source (run by the helper as root) | Values |
|---|---|---|
| `mdm.payloadTypes` | `/usr/bin/profiles show -output stdout-xml` | sorted, unique `PayloadType`s of the computer-level profiles; `[]` when none are installed |

### Planned

| Fact | Why privileged | Used by |
|---|---|---|
| `mdm.declarationTypes` | Declarative Device Management state needs root | managed-setting detection |
| `launchd.btm` | apps' embedded launchd jobs and login items (Background Task Management, `sfltool dumpbtm` needs root) | inventory, `posture.core.unsigned-launch-items` |
| `tcc.grants` | `TCC.db` needs Full Disk Access | inventory, posture |

**Until `mdm.payloadTypes` and `mdm.declarationTypes` are collected** (as valid lists of strings), the posture engine
can't rule out that a configuration profile owns a setting. That holds even on a Mac that isn't MDM-enrolled, because
a profile can be installed by hand. So every finding for a rule with `managedBy` is marked `managementUnknown` and is
**never `fixable`**. `mdm.enrollment` is informational.
