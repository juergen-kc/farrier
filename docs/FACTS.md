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
| `mdm.managedPreferences` | the plists in `/Library/Managed Preferences` (computer level; per-user subfolders aren't read yet) | `{ domain: [keys] }`: every preference domain a profile sets, with its keys; `{}` when the folder doesn't exist. A domain file that can't be read makes the whole fact `failed`, never partial |
| `mdm.declarationTypes` | derived from `mdm.enrollment`: declarations (Declarative Device Management) only come from an MDM server | `[]` on a Mac that isn't MDM-enrolled; left out (`unavailable`) on an enrolled Mac, where reading them isn't supported yet, or when enrollment is unknown |
| `softwareupdate.prefs` | `/Library/Preferences/com.apple.SoftwareUpdate.plist`, overridden by `/Library/Managed Preferences/com.apple.SoftwareUpdate.plist` | `{ AutomaticCheckEnabled, AutomaticDownload, CriticalUpdateInstall, ConfigDataInstall, AutomaticallyInstallMacOSUpdates, AutomaticallyInstallAppUpdates }`; only the keys that are set |
| `softwareupdate.managedKeys` | the managed preferences above | the keys a profile sets |
| `firewall.stealthMode` | `/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode` | `on`, `off` |
| `network.listeningTCP` | `/usr/sbin/netstat -anp tcp`. Unprivileged this works up to macOS 26; on macOS 27 a third-party process sees only its own sockets (netstat prints nothing, reported as `unavailable`), so the helper also collects it as root and its value wins | sorted TCP ports listening on a non-loopback address, e.g. `[22, 5900]` |
| `launchd.items` | the plists in `/Library/LaunchDaemons`, `/Library/LaunchAgents` and `~/Library/LaunchAgents`, and the code signature of each job's program (Security framework, in-process) | a list of `{ label, plist, scope, program, inspected, programExists, runAtLoad, keepAlive, disabled, script, inlineCommand, signature: { valid, notarized, appleSigned, adhoc, teamID, identifier, error }, error }` |

About `launchd.items`:
- `signature.notarized` is true for notarized code **and for Apple's own code** (which isn't notarized but is trusted
  the same way). It's missing when it couldn't be determined, which makes the rule *unknown*, never a pass.
- `signature.source` says it in Gatekeeper's words: `Apple`, `Notarized Developer ID`, `Unnotarized Developer ID`,
  `Ad hoc`, `Unsigned`, `Script`, `Missing program`, `Invalid signature` (checked against `spctl --assess` on a macOS 27.2.1 VM: Parallels Guest Tools'
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

## Inventory facts (T0, collected only by `farrier inventory`)

These take longer than the posture facts, so `farrier facts` and `farrier posture` don't collect them.

| Fact | Source | Values |
|---|---|---|
| `apps.installed` | `*.app` in `/Applications`, its sub-folders (e.g. Utilities) and `~/Applications`; `Contents/Info.plist`; the bundle's code signature (Security framework, as for launch jobs) | `[{ name, bundleID, version, path, signature, error }]`, sorted by path; an app whose Info.plist can't be read is listed with `error` |
| `system.extensions` | `/usr/bin/systemextensionsctl list` | `[{ category, teamID, bundleID, version, name, state, enabled, active }]`; the "N extension(s)" count must match the rows, or the fact is `unparsed` |
| `accounts.admins` | `/usr/bin/dscl . -read /Groups/admin GroupMembership` | sorted member names |

**Gatekeeper's second opinion.** The signature checks run offline: the `notarized` requirement only sees tickets that
are stapled or cached, and the strict static check rejects some script-based bundles. When they say "not
notarized" or "invalid", Farrier asks Gatekeeper itself (`spctl --assess --type execute -vv`), which also looks tickets
up online, and records `gatekeeperAccepted` and `gatekeeperSource` in the signature. Code Gatekeeper accepts as
"Notarized Developer ID" counts as notarized. This applies to launch jobs too. On a CI runner, this changed Microsoft
Edge from "Unnotarized" and two IDLE apps from "Unsigned" to "Notarized Developer ID", matching `spctl`.

The inventory also shows `launchd.items`, `mdm.profiles`, `tcc.grants` and `network.listeningTCP`. An app or launch job
"needs a look" (`!`, `flagged`) when its signature is invalid or missing, it isn't notarized (and isn't Apple's), or
it couldn't be checked.

## T1: via the privileged helper

Collected when `farrier` runs from `Farrier.app`, the helper is enabled (`farrier helper register`), and the
caller is in the console session. Otherwise `farrier facts` lists them as `unavailable`, with the reason.

| Fact | Source (run by the helper as root) | Values |
|---|---|---|
| `network.listeningTCP` | `/usr/sbin/netstat -anp tcp` as root (see the T0 table) | as above |
| `mdm.payloadTypes` | `/usr/bin/profiles show -output stdout-xml` | sorted, unique `PayloadType`s of the computer-level profiles; `[]` when none are installed |
| `mdm.profiles` | the same output | the computer-level profiles: `[{ identifier, displayName, organization, payloadTypes, mdmServer }]`, sorted by identifier; `mdmServer` is the host of the MDM payload's `ServerURL` (enrollment profile only). No other payload contents |
| `helper.fullDiskAccess` | opens (doesn't read) the system `TCC.db`, or `com.apple.TimeMachine.plist` if that's missing: only Full Disk Access allows it, even for root | `true` / `false`; missing (with the reason) if neither file exists or the error is unexpected |
| `tcc.grants` | the system `TCC.db` (`/Library/Application Support/com.apple.TCC/TCC.db`), read-only with SQLite; **needs Full Disk Access** | allowed grants for Full Disk Access, Accessibility, Screen Recording, Input Monitoring, sending events, Endpoint Security and Developer Tools: `[{service, client, clientType}]` (`service` is `fullDiskAccess`, `accessibility`, `screenRecording`, `inputMonitoring`, `postEvents`, `endpointSecurity` or `developerTools`; `clientType` is `bundle` or `path`), sorted |

**Full Disk Access.** Granted to `Farrier.app`, it covers only the helper (never the terminal or AI client that runs
`farrier`). Without it, facts that need it are `unavailable` with "Farrier.app doesn't have Full Disk Access", not
empty, so rules that use them come out **unknown**. `farrier helper full-disk-access` checks the grant, opens System
Settings → Privacy & Security → Full Disk Access, shows `Farrier.app` in the Finder and waits until the grant is on;
`farrier helper status` and the MCP `farrier_status` tool show it too. Per-user grants (camera, microphone, …) are
in each user's own `TCC.db` and aren't collected yet.

### Planned

| Fact | Why privileged | Used by |
|---|---|---|
| `mdm.declarationTypes` (enrolled Macs) | Declarative Device Management state needs root | managed-setting detection |
| `launchd.btm` | apps' embedded launchd jobs and login items (Background Task Management, `sfltool dumpbtm` needs root) | inventory, `posture.core.unsigned-launch-items` |

**Until `mdm.payloadTypes` and `mdm.declarationTypes` are collected** (as valid lists of strings), the posture engine
can't rule out that a configuration profile or declaration owns a setting. Profiles can be installed by hand even on a
Mac that isn't MDM-enrolled, so `mdm.payloadTypes` always needs the helper. Declarations can't: an unenrolled Mac has
none. So a finding for a rule with `managedBy` is marked `managementUnknown` and is **never `fixable`** when the
helper isn't available, or, for rules a declaration could manage (such as automatic security updates), on an
MDM-enrolled Mac. The helper checks enrollment again itself before changing such a setting.

**Managed preferences.** Any profile can set a preference domain's keys (Custom Settings, not only a setting's own
payload), and the managed value overrides the local one. Rules list the keys that matter as `managedBy: preference`;
if one is in `mdm.managedPreferences`, the finding is `managed` (for example "managed preferences
com.apple.SoftwareUpdate (CriticalUpdateInstall)"), and each fix in the catalog has the helper check the same keys
again before changing anything. A managed finding names the profile that carries its payload when `mdm.profiles` is
known. `farrier posture` starts with a one-line summary of how the Mac is managed (`management` in the JSON and in
the MCP `posture_check` result).
