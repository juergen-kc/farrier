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

## T1: planned, via the helper

| Fact | Why privileged | Used by |
|---|---|---|
| `mdm.payloadTypes` | the computer-level profiles need root | managed-setting detection |
| `mdm.declarationTypes` | Declarative Device Management state needs root | managed-setting detection |
| `launchd.items` | full launchd plists, signature and notarization checks across `/Library` | `posture.core.unsigned-launch-items` |
| `tcc.grants` | `TCC.db` needs Full Disk Access | inventory, posture |

**Until `mdm.payloadTypes` and `mdm.declarationTypes` are collected**, the posture engine can't rule out that an MDM
profile owns a setting on an enrolled Mac (or one whose enrollment is unknown). So it marks those findings
`managementUnknown` and **never `fixable`**.
