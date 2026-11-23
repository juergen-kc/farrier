# Roadmap

The privileged helper is part of the very first release. Building the trust boundary
first means every later feature uses the same plan → approve → apply path, so nothing
needs to be retrofitted.

## v0.0: Spikes (before any public release)

- [ ] Secure Enclave key with `.userPresence` in a Developer ID–signed app (no provisioning profile).
      Decides the approval design (see [THREAT_MODEL.md, T-3](THREAT_MODEL.md#t-3-approval-forgery)).
      Code and test checklist: [spikes/secure-enclave](../spikes/secure-enclave/).
      **Status:** passed on a macOS VM (Apple Development build). Approach C, the key blob in the login keychain
      behind a code-signing access list, is the provisional design. Still needed: a physical Mac with Touch ID,
      and Developer ID builds (V3/V5).
- [ ] `SMAppService` daemon registration, approval in System Settings, and `setCodeSigningRequirement` on both
      ends of the XPC connection. Also: the console-session check for approvals (finding F4), and enrolling the
      approval key with admin authorization.
      Code and test checklist: [spikes/smappservice-xpc](../spikes/smappservice-xpc/).
      **Status:** passed on a macOS VM (Apple Development build). Registration, mutual pinning, the console-session
      check (`SessionGetInfo` + console UID), admin-authorized enrollment, the full approval round trip, and the
      access-list integrity check all work. Findings for v0.1: the helper must restart itself after updates, a
      failed integrity check must rotate the key, the `farrier` command must be a wrapper (not a symlink), and the
      app needs a real icon and name. Still needed: Developer ID on a physical Mac.
- [ ] Swift MCP SDK: stdio, output schemas, annotations, and Tasks extension support for the 2026-07-28 spec.
      Code and test checklist: [spikes/mcp-sdk](../spikes/mcp-sdk/).
      **Status:** passed with Claude Code on a macOS VM. SDK 0.12.1 is usable for v0.1: Claude Code also speaks
      `2025-11-25`, and long calls move to the background after 120 s, so the missing Tasks extension doesn't matter.
      **Key finding:** a Full Disk Access grant to the app covers only the helper, not the CLI or MCP server, so all
      protected reads go through the helper. Not yet tested: Claude Desktop.
- [ ] Signing and notarization pipeline in GitHub Actions, plus a Homebrew cask. **Workflow written**
      (`.github/workflows/release.yml`, docs/RELEASING.md): Developer ID signing from an environment secret,
      notarytool + staple, a Gatekeeper check, a GitHub release with the zip, SHA256SUMS and the rendered cask.
      Dry runs (ad hoc) work; the real path needs a Developer ID certificate and an App Store Connect API key.
- [ ] Fixture capture script for Apple CLI outputs on macOS 14, 15, and 26.

## v0.1: Foundation and posture

Done:
- [x] Package layout, CI (Linux and macOS), `FarrierCore` with the rule-pack parser, linter (schema, protected
      paths, user-pack limits) and posture engine; `farrier rules lint|list` and `farrier posture --facts`
- [x] Unprivileged (T0) collectors: OS version, FileVault, SIP, Gatekeeper, firewall, MDM enrollment, software
      update settings; `farrier facts`, live `farrier posture`; golden parser tests; CI runs collection on a real
      macOS runner (docs/FACTS.md)
- [x] Privileged helper, first cut: `Farrier.app` packaging (`scripts/build-app.sh`), SMAppService registration
      (`farrier helper register|status|unregister`), mutual code-signing pinning, console-session check, version
      handshake and idle exit, and the first T1 fact (`mdm.payloadTypes`). **Validated** on a macOS 27.2.1 VM
      (Apple Development signing): registration and approval, root helper, `mdm.payloadTypes` collected, and the
      helper survives an app reinstall without re-registering. Over SSH the helper refuses both the user
      (session 0x5020, remote) and `sudo` (also not the console user), and the fact is reported as failed.

- [x] Plan → approve → apply for the first fix, `firewall.enable` (T4): canonical plans with a hash and expiry
      (`farrier plan posture|show|list`), the Secure Enclave approval key in the login keychain with the
      access-list integrity check (`farrier setup [--rotate]`), admin-authorized enrollment, one-time nonces, the
      helper's `applyPlan` (verifies and applies in one call, re-checks MDM ownership and the current state), and
      hash-chained user and helper journals (`farrier journal verify|show`). **Validated** on a macOS 27.2.1 VM
      (Apple Development signing, no Touch ID): `setup` showed the admin dialog and enrolled the key, and a second
      run changed nothing; the plan held only the firewall, with FileVault and launch items left out and why;
      `apply` showed the password prompt with text derived from the plan ("Farrier is trying to apply Farrier plan
      c0d6f594 (T4): Turn on the application firewall") and turned the firewall on (verified by reading it back);
      applying again reported `alreadyCompliant`; over SSH, apply was refused at the first helper call, before any
      prompt; both journals verified intact. After the review fixes: `setup --rotate` staged, enrolled and then
      promoted a new key (no `group://` entry appears by default, so none is exempted), and cancelling the
      password prompt changed nothing. Not yet tested: cancelling the admin dialog during rotation, a slow
      (> 60 s) approval, the integrity check after "Always Allow", an MDM-managed firewall.

- [x] `farrier mcp`: tools `farrier_status`, `facts_collect`, `posture_check`, `posture_explain`,
      `posture_plan_remediation`, `plan_show`, `apply_plan`, `journal_recent`, and the `security-checkup` prompt, on
      the same operations as the CLI. Annotation titles and hints, structured content, in-flight calls finish at
      end of input. CI drives it over stdio on Linux and macOS. **Validated** with Claude Code 2.1.330 on the
      macOS 27.2.1 VM (auto mode): all eight tools called (confirmed in the wire log), the prompt ran as
      `/mcp__farrier__security-checkup`, the agent reused the open plan instead of making a second one, reported a
      cancelled approval and did not retry it, applied after approval and re-checked; journal entries record
      `mcp:claude-code`. In auto mode Claude Code calls `apply_plan` without asking, so the on-device approval is the
      only gate, as designed.

- [x] Posture exceptions: accept a vendor's validly signed items for a rule (Apple Team ID, optional identifier,
      reason), as T4 plans approved on the Mac and stored by the helper in a root-owned file; `farrier exceptions
      list|add|remove`, MCP `exceptions_list` and `posture_plan_exception`; findings list what was accepted.
      **Validated** on the macOS 27.2.1 VM: accepting Parallels Guest Tools (team 4C6364ACXT) covered both jobs,
      the prompt showed the team and reason, the rule passed with "2 accepted by exception", and the helper wrote
      `exceptions.json` as root:wheel 0644.

- [x] Packaging: an app icon (`scripts/make-icon.py` → `Packaging/AppIcon.png` → `AppIcon.icns`), `scripts/install.sh`
      (root-owned app, a `farrier` wrapper on PATH, restarts an old helper), `farrier uninstall` plus
      `Contents/Resources/uninstall.sh` (helper registration, approval key, authorization right, app, wrapper;
      `--purge` also journals, plans and exceptions), and a Homebrew cask template. **Validated** on the macOS
      27.2.1 VM: install (wrapper in /opt/homebrew/bin, posture through it), uninstall (helper unregistered,
      keychain item, wrapper, app and authorization right gone; journal and exceptions kept), reinstall (macOS
      kept the Login Items approval, so the helper was enabled at once; setup enrolled a new key).

- [x] More posture rules: firewall stealth mode (with the `firewall.stealthEnable` fix), Remote Management, Screen
      Sharing and Remote Login (from the listening TCP ports; guidance only, since turning remote access off can lock
      someone out), and launch jobs that run scripts. **Validated** on the macOS 27.2.1 VM: the stealth fix applied
      (off → on, read back); the listening ports come from the helper (`[22, 88, 3283, 5900]`), because macOS 27
      shows an unprivileged third-party process only its own sockets; Remote Login, Remote Management and Screen
      Sharing fail as they should on that VM.

- [x] Full Disk Access onboarding: the helper checks the grant (it opens a file only Full Disk Access allows),
      `farrier helper full-disk-access` opens the right Settings pane, shows the app and waits for the grant;
      `helper status`, `setup` and the MCP `farrier_status` report it; the first fact that needs it, `tcc.grants`
      (system TCC.db), is reported as missing for that reason, so rules on it are unknown; uninstall resets the
      grant. **Validated** on the macOS 27.2.1 VM: without the grant, `helper.fullDiskAccess = false` and `tcc.grants`
      unavailable with the hint; the command opened Settings and the Finder, and reported "granted" as soon as the
      switch was on; `tcc.grants` then listed 19 grants; turning the switch off was seen at once (`--check` exit 1).
      The running helper picks up both changes without a restart.

- [x] More fixes: automatic security updates (`softwareupdate.enableSecurityAutoInstall`) and Gatekeeper
      (`gatekeeper.enable`, T4). `mdm.declarationTypes` is `[]` on a Mac that isn't MDM-enrolled (declarations only
      come from an MDM server), so the update fix can be planned there; on enrolled Macs it isn't, and the helper
      re-checks enrollment before changing it. **Validated** on the macOS 27.2.1 VM (not enrolled): with
      `CriticalUpdateInstall` off, the plan showed the settings it saw, the apply turned on only that key, and posture
      passed right after. **Gatekeeper not validated:** macOS 27 no longer offers "Anywhere" in Privacy & Security, so
      `spctl --global-disable` can't be confirmed and Gatekeeper can't be turned off locally to test the fix; it needs
      a macOS 14 or 15 Mac. The helper reports success only if `spctl --status` reads back "enabled".

To do:
- Approval key: periodic rotation (every 30 days), and validation on a physical Mac with Touch ID and
  Developer ID signing
- Homebrew cask: the tap ([juergen-kc/homebrew-farrier](https://github.com/juergen-kc/homebrew-farrier), with
  `brew style`/`brew audit` CI) exists and the release workflow commits each release's cask to it; it still needs a
  first real (notarized) release to be tested
- MCP: progress notifications for long calls; resources (`farrier://plan/{id}`, `farrier://journal/recent`); the
  other runbook prompts; validation with Claude Desktop
- Undo for T4 changes (record the previous state, plan the reverse change)
- `posture.core` pack: about 25 high-value checks with mSCP mappings
- Managed-device detection (`managed` findings are not fixable locally)
- `inventory` with signing and notarization status for launchd jobs, login items and extensions
- `inventory` tools in the MCP server, and `--json` everywhere in the CLI
- `--redact`

## v0.2: Cleanup

- Quarantine (user and root), restore, and expiry
- Cleanup packs: system and user caches, logs, Xcode, simulators, package managers
  (npm/pnpm/yarn/pip/cargo/gradle), Homebrew, Docker, iOS backups, APFS local snapshots (T3)
- Developer artifact discovery (`node_modules`, `target`, `.build`, `DerivedData`) under the folders you configure
- App uninstall with leftovers and receipts
- `disk_usage` with honest "reclaimable now" and "reclaimable after expiry" numbers

## v0.3: Drift and debugging

- Snapshots and diffs
- Debugging tools: `log_query`, `power_history`, `crash_reports`, `network_diagnose`,
  `process_snapshot`, `sysdiagnose_summarize` (Tasks)
- MCP prompts and runbooks

## v0.4: Patching and adapters

- `updates_list` and `updates_plan` across macOS, Homebrew, the App Store, and third-party apps
- JumpCloud adapter: status, compare, and optional write-back of findings
- Adapter SDK documentation, so others can contribute adapters (Jamf, Kandji, Intune, Fleet)

## Later / maybe

- An MCP Apps view to review plans inside the chat
- Scheduled read-only checks with local notifications
- Benchmark-level reports (CIS level 1/2, mSCP baselines) exported as Markdown or JSON
