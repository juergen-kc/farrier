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
- [ ] Signing and notarization pipeline in GitHub Actions, plus a Homebrew cask.
- [ ] Fixture capture script for Apple CLI outputs on macOS 14, 15, and 26.

## v0.1: Foundation and posture

- Helper lifecycle: a version handshake (a mismatched helper exits after replying) and an idle exit
- Approval key: setup, admin-authorized enrollment, the integrity check with automatic rotation, and the
  console-session check
- Packaging: a root-owned `Farrier.app` with an icon; the Homebrew cask installs a `farrier` wrapper script;
  uninstall removes the LaunchDaemon, the enrolled key and the authorization right
- Full Disk Access onboarding: detect via the helper, open the right Settings pane, and report "unknown" without it
- MCP server: progress notifications, annotation titles, and letting in-flight requests finish at end of input
- `farrier-helper` with `readPrivileged` and `setSystemSetting` (small allowlist: firewall,
  stealth mode, automatic update settings)
- Plan, approve and apply, with the journal
- `posture.core` pack: about 25 high-value checks with mSCP mappings
- Managed-device detection (`managed` findings are not fixable locally)
- `inventory` with signing and notarization status for launchd jobs, login items and extensions
- CLI with `--json`, and `farrier mcp` exposing posture, inventory and plan tools
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
