# Architecture

> Status: design draft. Items marked **SPIKE** need a prototype before we commit to them.

## Overview

```
 ┌─────────────────────┐   stdio (MCP)   ┌────────────────────────────────────────┐
 │  AI client          │◀──────────────▶│ farrier (user process, signed)        │
 │  Claude Code, etc.  │                 │  ├─ MCP server   (`farrier mcp`)       │
 └─────────────────────┘                 │  ├─ CLI          (`farrier …`)         │
                                         │  └─ FarrierCore  (collectors, checks,  │
 ┌─────────────────────┐   terminal      │                   rules, planner)      │
 │  Human              │◀──────────────▶│                                        │
 └─────────────────────┘                 └──────────────┬─────────────────────────┘
          ▲  Touch ID / password                        │ XPC (Mach service)
          │  (LocalAuthentication)                      │ code-signing requirement
          │                                             │ enforced on both ends
          └──────────── approval ──────────┐            ▼
                                           │ ┌────────────────────────────────────┐
                                           └▶│ farrier-helper (root LaunchDaemon) │
                                             │  ├─ fixed verb allowlist           │
                                             │  ├─ plan verification              │
                                             │  ├─ quarantine (root-owned)        │
                                             │  └─ journal (append-only)          │
                                             └────────────────────────────────────┘
```

The design has one user-level binary and one root daemon. Both live inside a signed, notarized
`Farrier.app` bundle. The bundle has no UI and exists only because `SMAppService` daemons
must be shipped inside an app bundle.

## Components

### FarrierCore (Swift library)

All logic lives here, with no MCP or CLI code. Its modules:

| Module | Responsibility |
|---|---|
| `Collectors` | Read system state: files, `launchd`, profiles, TCC, code signatures, IOKit, network, logs. They return typed `Codable` facts. |
| `Rules` | Load and validate rule packs (YAML). Evaluate posture checks against facts. Match cleanup targets. |
| `Planner` | Turn matches into a `Plan`, a list of `PlanItem`s with evidence, tier and reversibility. |
| `Executor` | Apply user-tier plan items directly, and forward privileged items to the helper. |
| `Quarantine` | Move items aside, restore them, and expire them. |
| `Journal` | Append-only, hash-chained JSONL log of every applied action. |
| `Snapshot` | Serialize the inventory, and diff two snapshots. |
| `Adapters` | `ManagementAdapter` protocol for JumpCloud, and others later. |
| `HelperClient` | Typed XPC client for the helper. |

Collectors use native APIs where public ones exist, such as Security (`SecStaticCode`),
IOKit, SystemConfiguration, and FileManager. Otherwise they call Apple's CLIs (`fdesetup`, `profiles`,
`softwareupdate`, `sfltool`, `log`, `pmset`, `systemextensionsctl`) **by absolute path, with
fixed argument vectors, never through a shell**. Each wrapped CLI has a parser plus golden
fixture tests for every supported macOS version.

### `farrier` (CLI)

- Built with `swift-argument-parser`.
- Every command supports `--json`, whose output matches the MCP tool's `structuredContent` schema.
- `farrier mcp` starts the stdio MCP server, inside the same signed binary as the CLI.
- **The CLI and the MCP server never rely on privacy (TCC) grants.** macOS attributes their file access to the
  app at the top of their process chain: Terminal, iTerm, Claude Desktop, and so on. So a Full Disk Access grant to
  Farrier doesn't apply to them, and the terminal's grant (if any) is an accident of how the user launched them.
  Everything TCC-protected is read **through the helper** (`readPrivileged`, tier T1). Verified in the
  [MCP SDK spike](../spikes/mcp-sdk/RESULTS.md): with FDA granted only to the app, the CLI and the MCP server were
  denied while the helper could read; with FDA only on Terminal, it was the other way round.
- **The binary only runs from inside `Farrier.app`.** Its signature also covers the bundle (`Info.plist`), so a
  copy taken out of the bundle is killed at launch. That's verified, and it's good for security.
- **The `farrier` command on `PATH` is a wrapper script**, not a symlink:
  `exec /Applications/Farrier.app/Contents/MacOS/farrier "$@"`. Through a symlink, `Bundle.main` resolves to the
  symlink's directory and loses the bundle. The helper still accepts the caller, but anything that looks up
  Farrier's own bundle breaks.
- `Farrier.app` is installed **owned by root**, so nothing running as the user can modify it.

### `farrier mcp` (MCP server)

> Verified in the [MCP SDK spike](../spikes/mcp-sdk/RESULTS.md) with Claude Code 2.1.329 on a macOS VM, unless
> marked otherwise.

- Built on the official Swift MCP SDK (`modelcontextprotocol/swift-sdk`), pinned to an exact version (0.12.1 in
  the spike). It needs swift-tools 6.1 or later and adds about 5 MB to the binary, including swift-nio and
  swift-system.
- **Protocol version:** SDK 0.12.1 supports versions up to `2025-11-25`. Claude Code itself requests
  `2025-11-25`, so in practice there's no gap. A client asking for a newer version gets `2025-11-25` back. Follow SDK
  releases for `2026-07-28`.
- **What Claude Code does with our metadata:**
  - `/mcp` labels each tool **read-only** or **destructive** from the annotations, and shows the **annotation
    `title`**, not the tool `title`. So every tool sets an annotation title.
  - Server `instructions` reach the model, which quoted them verbatim.
  - Resources are offered via `@`. Prompts become slash commands (`/farrier:<prompt>`).
  - The client advertised `roots` and `elicitation`, but not `sampling` or `tasks`.
- It is a thin layer: each tool calls one FarrierCore function and returns its result as
  structured content with an output schema.
- Tool annotations come from the operation's tier (see [TOOLS.md](TOOLS.md)).
- **Long operations** (full-disk scans, updates, sysdiagnose):
  - They send **progress notifications** whenever the client provides a `progressToken`. Claude Code always does.
  - The SDK has no Tasks extension, and Claude Code doesn't need it. After **120 s**, Claude Code moves a tool call
    to the background and delivers the result as a notification when it completes. Verified up to 5 min.
  - Progress doesn't extend the 120 s foreground limit.
  - Other clients may time out instead. So operations that can run much longer than about 5 min get a start/status
    pair of tools as a fallback.
- Exposes **resources** (`farrier://posture/latest`, `farrier://snapshot/{id}`,
  `farrier://journal/recent`) and **prompts** (debugging runbooks).
- **Stdout belongs to the protocol.** Diagnostics go to stderr or a log file.
- **On end of input, the server lets in-flight requests finish** before exiting. In the spike, the SDK's loop ended
  at EOF while handlers were still running, and replies were lost. Real clients keep stdin open, so the impact is
  low, but it's an easy fix.
- **Client-side confirmation is not a safeguard.** In its default permission mode, Claude Code asks before calling a
  tool. In **auto mode**, which is common, it called the destructive tool without asking. The only gate Farrier relies
  on is its own on-device approval, which worked from the agent in both modes. A cancel came back as a clear error,
  and the agent didn't retry.
- There is no `apply` path that bypasses on-device approval. Approval is a Touch ID or password prompt for
  the Secure Enclave approval key (see [Approve](#plan-approve-apply)), not MCP elicitation. Elicitation is
  answered by the AI client, which is the thing we don't fully trust.

### `farrier-helper` (privileged helper)

> Verified in the [SMAppService/XPC spike](../spikes/smappservice-xpc/RESULTS.md) (macOS VM, Apple Development
> build), unless marked otherwise.

- Registered with `SMAppService.daemon(plistName:)` from
  `Farrier.app/Contents/Library/LaunchDaemons/`. The LaunchDaemon plist uses `BundleProgram`, `MachServices`
  and `AssociatedBundleIdentifiers`.
- **Registration flow:**
  - Before registering, the status is `notFound`.
  - `register()` **throws** (`SMAppServiceErrorDomain` 1, "Operation not permitted") while the status becomes
    `requiresApproval`. Farrier treats that as "waiting for approval", not as a failure, and opens
    System Settings → General → Login Items.
  - The user sees a notification, *"App Background Activity — 'Farrier' can run in the background for all users"*,
    with Allow / Don't Allow. Farrier also appears under **Background App Activity**, with its bundle name and icon,
    off until approved. **So the app must ship a real icon and a clear name**: that's all the user sees when deciding.
  - After approval: `enabled`.
- **launchd pins the helper.** It attaches a launch constraint (signing identifier + Team ID) to the job, so a
  modified or swapped helper binary won't launch.
- Listens on one Mach service. On every incoming connection it calls
  `NSXPCConnection.setCodeSigningRequirement(_:)` with a requirement pinned to Farrier's
  bundle identifier **and** Team ID:
  `anchor apple generic and identifier "<id>" and certificate leaf[subject.OU] = "<team>"`. The client
  pins the helper the same way. Both sides read their own Team ID from their signature, so nothing is hardcoded.
  - In the spike, an ad hoc–signed client, and a client with the same certificate but a different identifier,
    were both rejected: the client sees `NSCocoaErrorDomain` 4097, and the helper's methods never run. A client
    expecting a different helper refused it (4102).
- The protocol is a small `@objc` interface that passes versioned `Codable` payloads as `Data`.
- It runs **only fixed verbs**. There is no "run this command" verb. The initial verb set:

  | Verb | Purpose |
  |---|---|
  | `readPrivileged(fact)` | Read **root-only or TCC-protected** facts: system and user TCC.db, `/Library` launchd plists with full detail, firewall state, JumpCloud agent config, Safari/Mail metadata where a check needs it. Fixed facts only, never an arbitrary path. Any user-specific location is resolved for the **console user** by the helper itself, never from a path the client sends. |
  | `quarantine(items, planProof)` | Move root-owned items into root quarantine |
  | `restore(planID)` / `expireQuarantine()` | Restore items, or expire them after the retention window |
  | `deleteLocalSnapshot(name, planProof)` | Delete an APFS local snapshot (irreversible, so it is T3) |
  | `applyPlan(plan, payload, signature)` | Verify the approval and carry out the plan's items, all in one call. Items are **remediation catalog** actions only (so far `firewall.enable`, `firewall.stealthEnable`, `gatekeeper.enable`, `softwareupdate.enableSecurityAutoInstall` and the exception changes); the helper takes no settings, values, commands or paths from the client |
  | `uninstallPkgReceipt(id, planProof)` | Remove installer receipts and files listed in a bill of materials (BOM) |
  | `adapterRequest(adapter, op, planProof?)` | Make a signed management-plane call (JumpCloud System Context) |
  | `beginApproval(planHash)` | Issue a one-time nonce and expiry for one approval (prevents replay) |
  | `enrollApprovalKey(publicKey, authorization)` | Register the approval public key. Requires **admin** authorization (see below) |
  | `revokeApprovalKey(authorization)` | Remove the enrolled key, for rotation or uninstall. Requires admin authorization |
  | `approvalKeyStatus()` | Whether a key is enrolled, and its fingerprint |

- The helper **re-validates** every item itself. It does not trust the client's plan contents.
  It resolves paths with `O_NOFOLLOW` on each path component, checks owner, mode and inode against what the plan
  recorded, rejects anything outside the allowed roots for that rule, and never follows symlinks.
- **Lifecycle and updates.** launchd starts the helper on demand. An app update keeps the registration (no new
  approval), but **does not replace a helper process that is already running**. In the spike, the old binary kept
  answering until `launchctl kickstart -k`. The client can't restart it (that needs root), so:
  - every request carries the client's build version. If it differs from the helper's own, the helper answers and
    then exits, and launchd starts the new binary on the next connection.
  - the helper also exits after a short idle period (target: 60 s), so nothing runs between uses.
  - in-memory state, such as approval nonces, is lost when the helper exits. That's safe, because the approval
    just fails and must be repeated.

## Operation tiers

Every operation and every plan item has a tier. The tier drives MCP annotations, approval,
and logging.

| Tier | Meaning | Example | Approval |
|---|---|---|---|
| **T0** read | Read user-accessible state that isn't TCC-protected | posture (unprivileged part), disk usage | none |
| **T1** privileged read | Read via the helper: anything root-only **or TCC-protected** (even user-owned) | system TCC.db, root launchd details, user TCC.db | none (helper checks the client signature and the console session) |
| **T2** reversible change | Can be undone from quarantine or journal | move caches to quarantine | plan + confirm (`--yes` allowed for allowlisted rules) |
| **T3** destructive | Cannot be undone | delete APFS snapshot, empty quarantine | plan + **on-device auth** |
| **T4** system config | Changes system security or config | enable firewall, change update policy | plan + **on-device auth** |

A plan's tier is the highest tier of any item in it.

## Plan, approve, apply

```
collect ─▶ match rules ─▶ PLAN ─▶ (human reviews) ─▶ APPROVE ─▶ APPLY ─▶ JOURNAL
                           │                            │          │
                           │ id, hash, ttl, items       │ proof    │ re-validate each item
                           ▼                            ▼          ▼
                     ~/.farrier/plans/<id>.json   Secure Enclave       quarantine / helper
                                                  signature (Touch ID)
```

**Plan.** Canonical JSON with `id`, `createdAt`, `expiresAt` (default 15 min), `tier`,
`host` (hardware UUID), and `items[]`. Each item records the rule ID, target, size, last use,
evidence (why it matched and why it's safe), and a fingerprint (device, inode, size, mtime,
owner). `planHash` is the SHA-256 of the canonical encoding.

**Approve.** T3 and T4 plans need an approval that the **helper can verify itself**, so a compromised
user process can't produce one without the user being present.

> Status: **provisional.** This design ("Approach C") was chosen from the
> [Secure Enclave spike](../spikes/secure-enclave/RESULTS.md) and exercised end to end, with enrollment, nonces and
> the session check, in the [SMAppService/XPC spike](../spikes/smappservice-xpc/RESULTS.md). Both ran on a macOS VM
> with an Apple Development build. It becomes final once the core tests pass on a physical Mac with Touch ID and
> with Developer ID signing.

**The approval key**
- A P-256 key in the Secure Enclave, created with CryptoKit (`SecureEnclave.P256.Signing.PrivateKey`) and
  `.userPresence` access control: Touch ID, or the login password as fallback. Every signature prompts,
  and an earlier unlock is never reused.
- The key itself never leaves the Secure Enclave. Its `dataRepresentation` is an encrypted blob that only
  this Mac's Secure Enclave can use. It's stored in the user's **login keychain** as a generic password whose
  access list trusts **only Farrier's signing identity** (its designated requirement). No entitlement or provisioning profile is needed.
- The item's label carries the warning, because keychain dialogs display it:
  *"Farrier approval key — Farrier never asks for this. Click Deny."* (spike finding F2)

Why not keep the blob in a plain file (the spike's "Approach A")? Any process running as the user could
then use it, and it controls the name and text in the prompt (finding F1). In the keychain, any binary other
than Farrier gets a keychain dialog plus a login-password request **before** it can reach the signing prompt.
The same keychain also refuses SSH sessions (finding F4).

**Enrollment**
- `farrier setup` creates the key and calls the helper's `enrollApprovalKey`. The helper requires **admin**
  authorization for this, so a same-user process can't swap in its own key.
- How it works (verified):
  - At startup, the helper defines its own right, `dev.farrier.enroll-approval-key`, with the rule
    `authenticate-admin`, in the authorization database.
  - The client sends an `AuthorizationExternalForm`. The helper requests the right with interaction allowed.
  - The admin dialog appears in the user's session, credited to the **app**: *"enroll a Farrier approval key —
    Enter your password to continue with 'Farrier'."*
  - It asks every time, with no silent reuse. Cancel returns `errAuthorizationCanceled` (-60006).
- The helper stores the public key at `/Library/Application Support/Farrier/approval-key.pub`. It sets
  `root:wheel` and `0644` **explicitly**: in the spike, the group was inherited as `admin`. Changing the key later
  means re-enrolling, which is journaled and needs admin authorization again.
- **Full Disk Access for the helper.** Setup asks the user to grant Full Disk Access to `Farrier.app`. That grant
  covers the helper, the LaunchDaemon in the bundle (verified). Farrier detects whether the grant is there by having
  the helper try a known protected read, opens System Settings → Privacy & Security → Full Disk Access when it's
  missing, and reports TCC-dependent checks as "unknown (no Full Disk Access)" rather than as passed or failed.
- The authorization right stays in the system database until removed, so **uninstall must remove it**
  (`security authorizationdb remove`). The database also records the identity of the code that created the right.

**Approval flow**
1. The client calls `beginApproval(planHash)`. The helper returns a one-time 32-byte nonce and an expiry
   (default 5 minutes; the spike used 60 s). Nonces live in the helper's memory.
2. The client builds the payload:
   `"farrier-plan-approval-v1" 0x00 | planHash (32) | nonce (32) | expiresAt (int64 BE)`.
3. It reads the key blob from the keychain and signs the payload. That triggers the prompt, whose text Farrier
   **derives from the plan itself**, never from arguments or agent text. For example:
   *"farrier is trying to approve plan 3f9a…: delete 2 APFS snapshots (12.4 GB), irreversible."*
   The prompt names the **executable file name**, so the binary must be called `farrier`.
4. The client sends the plan's canonical bytes, the payload and the signature (ECDSA P-256, DER) to `applyPlan`.
   The helper consumes the nonce (**any submission consumes it**, valid or not), checks that `planHash` and the
   expiry match what it issued and haven't passed, verifies the signature against the enrolled public key, hashes
   the plan bytes itself, requires them to be the plan's exact canonical encoding, and checks the plan's host and
   expiry and that every item is a catalog action with the catalog's tier. Only then does it act. In the spike, a
   replay, a tampered signature and an expired approval were each refused; the product's tests cover these and
   more (`PlanApproval.verify`, tested on Linux).

   Verifying and applying are one verb on purpose: with a separate `submitApproval`, a verified approval would have
   to be remembered and later matched to a plan, which is one more place for the two to come apart.

**Exceptions (accepted risks).** Some findings are known and acceptable, for example a VM's guest tools that are
Developer ID–signed but not notarized. An exception names a rule, a vendor's Apple Team ID (optionally one signing
identifier) and a reason. It only removes **validly signed** items of that team from the rule's list fact; it never
turns an unknown into a pass. Adding or removing one is a T4 plan (`exception.add`, `exception.remove`) approved on
the Mac like any other: the prompt shows the team and the reason, which come from validated parameters. The helper
writes `/Library/Application Support/Farrier/exceptions.json` (root:wheel, 0644); a copy that isn't root-owned or is
writable by others is ignored, so malware running as the user can't accept itself. Each change is journaled.

**Carrying out an item.** Each catalog action is fixed code in the helper that re-checks the Mac first. For
`firewall.enable`: the helper reads the MDM profiles itself and refuses if one manages the firewall, or if it can't
tell; it reads the current state and reports `alreadyCompliant`, or refuses if the state differs from what the plan
recorded; then it runs `socketfilterfw --setglobalstate on` and reports success only if reading the state back shows
the firewall on. `gatekeeper.enable` works the same way with `spctl --global-enable` (or `--master-enable`) and
`spctl --status`. `softwareupdate.enableSecurityAutoInstall` refuses unless the software update settings are exactly
what the plan recorded, and on any MDM-enrolled Mac (a declaration could manage them, and declarations can't be read
yet); it sets `CriticalUpdateInstall` and `ConfigDataInstall` with `defaults write` and checks each with `defaults
read`. Every outcome goes to the helper's journal.

**Console-session check (required, verified).** The helper accepts approval-related calls (`beginApproval`,
`applyPlan`, enrollment, revocation) only from the user session at the screen. For each call:
1. Take the caller's audit session ID from the XPC connection (`NSXPCConnection.auditSessionIdentifier`).
2. Call `SessionGetInfo` on it. This works from root for another process's session. Require the session to have
   **graphics access** (bit `0x0010`) and **not be remote** (bit `0x1000`).
3. Require the caller's effective UID to be the **console user** (`SCDynamicStoreCopyConsoleUser`).

Spike results:

| Caller | Session bits | Result |
|---|---|---|
| Terminal at the screen | `0x6030` | accepted |
| SSH | `0x5020` (no graphics, remote) | refused before any prompt |
| `sudo` at the screen | `0x6030` | refused |

`sudo` stays in the console's audit session, so **step 3 is essential**: step 2 alone would accept it.

Why it's mandatory: a prompt *can* be triggered from SSH and appears on the screen (Secure Enclave spike, F4).
The keychain blocks that by default, but not if an attacker who knows the password unlocks the keychain over SSH.

**Integrity check (verified).** At startup, Farrier reads the key item's access list (`SecKeychainItemCopyAccess`).
The decrypt/sign entry must trust only Farrier, which the keychain records as the **bundle path**, and the
change-ACL entry must trust no application. If anything else is trusted (for example, after a user clicked
"Always Allow" in an attacker's dialog), **Farrier rotates the key**, not just warns: delete it, create a new one,
and re-enroll with admin authorization.

Rotation is necessary because "Always Allow" means the other program has already been able to read the key blob,
and the blob can be used from any process (finding F1). In the spike, the access list detected
`/usr/bin/security` after "Always Allow", and `security` had indeed printed the blob.

The check is strict: any app other than Farrier on an entry that grants access to the secret (decrypt, derive,
export, sign, MAC), an entry like that open to *any* application, or **any** app allowed to change the access list,
counts as a failure. If the access list can't be read, the check fails closed.

**Limit:** a one-time "Allow" in a keychain dialog also hands over the blob, but leaves the access list unchanged,
so this check cannot see it. That's why the key is also **rotated periodically** (planned: every 30 days). See
THREAT_MODEL.md, T-3, for the residual risk and the longer-term fix (binding the key's use to Farrier's code identity).

**Apply.** `farrier apply <id>` (or the `apply_plan` tool) loads the plan, checks that the
hash and expiry are valid, and re-fingerprints every item. Any mismatch drops that item and
reports it, so a file swapped after planning (time-of-check to time-of-use, TOCTOU) is not acted on. User-owned items are applied in-process.
Root-owned items go to the helper together with the proof.

## Quarantine

- The user quarantine is `~/Library/Application Support/Farrier/Quarantine/<plan-id>/`. The root
  quarantine is `/Library/Application Support/Farrier/Quarantine/<plan-id>/` (mode 0700, owned by root).
- Items are **renamed** (moved) on the same volume, so quarantining is instant and uses no
  extra space. Items on another volume are skipped and reported, never copied and deleted.
- `manifest.json` maps each original path to its quarantined path and metadata.
- The default retention is 7 days. Expiring quarantine is itself a T3 operation. The scheduled
  expiry runs as a T3 plan that the user pre-approved when changing the setting.
- Disk space is not actually freed until the retention window expires. Reports show **reclaimable
  now** and **reclaimable after expiry** separately, so nobody is misled.

## Journal

- JSONL. Each entry has a timestamp, actor (`cli` | `mcp:<client name>`), plan ID, item, result,
  and `prevHash`.
- The user journal lives in `~/Library/Application Support/Farrier/journal.jsonl`. The helper keeps its own
  root-owned journal. `farrier journal verify` checks both hash chains.

## Managed-device awareness

At startup, Farrier collects enrollment state (`profiles status -type enrollment`) and
installed profile payloads. Each posture rule declares which payload keys can enforce it. If a
profile enforces a setting:

- the finding is labeled `managed`, along with the profile identifier
- remediation for it is **disabled**, and the result says who owns the setting

## Management adapters

```swift
protocol ManagementAdapter {
    static var id: String { get }
    func detect() async -> AdapterPresence          // is this device enrolled?
    func deviceRecord() async throws -> DeviceRecord
    func report(findings: [Finding]) async throws   // optional write-back
}
```

**JumpCloud (reference adapter).** It uses System Context Authorization: requests are signed
with the JumpCloud agent's device key, so no admin API key lives on the machine. The key
is readable only by root, so all adapter calls go through the helper's `adapterRequest` verb.
Planned uses:

- compare local posture with the device record and applied policies
- optionally write findings back (for example, a description or attribute) so that dynamic groups and
  policies in JumpCloud perform the remediation

Rule: **Farrier diagnoses, the management plane enforces.**

## Repository layout (planned)

```
Farrier/
├─ Package.swift
├─ Sources/
│  ├─ FarrierCore/         # library: Collectors, Rules, Planner, Executor, …
│  ├─ FarrierHelperKit/    # shared XPC protocol + payload types (client & helper)
│  ├─ farrier/             # CLI + `farrier mcp`
│  └─ farrier-helper/      # privileged daemon
├─ App/                    # Farrier.app bundle wrapper, Info.plist, LaunchDaemon plist, entitlements
├─ rules/                  # bundled rule packs (YAML), signed with the release
├─ Tests/
│  ├─ FarrierCoreTests/
│  └─ Fixtures/<macOS-version>/   # captured CLI outputs for parser golden tests
├─ docs/
└─ scripts/                # build, sign, notarize, release
```

## Platform

- macOS 14 or later. That gives `SMAppService` and `setCodeSigningRequirement`, and keeps the version matrix small.
- Apple silicon is the primary target, and Intel is best-effort (tested in CI where runners exist).
- Swift 6 with strict concurrency.

## Out of scope

- **EndpointSecurity / real-time monitoring.** It needs an entitlement Apple grants selectively.
- **UI automation (clicks, keystrokes).** Other projects already cover it, and it conflicts with Farrier's safety model.
- **Remote or multi-host management.** Use your MDM for that. Farrier is one machine, operated locally.
