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
- `farrier mcp` starts the stdio MCP server. It runs inside the same signed binary, so Full Disk Access
  (FDA) and other TCC grants apply to one stable identity, not to a terminal or interpreter.

### `farrier mcp` (MCP server)

- Built on the official Swift MCP SDK. **SPIKE:** confirm SDK support for the 2026-07-28 spec
  and the Tasks extension.
- It is a thin layer: each tool calls one FarrierCore function and returns its result as
  structured content with an output schema.
- Tool annotations come from the operation's tier (see [TOOLS.md](TOOLS.md)).
- Long operations (full-disk scans, updates, sysdiagnose) use the **Tasks** extension, with a
  synchronous fallback when the client doesn't support it.
- Exposes **resources** (`farrier://posture/latest`, `farrier://snapshot/{id}`,
  `farrier://journal/recent`) and **prompts** (debugging runbooks).
- There is no `apply` path that bypasses on-device approval. Approval comes from LocalAuthentication,
  not from MCP elicitation, because elicitation is answered by the AI client, which is the thing we don't fully
  trust.

### `farrier-helper` (privileged helper)

- Registered with `SMAppService.daemon(plistName:)` from
  `Farrier.app/Contents/Library/LaunchDaemons/`. The user approves it once in
  System Settings → General → Login Items & Extensions.
- Listens on one Mach service. On every incoming connection it calls
  `NSXPCConnection.setCodeSigningRequirement(_:)` with a requirement pinned to Farrier's
  bundle identifier **and** Team ID. The client checks the helper the same way.
- The protocol is a small `@objc` interface that passes versioned `Codable` payloads as `Data`.
- It runs **only fixed verbs**. There is no "run this command" verb. The initial verb set:

  | Verb | Purpose |
  |---|---|
  | `readPrivileged(fact)` | Read root-only facts: system TCC.db, `/Library` launchd plists with full detail, firewall state, JumpCloud agent config |
  | `quarantine(items, planProof)` | Move root-owned items into root quarantine |
  | `restore(planID)` / `expireQuarantine()` | Restore items, or expire them after the retention window |
  | `deleteLocalSnapshot(name, planProof)` | Delete an APFS local snapshot (irreversible, so it is T3) |
  | `setSystemSetting(key, value, planProof)` | Change an allowlisted setting (firewall on, stealth mode, etc.) |
  | `uninstallPkgReceipt(id, planProof)` | Remove installer receipts and files listed in a bill of materials (BOM) |
  | `adapterRequest(adapter, op, planProof?)` | Make a signed management-plane call (JumpCloud System Context) |

- The helper **re-validates** every item itself. It does not trust the client's plan contents.
  It resolves paths with `O_NOFOLLOW` on each path component, checks owner, mode and inode against what the plan
  recorded, rejects anything outside the allowed roots for that rule, and never follows symlinks.
- It exits when idle (launchd on demand), so nothing runs between uses.

## Operation tiers

Every operation and every plan item has a tier. The tier drives MCP annotations, approval,
and logging.

| Tier | Meaning | Example | Approval |
|---|---|---|---|
| **T0** read | Read user-accessible state | posture (unprivileged part), disk usage | none |
| **T1** privileged read | Read via the helper | system TCC.db, root launchd details | none (helper checks the client signature) |
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
                     ~/.farrier/plans/<id>.json   LocalAuthentication  quarantine / helper
```

**Plan.** Canonical JSON with `id`, `createdAt`, `expiresAt` (default 15 min), `tier`,
`host` (hardware UUID), and `items[]`. Each item records the rule ID, target, size, last use,
evidence (why it matched and why it's safe), and a fingerprint (device, inode, size, mtime,
owner). `planHash` is the SHA-256 of the canonical encoding.

**Approve.** For T3 and T4, the user process asks LocalAuthentication to authenticate the user,
showing a summary of the plan (counts, total size, tier). The approval yields a `planProof`.

**SPIKE: approval the helper can verify.** The preferred design is a Secure Enclave P-256 key that is
created at install with `.userPresence` access control, and whose public key the helper stores in a root-owned file.
Approval means signing `planHash` with that key, which triggers Touch ID. The helper then checks the
signature, so a compromised user process can't forge approval without the user's finger.
Open question: whether Developer ID distribution (no provisioning profile) can create and use
Secure Enclave keys with the needed keychain entitlement. If it can't, the fallback is
LocalAuthentication in the signed client, with the helper trusting the code-signing requirement.
That is weaker, and the threat model records it as such.

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
