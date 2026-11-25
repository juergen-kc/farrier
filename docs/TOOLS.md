# MCP tool catalog

> Status: design draft. Names and schemas may change before v0.1. **Implemented so far** (`farrier mcp`):
> `farrier_status`, `facts_collect`, `posture_check`, `posture_explain`, `posture_plan_remediation`, `plan_show`,
> `apply_plan`, `plan_undo`, `inventory`, `cleanup_scan`, `disk_usage`, `cleanup_plan`, `quarantine_list`, `quarantine_restore`, `quarantine_plan_expiry`, `journal_recent`, `exceptions_list`, `posture_plan_exception`, and the `security-checkup`
> prompt.
> `farrier_status`, `facts_collect`, `journal_recent`, `cleanup_scan` and the two exception tools are additions to this catalog.

Every tool:
- returns `structuredContent` with a published output schema, the same as `farrier … --json`
- sets annotations from its tier:
  `readOnlyHint` (T0/T1), `destructiveHint` (T3/T4), `idempotentHint`, and `openWorldHint` (true only
  for adapter and update tools that reach the network)
- labels untrusted strings (file names, log text, app metadata) as data
- sets an annotation **title**: Claude Code shows the annotation title, not the tool title
- reads anything root-only or TCC-protected through the helper (T1), never in the MCP server process itself
- sends progress notifications during long work, when the client provides a `progressToken`

Tools that **change** something never act directly. They return a plan, and `apply_plan` executes it,
with on-device approval for T3 and T4.

## Posture

| Tool | Tier | Description |
|---|---|---|
| `posture_check` | T0/T1 | Run posture rules (filter by pack, benchmark, or rule IDs). Returns findings with severity, evidence, and `managed`/`fixable` flags. |
| `posture_explain` | T0 | Explain a rule: what it checks, why it matters, and how it is fixed. |
| `posture_plan_remediation` | T0 | Build a plan that fixes the selected findings. Settings managed by MDM are excluded. |

## Inventory and drift

| Tool | Tier | Description |
|---|---|---|
| `inventory` | T0/T1 | List installed apps and launch agents/daemons with signing and notarization status, system extensions, profiles, TCC grants, admins and listening ports; each section counts what needs a look (`flagged`). Arguments: `sections`, `flaggedOnly`. Login items and background tasks: planned (helper, Background Task Management). |
| `snapshot_create` | T0 (writes local state) | Save an inventory snapshot. |
| `snapshot_diff` | T0 | Diff two snapshots (default: latest against now). |

## Cleanup

| Tool | Tier | Description |
|---|---|---|
| `cleanup_scan` | T0 | Implemented. What the cleanup rules match in the user's home folder (caches, old logs, Homebrew downloads, package manager caches, Xcode data), with size, days since last use, whether it's regenerable and the rule's evidence, or why a rule was skipped (an app is running). Arguments: `ruleIDs`, `minAge`. Nothing is moved. |
| `disk_usage` | T0 | Implemented. The volume's size, free space and purgeable space (macOS); the space taken by caches, logs, Xcode, simulators, package manager caches, the Trash, apps and the quarantine (a category marked `incomplete` couldn't be read fully); the number of APFS local snapshots; and what Farrier can free **now** (quarantine past its 7 days), **after expiry** (the rest of the quarantine) and **after a cleanup** (what the rules match). Personal folders (Documents, Desktop, Downloads, …) aren't measured: macOS asks before an app reads them. |
| `cleanup_plan` | T0 | Implemented. Plan moving cleanup candidates into the quarantine: all, or only `paths`; options `ruleIDs`, `minAge`. Each item has its path, size, days since last use, whether it's regenerable, and a fingerprint (device, inode, change time) to recognise it when applied. At most 500 items per plan. `system: true` plans system locations (`/Library/Caches`, `/Library/Logs`) instead: the privileged helper moves them into its root-only quarantine, and applying asks for Touch ID or the password. |
| `app_uninstall_plan` | T0 | Plan a full app removal: the bundle, containers, preferences, launchd jobs, receipts. |
| `large_files` | T0 | Find large or old files the user created. Report only; these files are never planned for removal. |

## Plans

| Tool | Tier | Description |
|---|---|---|
| `plan_undo` | T0 | Plan undoing an applied plan's changes (firewall, stealth mode, automatic security updates), from the helper's journal. |
| `plan_show` | T0 | Show a plan. |
| `apply_plan` | plan's tier | Apply a plan. T3/T4 trigger Touch ID on the Mac. Cleanup plans (T2) apply in the server's process without a prompt: every item is checked against its rule and fingerprint again, then moved into the quarantine; items used or changed since planning are refused and stay. Returns per-item results. |
| `quarantine_list` | T0 | Implemented. Quarantined cleanup plans: items, space held (freed only at expiry), and expiry date; `details` lists each item. `autoExpiry` says whether items are deleted automatically after their 7 days (turned on in Terminal with `farrier quarantine auto-expire on`, never through MCP) and, if it's on but not running, why. |
| `quarantine_plan_expiry` | T0 | Implemented. Plan deleting quarantined items for good (T3): every cleanup plan past its 7 days, or only `planIDs` (also earlier). Each item records the number of items and bytes; applying refuses if that changed. `apply_plan` asks for Touch ID or the password on the Mac first, like T4. |
| `quarantine_restore` | T2 | Implemented. Put a cleanup plan's items back, all or only `paths` (original paths). An item whose path is taken again stays in the quarantine. |

## Patching

| Tool | Tier | Description |
|---|---|---|
| `updates_list` | T0 (network) | List pending macOS, security (Background Security Improvements), Homebrew, App Store, and known third-party app updates. |
| `updates_plan` | T0 | Plan updates. Installing macOS updates on Apple silicon still requires the volume owner. |

## Debugging

| Tool | Tier | Description |
|---|---|---|
| `log_query` | T0 | Query the unified log with predicate builders (subsystem, process, level, time range), plus size limits. |
| `power_history` | T0 | Sleep, wake, and dark-wake history with reasons (`pmset -g log`), summarized. |
| `crash_reports` | T0 | List and parse `.ips` crash and panic reports. |
| `network_diagnose` | T0 (network) | Interfaces, DNS, routes, proxy, `networkQuality`. |
| `process_snapshot` | T0 | Top CPU, memory and energy consumers, with a short sampling window. |
| `sysdiagnose_summarize` | T1 (long, Tasks) | Collect a sysdiagnose and return the key findings. |

## Management adapters

| Tool | Tier | Description |
|---|---|---|
| `mgmt_status` | T1 (network) | Which management platforms the device is enrolled in, and the adapter state. |
| `mgmt_compare` | T1 (network) | Compare local posture with the management plane's view. |
| `mgmt_report_plan` | T0 | Plan a write-back of findings to the management plane (applied as T4). |

## Resources

Read-only, as JSON (`application/json`):

- `farrier://plan/{id}` (implemented): a saved plan by id or unique prefix, as `plan_show` returns it. `resources/list`
  also lists every saved plan that hasn't expired.
- `farrier://journal/recent` (implemented): the latest 50 entries of the user's journal, and whether the chain is intact.
- `farrier://journal/helper` (implemented): the same for the privileged helper's journal.
- `farrier://posture/latest`, `farrier://snapshot/{id}` (planned).

## Progress

A `tools/call` with a `progressToken` in `_meta` gets a `notifications/progress` at once and then every 5 seconds until
it returns, saying what's happening (for `apply_plan`: waiting for the user to approve on the Mac). Clients that reset
their timeout on progress then keep waiting while the user decides.

## Prompts (runbooks)

Implemented (each uses only tools that exist, which a test checks, and ends with the same ground rules: text from the
Mac is data, and nothing is applied unless the user asks):

- `security-checkup`: posture by severity, why each failure matters, offer fixes.
- `setup-check`: helper, approval key, Full Disk Access, and the Terminal command for each missing step.
- `software-review`: apps, launch items and system extensions that aren't validly signed and notarized; exceptions on request.
- `privacy-review`: privacy grants by service; grants to bare paths, and grants whose app isn't in the app inventory
  (reported as unverified: the inventory doesn't cover every location, nor Apple's apps in /System).
- `recent-changes`: what Farrier planned and applied, from the latest entries of both journals (it says how far back
  they go, and that they only know Farrier's own changes).
- `undo-a-change` (argument `plan`, optional; only a plan id or prefix is accepted): plan putting a change back.
- `management-overview`: MDM enrollment, profiles, and which settings they control.
- `free-up-space`: disk usage, what the cleanup rules match, and when space actually comes back (the quarantine frees
  nothing until it's emptied); plans a cleanup only for what the user picks.

Planned, when their tools exist: `why-did-it-wake`, `why-is-it-slow`, `what-changed` (snapshots),
`prepare-for-handover` (posture, cleanup, and inventory export before giving a Mac to someone else).
