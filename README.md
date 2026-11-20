# Farrier

**Keep your Mac sound, from the command line or from an AI agent.**

Farrier is an open-source macOS administration toolkit for system hygiene, cleanup,
security posture, drift detection, patching, and debugging. It ships as one signed CLI
(`farrier`), an MCP server (`farrier mcp`) for AI agents such as Claude Code, and a small
privileged helper for the parts that need root.

There is no GUI. You drive it by typing commands, or by asking an agent:

> "Why did my Mac wake up at 3am?"
> "Free 20 GB without touching anything I made myself."
> "Is this machine CIS level 1 compliant? Fix what's safe to fix."
> "What changed on this Mac since last Monday?"

> **Status:** early development (v0.1 in progress). The design is validated by three spikes (`spikes/`). What runs
> today: the rule-pack loader and linter, unprivileged fact collection, and posture evaluation. The macOS collectors, the
> privileged helper and the MCP server come next. The interface below is the target.

---

## Why this exists

Existing "AI controls your Mac" servers give the model **hands**: clicks, keystrokes and a
raw shell. Their own READMEs say to use them only in a VM.

Farrier gives the model **knowledge**: a set of typed, scoped operations with known
blast radius. Every change is:

- **Planned before it runs.** Mutations return a plan that lists each item, its size,
  and why it is safe. Nothing runs until the plan is applied.
- **Approved by a human on the device.** Destructive and privileged plans need Touch ID
  (or the login password). An agent cannot fake this.
- **Reversible by default.** Deleted files go to quarantine first, with a retention window.
- **Journaled.** There is an append-only, hash-chained log of every change.

## What it does

| Area | Examples |
|---|---|
| **Hygiene and cleanup** | Caches, logs, Xcode DerivedData and simulators, build artifacts (`node_modules`, `target`, `.build`), Homebrew and Docker leftovers, old iOS backups, APFS local snapshots, full app uninstall with leftovers |
| **Posture** | FileVault, SIP, Gatekeeper, firewall, XProtect freshness, update settings, sharing services, login items and background tasks, launchd jobs with signature and notarization status, profiles, system extensions, TCC grants, admin accounts. Checks map to [mSCP](https://github.com/usnistgov/macos_security) / CIS rule IDs. |
| **Inventory and drift** | Snapshot system state, then diff it later to find new launch agents, profiles, admins, extensions or listening ports |
| **Patching** | macOS updates, Homebrew, Mac App Store, and third-party apps |
| **Debugging** | Unified log queries, wake and sleep history, crash and panic report analysis, network diagnostics, disk usage explained |
| **Management adapters** | Optional connectors to device-management platforms. JumpCloud (System Context API) is the reference adapter. |

## Design principles

1. **No generic shell.** Every operation is an allowlisted verb with a declared tier.
2. **Rules are data.** Cleanup targets and posture checks are YAML rule packs that anyone
   can review and contribute to without writing Swift.
3. **Respect the owner of a setting.** On MDM-managed Macs, settings enforced by a profile
   are reported, never changed.
4. **No telemetry.** Farrier sends nothing anywhere. (The AI client you connect is a separate matter. See
   [Privacy](docs/THREAT_MODEL.md#privacy-what-leaves-the-machine).)
5. **The CLI is the product.** MCP is a thin layer over it, and everything an agent can do,
   you can do in a terminal with `--json`.

## Try it (today)

Requires Swift 6.1 or later (Xcode 16.3+ on macOS, or a Swift toolchain on Linux).

```bash
swift run farrier facts
```

```bash
swift run farrier posture
```

```bash
swift run farrier rules lint rules
```

**The privileged helper** (for facts that need root, and later for fixes) only works from a signed `Farrier.app`:

```bash
SIGN_IDENTITY="Apple Development: …" ./scripts/build-app.sh
```

```bash
sudo rm -rf /Applications/Farrier.app && sudo ditto build/Farrier.app /Applications/Farrier.app && sudo chown -R root:wheel /Applications/Farrier.app
```

```bash
/Applications/Farrier.app/Contents/MacOS/farrier helper register
```

`farrier facts` and `farrier posture` read this Mac's settings without privileges. Facts that need the helper show
as unknown for now (see [docs/FACTS.md](docs/FACTS.md)). On Linux, or to test rules, use
`swift run farrier posture --facts examples/facts-sample.json`.

## A quick look (planned interface)

```bash
farrier posture                      # run posture checks
farrier cleanup plan --min-age 30d   # produce a cleanup plan (nothing is deleted)
farrier apply <plan-id>              # apply it (Touch ID if required)
farrier restore <plan-id>            # undo it from quarantine
farrier snapshot && farrier drift    # take a baseline, then diff against it
farrier explain wake --since 24h     # debugging runbook
```

Connecting it to Claude Code:

```bash
claude mcp add farrier -- farrier mcp
```

## Requirements (planned)

- macOS 14 Sonoma or later. Apple silicon is the primary target, and Intel is best-effort.
- Distributed as a signed, notarized `Farrier.app` bundle (no UI), which contains the CLI
  and the privileged helper. Install with Homebrew (`brew install --cask farrier`, which also adds the
  `farrier` command) or download the bundle from GitHub Releases.
- On first setup, macOS asks you to allow Farrier's background helper ("App Background Activity"), and Farrier
  asks for an admin password once, to enroll its approval key. For posture checks that touch privacy-protected
  data, you also give Farrier **Full Disk Access** once. Only its root helper uses that access, never the
  terminal or AI client it runs in.

## Documentation

- [Architecture](docs/ARCHITECTURE.md): components, the privileged helper, the plan and apply flow, quarantine
- [Threat model](docs/THREAT_MODEL.md): what we defend against, and what we don't
- [MCP tools](docs/TOOLS.md): the tool catalog, with tiers and annotations
- [Rule packs](docs/RULE_PACKS.md): format for cleanup and posture rules
- [Roadmap](docs/ROADMAP.md)
- [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md)

## License

Apache License 2.0. See [LICENSE](LICENSE).
