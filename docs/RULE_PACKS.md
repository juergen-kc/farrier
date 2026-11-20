# Rule packs

Cleanup targets and posture checks are **data**: YAML files in `rules/`. You can add a
cleanup location or a posture check without writing Swift.

- **Bundled packs** (`rules/` in this repo) are signed with each release and can use every
  feature.
- **User packs** (`~/.config/farrier/rules/*.yaml`) are restricted. See
  [THREAT_MODEL.md, T-5](THREAT_MODEL.md#t-5-malicious-rule-pack).

Each file has a `pack` header and a list of `rules`. Rule IDs are global and must be stable:
`<pack>.<name>`.

## Cleanup rules

```yaml
pack:
  id: dev.xcode
  title: Xcode developer artifacts
  version: 1

rules:
  - id: dev.xcode.derived-data
    title: Xcode DerivedData
    kind: cleanup
    tier: T2                       # T2 = reversible via quarantine
    targets:
      - path: ~/Library/Developer/Xcode/DerivedData/*
        type: directory
    regenerable: true              # rebuilt automatically when needed
    minAge: 14d                    # based on last access (falls back to mtime)
    when:
      processNotRunning: [Xcode]   # skip while Xcode is open
    evidence: >
      Build intermediates and indexes. Xcode regenerates them on the next build.
      Removing them only costs the time of a clean build.
    references:
      - https://developer.apple.com/documentation/xcode/build-system
```

### Fields

| Field | Required | Notes |
|---|---|---|
| `id`, `title`, `kind` | yes | `kind: cleanup` |
| `tier` | yes | `T2` (quarantine) or `T3` (irreversible, such as APFS snapshots). User packs: `T2` only. |
| `targets[].path` | one of | A glob. `~` is expanded. `**` is allowed only below a fixed prefix. |
| `targets[].fact` | one of | Targets supplied by a collector (for example `simctl.devices.unavailable`) when a glob can't express them. Bundled packs only. |
| `targets[].type` | no | `file` \| `directory` \| `any` (default `any`) |
| `targets[].contains` | no | Marker files that must exist, for example `package.json` next to `node_modules` |
| `regenerable` | yes | `true` only if the owning app recreates the data without user action |
| `minAge`, `minSize` | no | Defaults can be overridden per run |
| `when` | no | Preconditions: `processNotRunning`, `appInstalled`, `appNotInstalled` (orphan detection) |
| `privileged` | no | `true` means the helper applies it (bundled packs only) |
| `evidence` | yes | Plain-language reason it's safe. It is shown in every plan. |

The hardcoded protected paths (`~/Documents`, `~/Desktop`, `~/Pictures`, `~/Movies`, `~/Music`,
iCloud Drive, `~/Library/Mobile Documents`, mail and message stores, keychains, and others)
**override every rule**.

## Posture rules

```yaml
pack:
  id: posture.core
  title: Core macOS security posture
  version: 1

rules:
  - id: posture.core.filevault
    title: FileVault is enabled
    kind: check
    severity: high
    collect:
      fact: filevault.status        # provided by a FarrierCore collector
    expect:
      equals: "On"
    managedBy:                      # MDM payloads that can enforce this setting
      - payloadType: com.apple.MCX.FileVault2
    remediation:
      automatic: false              # enabling FileVault involves recovery-key handling
      guidance: >
        Enable FileVault in System Settings → Privacy & Security → FileVault, or with
        your MDM so the recovery key is escrowed.
    mappings:
      mscp: system_settings_filevault_enforce
      cis_macos_15: "2.6.6"         # verify against the current benchmark
```

### Fields

| Field | Required | Notes |
|---|---|---|
| `kind` | yes | `check` |
| `severity` | yes | `info` \| `low` \| `medium` \| `high` \| `critical` |
| `collect.fact` | yes | A fact ID from a collector. Only bundled collectors exist, so rules can't run commands. |
| `expect` | yes | `equals`, `notEquals`, `in`, `matches`, `lt`/`gt`, `exists`, `all`/`any` (nested). `path` selects a key inside a structured fact, and `each` applies a condition to every element of a list. |
| `managedBy` | no | `payloadType` (configuration profiles) or `declarationType` (Declarative Device Management). If one is present, the finding is `managed` and is not fixable locally. |
| `remediation.automatic` | yes | `true` requires `remediation.action`, which names an allowlisted helper setting (T4) |
| `mappings` | no | Benchmark IDs (mSCP, CIS, NIST 800-53) |

## Testing a rule

```bash
farrier rules lint rules/                         # schema and safety checks
farrier rules test dev.xcode.derived-data --fixture Tests/Fixtures/home-dev
farrier cleanup plan --rule dev.xcode.derived-data --json
```

Every bundled rule needs a fixture test. CI rejects rules that could match a protected path.
