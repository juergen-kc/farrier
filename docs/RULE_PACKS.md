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
    minAge: 14d                    # since anything inside was last written or read
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
| `targets[].exclude` | no | Names (globs on the last component) never matched, for example `com.apple.*` under `~/Library/Caches` |
| `regenerable` | yes | `true` only if the owning app recreates the data without user action |
| `minAge`, `minSize` | no | `minAge` counts from the newest modification of anything inside, or the newest access of a file inside (folder access times aren't used: listing a folder changes them). A run can raise it (`--min-age`), never lower it. |
| `when` | no | Preconditions: `processNotRunning`, `appInstalled`, `appNotInstalled` (orphan detection) |
| `privileged` | no | `true` means the privileged helper scans and moves it (bundled packs only, T2, targets only inside `/Library/Caches` or `/Library/Logs`). Targets outside home folders must be privileged. |
| `evidence` | yes | Plain-language reason it's safe. It is shown in every plan. |

Globs: `*` and `?` match within one component and never match a leading dot; `**` matches any number of folders
(at most 12). Symlinks are never followed. When several rules match the same path, the target with the longest literal
prefix keeps it (Homebrew downloads over all caches), and a match inside another match is counted once, with the outer one. A folder that can't be read completely (no permission,
or more than 200,000 entries) is left out of a rule with a minimum age, because what wasn't seen could be recent; the
report counts these as `incomplete`.

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
    managedBy:                      # what can enforce this setting (MDM payloads, managed preferences)
      - payloadType: com.apple.MCX.FileVault2
      - { preference: com.apple.MCX, keys: [dontAllowFDEDisable] }
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
| `managedBy` | no | Each entry is one of `payloadType` (configuration profiles), `declarationType` (Declarative Device Management), or `preference` (a managed preference domain, with optional `keys`: any profile can set those, e.g. with Custom Settings, and they override local settings). If one is present, the finding is `managed` (with the profile's name when it's known) and is not fixable locally. If what an entry needs can't be read, the finding is `managementUnknown` and not fixable either. |
| `remediation.automatic` | yes | `true` requires `remediation.action`, which names an allowlisted helper setting (T4) |
| `mappings` | no | Benchmark IDs (mSCP, CIS, NIST 800-53) |

## Testing a rule

```bash
farrier rules lint rules/                         # schema and safety checks
farrier rules test dev.xcode.derived-data --fixture Tests/Fixtures/home-dev
farrier cleanup plan --rule dev.xcode.derived-data --json
```

Every bundled rule needs a fixture test. CI rejects rules that could match a protected path.
