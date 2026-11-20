# Contributing to Farrier

Thanks for helping. There are three main ways to contribute, from easiest to hardest:

1. **Rule packs.** Add a cleanup location or a posture check in YAML. No Swift needed.
   See [docs/RULE_PACKS.md](docs/RULE_PACKS.md).
2. **Fixtures.** Capture Apple CLI output from a macOS version or configuration we don't cover yet
   (`scripts/capture-fixtures.sh`, planned). Parsers live or die by these fixtures.
3. **Code.** Collectors, tools, adapters, and the helper.

## Ground rules

- **Safety beats coverage.** A cleanup rule must explain why it is safe, in its `evidence` field. If
  you can't explain it, it doesn't belong in a bundled pack.
- **No new helper verbs without a threat-model update.** Changes to `farrier-helper` or
  `FarrierHelperKit` need an update to [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) in the same
  pull request, and a review from a maintainer listed as a helper owner in `CODEOWNERS`.
- **No shell strings.** Call external tools by absolute path with fixed argument arrays.
- **No telemetry, ever.**

## Development

Requires Swift 6.1 or later: Xcode 16.3+ on macOS 14+, or a Swift toolchain on Linux. `FarrierCore` and the
CLI build on Linux; the macOS-only parts (collectors, helper, MCP server) will be separate targets. CI runs on
both (`.github/workflows/ci.yml`).

```bash
swift build
```

```bash
swift test
```

```bash
swift run farrier rules lint rules
```

```bash
swift run farrier posture --facts examples/facts-sample.json
```

Tests use Swift Testing (`import Testing`). Every rule-pack behaviour, and especially every safety rule (protected
paths, user-pack limits), needs a test in `Tests/FarrierCoreTests`.

The helper will need a signed build to register with `SMAppService` (planned: `scripts/dev-sign.sh`). Until then,
see `spikes/smappservice-xpc/` for how signing and installation work.

## Pull requests

- Keep each PR focused. Rules, collectors and helper changes go in separate PRs where possible.
- Add or update tests and fixtures.
- Sign off your commits (Developer Certificate of Origin):
  `git commit -s`. This certifies you wrote the change or have the right to submit it under
  Apache-2.0. See <https://developercertificate.org>.

## Code style

- Swift 6, strict concurrency, `swift-format` with the repo config.
- Public types in `FarrierCore` are documented.
- Errors are typed and include actionable messages. They never include secrets or full file contents.
