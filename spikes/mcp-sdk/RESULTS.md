# Results

Fill this in while working through [CHECKLIST.md](CHECKLIST.md).

## Test machine

| | |
|---|---|
| Date | |
| Mac model / VM | |
| macOS version | |
| Swift version (`swift --version`) | |
| Claude Code version (`claude --version`) | |
| Claude Desktop version (optional) | |

## Build and protocol

| Test | Result | notes |
|---|---|---|
| M0 build (fixes needed?) | | |
| M1 binary size: before / after | | |
| M1b ping and approve still work | | |
| M2 negotiation: asked 2026-07-28 → got | | |
| M3 stdout hygiene | | |
| M3b wire log | | |

## Claude Code

| Test | Result | notes |
|---|---|---|
| M4 connected, `/mcp` | | |
| M5 version asked / got; client capabilities | | |
| M6 read-only tool: permission asked? result shown how? | | process chain: |
| M7 destructive tool: permission wording | | |
| M7 prompt appeared (screenshot) | | |
| M7 waiting about 60 s before approving | | |
| M7 cancel → reported how | | |
| M8 helper_whoami via the agent | | asid vs Terminal: |
| M9 resource / prompt / instructions | | |
| M10 slow_operation 30 / 120 / 300 s | | timeout at: ; progress token: |

## TCC attribution

FDA held by (record per state): Terminal / Claude / FarrierSpike

| State | Probe | TCC.db | Safari | Mail | Messages | Caches |
|---|---|---|---|---|---|---|
| A (none) | CLI from Terminal | | | | | |
| A | helper | | | | | |
| A | via Claude Code | | | | | |
| B (FarrierSpike) | CLI from Terminal | | | | | |
| B | helper | | | | | |
| B | via Claude Code | | | | | |
| C (Terminal) | CLI from Terminal | | | | | |
| C | helper | | | | | |
| C | via Claude Code | | | | | |

M14 user-folder dialog names:

## Claude Desktop (optional)

| Test | Result | notes |
|---|---|---|
| M15 process chain / sessionOK / prompt / tcc | | |

## Conclusions

- SDK suitable for v0.1: [ ] yes / [ ] with workarounds / [ ] no
- Protocol version gap (2025-11-25 vs 2026-07-28): impact:
- Annotations honoured by Claude Code:
- Privileged reads must go through: [ ] the CLI's own FDA / [ ] the helper
- Long operations:

ARCHITECTURE.md and THREAT_MODEL.md updated: [ ]
