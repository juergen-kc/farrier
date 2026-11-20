# Results

Fill this in while working through [CHECKLIST.md](CHECKLIST.md).

## Test machine

| | |
|---|---|
| Date | 2026-11-20 |
| Mac model / VM | VirtualMac2,1 (macOS VM) |
| macOS version | 27.2.1 (26B131) |
| Swift version (`swift --version`) | Apple Swift 6.4.2 (Xcode, macOS 27.2 SDK) |
| Claude Code version (`claude --version`) | |
| Claude Desktop version (optional) | |

## Build and protocol

| Test | Result | notes |
|---|---|---|
| M0 build (fixes needed?) | ✅ after 1 fix | `structuredContent: toValue(d)` resolved to the generic, throwing `init<Output: Codable>` (because `Value` is Codable). Passing `as Value?` selects the plain init. SPM resolved: swift-sdk 0.12.1, swift-log 1.17.2, swift-system 1.9.0, swift-nio 2.105.0, eventsource 1.6.0, swift-atomics 1.3.1, swift-collections 1.7.6. Only the known keychain deprecation warnings appeared in the build output shown (the first build log was cut off at the error). |
| M1 binary size: before / after | 5.2 MB after | spike-2 size before: not recorded |
| M1b ping and approve still work | | |
| M2 negotiation: asked 2026-07-28 → got | ✅ **2025-11-25** | The initialize reply carries capabilities (prompts, resources, tools; listChanged false), `instructions`, and serverInfo (name, title, version). tools/list returns all 5 tools with annotations, titles and the `outputSchema`. `initializeHook` sees the client's name, version and capabilities. |
| M2b stdin closed immediately | ⚠️ **no output** | When `printf` closes stdin right after the requests, the SDK's message loop ends at end-of-input (`-- stopped` is logged **before** the initialize hook runs), `waitUntilCompleted()` returns, and `exit(0)` ends the process before any reply is written. With stdin held open (`( printf …; sleep 3 ) \| $F mcp`), both replies arrive and `exit=0`. **Product:** after `waitUntilCompleted()`, allow a short grace period, or wait for in-flight handlers, before exiting. Real clients keep stdin open, so the impact is low. |
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
