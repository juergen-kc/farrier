# Spike: Swift MCP SDK

The third v0.0 spike. It checks whether the official Swift MCP SDK can carry Farrier's MCP server, and how an AI
client (Claude Code, Claude Desktop) interacts with Farrier's trust boundary.

**The code lives in [`../smappservice-xpc`](../smappservice-xpc/).** In the product, `farrier mcp` runs inside the
same signed binary as the CLI and talks to the same root helper. So the spike adds an `mcp` command to that spike's
client instead of building a separate app. See `Sources/farrier-spike/MCPServer.swift` and `Approval.swift`, plus
the `tccProbe` verb in the helper.

## What we already know (from reading the SDK source, not yet run)

- **Version:** the latest release is **0.12.1** (2026-04-29); `main` was last changed on 2026-11-15. The public
  server API is the same in both. The spike pins `exact: "0.12.1"`.
- **Protocol versions:** the SDK supports `2025-11-25`, `2025-06-18`, `2025-03-26` and `2024-11-05`, **not
  `2026-07-28`**. If a client asks for an unsupported version, the server answers with its latest
  (`2025-11-25`), and it's up to the client whether to continue.
- **No Tasks extension.** Long operations need another approach (progress notifications, or splitting the work
  into start and poll tools).
- **Supported:** tools with `annotations` (readOnly/destructive/idempotent/openWorld hints), `outputSchema` and
  `structuredContent`; resources; prompts; progress notifications; logging; server `instructions`; a stdio
  transport.
- **Build requirements:** the SDK declares `swift-tools-version:6.1` (Xcode 16.3 or later) and macOS 13+.
  Dependencies: swift-system, swift-log, and eventsource (Apple platforms).

## Questions

1. **Build and packaging.** Does it build into the signed app's main executable? What does it add (binary size,
   dependencies)?
2. **Protocol negotiation.** What version does Claude Code ask for, what does it get, and does it work? Does the client
   advertise anything the SDK can't handle (for example Tasks)?
3. **Stdout hygiene.** Is every stdout line a protocol message?
4. **Tool metadata in the client.** Does Claude Code use the annotations, for example by asking permission for
   destructive tools only? Does it use `structuredContent`? Are resources, prompts and server instructions surfaced?
5. **TCC attribution (important).** When Claude Code (or Terminal) starts `farrier mcp`, whose Full Disk Access
   applies: Farrier's, or that of the app at the top of the process chain? If it's the latter, privileged reads
   must go through the helper. Does the helper (started by launchd) get Farrier's FDA?
6. **Session check via an agent.** Does the helper accept calls from an MCP server started by Claude Code (and by
   Claude Desktop)? It should: they run in the console session.
7. **Approval triggered by an agent.** Does the Touch ID or password prompt appear when the agent calls a
   destructive tool? What does the client do while the tool blocks? What happens when the user cancels?
8. **Long operations.** When does the client time out? Are progress notifications shown, and do they keep the call alive?

## Tools exposed by the spike server

| Tool | Annotations | Purpose |
|---|---|---|
| `system_info` | readOnly, idempotent | identity, signature, process chain, SSH or console; has an `outputSchema` |
| `tcc_probe` | readOnly | try to read FDA-protected locations; optionally the user folders; optionally via the helper |
| `helper_whoami` | readOnly | the helper's console-session decision for this caller |
| `approve_test_plan` | **destructive** | full approval round trip (prompt on the Mac); changes nothing |
| `slow_operation` | readOnly | waits N seconds, sending progress if the client asked for it |

Plus one resource (`farrier-spike://info`) and one prompt (`why-did-it-wake`).

Every MCP message is logged to `~/Library/Logs/FarrierSpike/mcp-wire.log`.
