# Test checklist

Run on the macOS VM, with spike 2 (SMAppService/XPC) installed and the approval key enrolled. Record results in
[RESULTS.md](RESULTS.md). **Time needed:** about 60 minutes.

## 0. Build and install

The code is in the spike-2 package:

```bash
cd ~/Downloads/farrier/farrier && git pull && cd spikes/smappservice-xpc
```

```bash
swift --version
```

The SDK needs Swift 6.1 or later. Record the version.

```bash
export SIGN_IDENTITY="Apple Development: Jurgen Klaaben (U366MAP9SE)" && ./scripts/build-app.sh
```

The first build downloads the SDK and its dependencies, so it needs network access.

```bash
sudo rm -rf /Applications/FarrierSpike.app && sudo ditto out/FarrierSpike.app /Applications/FarrierSpike.app && sudo chown -R root:wheel /Applications/FarrierSpike.app
```

The helper protocol gained a verb, so restart the helper:

```bash
sudo launchctl kickstart -k system/dev.farrier.spike.helper
```

```bash
F=/Applications/FarrierSpike.app/Contents/MacOS/farrier-spike; W=~/Library/Logs/FarrierSpike/mcp-wire.log
```

- [ ] **M0 build:** it compiles. Record any fixes and warnings. The MCP code was written against the SDK source
      without a compiler.
- [ ] **M1 size:** `ls -lh $F`. Compare with the spike-2 build (look it up in `git stash` or an older `out/`).
      Also record `swift package show-dependencies --format flatlist`.
- [ ] **M1b:** `$F ping` and `$F approve` still work. The helper was restarted and the refactor shouldn't change anything.

## 1. Protocol by hand (no AI client)

- [ ] **M2 negotiation:** send an `initialize` asking for `2026-07-28`, then `tools/list`. Keep stdin open for a moment
      with `sleep 3`. Without it, the server stops at end-of-input before replying (see M2b in RESULTS.md):

```bash
( printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2026-07-28","capabilities":{},"clientInfo":{"name":"manual","version":"0"}}}' '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'; sleep 3 ) | $F mcp
```

  Expect a reply with `"protocolVersion":"2025-11-25"` (the fallback), then the 5 tools. Record whether the
  server exits cleanly at the end of input.

- [ ] **M3 stdout hygiene:** run the same command, piped into a JSON check. Expect no `BAD` lines:

```bash
( printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"manual","version":"0"}}}' '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"system_info","arguments":{}}}'; sleep 3 ) | $F mcp | while IFS= read -r l; do echo "$l" | python3 -m json.tool >/dev/null 2>&1 || echo "BAD: $l"; done; echo checked
```

- [ ] **M3b wire log:** `tail -5 $W` shows the messages in both directions.

## 2. Claude Code

```bash
claude mcp add farrier-spike -- /Applications/FarrierSpike.app/Contents/MacOS/farrier-spike mcp
```

```bash
claude mcp list
```

- [ ] **M4 connected:** `claude mcp list` shows `farrier-spike` as connected. Start `claude` in a new directory and
      run `/mcp`. Record what it shows: the server, its tools, and any warnings.
- [ ] **M5 negotiated version:** `grep -m3 protocolVersion $W`. Record what Claude Code **asked for** and what it
      **got**. Also record the client's `capabilities` from the `initialize from client=…` line, for example whether it
      advertises tasks, elicitation or sampling.
- [ ] **M6 read-only tool:** ask Claude: *"Call the farrier-spike system_info tool and show me the process chain."*
      Record: did Claude Code ask for permission? How does it show the result: text, structured, or both? Which
      processes are in the chain (expect `farrier-spike`, then Claude Code, the shell, and Terminal)?
- [ ] **M7 destructive tool and the approval prompt:** ask: *"Call approve_test_plan."* Record:
  - [ ] Did Claude Code ask permission **before** calling it? Is the wording different from M6, i.e. does it use `destructiveHint`?
  - [ ] Did the Mac's password or Touch ID prompt appear, with the text "approve Farrier plan …"? Screenshot it.
  - [ ] While the prompt is open, what does Claude Code show? Does it time out if you wait about 60 s before approving?
  - [ ] After approving: `approved: true` and `secondsWaiting`.
  - [ ] Repeat, but click **Cancel** in the prompt. Expect `approved: false`, an `isError` result, and the sign step
        error `LAError -2`. How does Claude Code report it?
- [ ] **M8 session check through the agent:** ask: *"Call helper_whoami."* Expect `sessionOK: true`, with the same asid as
      your Terminal (`$F whoami` from a normal Terminal gives the comparison).
- [ ] **M9 resource, prompt and instructions:**
  - [ ] In Claude Code, type `@` and see whether `farrier-spike://info` is offered.
  - [ ] Type `/` and see whether a `why-did-it-wake` prompt command is offered (for example
        `/mcp__farrier-spike__why-did-it-wake`). Run it.
  - [ ] Ask: *"What instructions did the farrier-spike server give you?"* Does Claude know them?
- [ ] **M10 long operations:** ask Claude to call `slow_operation` with `seconds` 30, then 120, then 300. Record:
  - [ ] which ones complete, and when the client gives up (and with what error)
  - [ ] whether `progressTokenReceived` is true, i.e. whether Claude Code asks for progress
  - [ ] whether progress is shown in the UI
  - [ ] whether `MCP_TOOL_TIMEOUT=600000 claude` changes the outcome

## 3. TCC attribution (the important part)

Check System Settings → Privacy & Security → **Full Disk Access** first, and record which of these apps have FDA:
Terminal, Claude (the app), FarrierSpike.

Run each probe in three states. For each state, record the results of all three probes in the matrix in RESULTS.md.

**The three probes:**

| Probe | How |
|---|---|
| CLI from Terminal | `$F tcc-probe` |
| Helper | `$F helper-tcc-probe` |
| Through the agent | ask Claude: *"Call tcc_probe with viaHelper true."* |

**The three states:**
- [ ] **M11 state A:** nobody has FDA.
- [ ] **M12 state B:** only FarrierSpike has FDA. Add `/Applications/FarrierSpike.app` with **+**.
- [ ] **M13 state C:** only Terminal has FDA. Remove FarrierSpike first.

In each state, `TCC.db`, `Safari`, `Mail` and `Messages` will be readable or denied. `posix: NSPOSIXErrorDomain 1`
(EPERM) means TCC denied it. `Library/Caches` is the control, and should always be readable.

- [ ] **M14 user folders:** `$F tcc-probe --user-folders`, then via Claude: *"Call tcc_probe with includeUserFolders
      true."* If a dialog like *"… would like to access files in your Desktop folder"* appears, **screenshot it**. Which
      app name does it show: Terminal, Claude, or FarrierSpike? Click **Don't Allow**.

What the results mean:
- If FarrierSpike's FDA has an effect in the CLI or agent column, Farrier can use its own grant directly.
- If only Terminal's FDA has an effect there, TCC attributes the access to the top of the process chain, so
  privileged reads must go through the helper.
- If the helper column changes in state B, the helper inherits the app's FDA grant.

## 4. Claude Desktop (optional)

Add this to `~/Library/Application Support/Claude/claude_desktop_config.json`, then restart Claude Desktop:

```json
{ "mcpServers": { "farrier-spike": { "command": "/Applications/FarrierSpike.app/Contents/MacOS/farrier-spike", "args": ["mcp"] } } }
```

- [ ] **M15:** `system_info` (process chain: is Claude Desktop the top app?), `helper_whoami` (`sessionOK`?),
      `approve_test_plan` (prompt?), and `tcc_probe` in state B. Compare with Claude Code.

## 5. Clean up

```bash
claude mcp remove farrier-spike
```

Also:
- Remove FarrierSpike (and Terminal, if you added it for the test) from Full Disk Access.
- Remove the Claude Desktop config entry, if you added one.
- The spike-2 cleanup (section 8 of its checklist) still applies.
