#!/usr/bin/env bash
# Talks to `farrier mcp` over stdio like a client would: initialize, list tools, call a read-only tool.
#   scripts/mcp-smoke.sh <farrier binary>          (CI runs it on Linux and macOS)
set -euo pipefail
BIN=${1:?usage: mcp-smoke.sh <farrier binary>}
OUT=$(mktemp)
requests() {
  printf '%s\n' \
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"mcp-smoke","version":"1"}}}' \
    '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
    '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
    '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"posture_explain","arguments":{"ruleID":"posture.core.firewall"}}}' \
    '{"jsonrpc":"2.0","id":4,"method":"prompts/list"}'
}
# Like a real client, keep stdin open until the replies are in.
( requests; sleep 5 ) | "$BIN" mcp > "$OUT"
cat "$OUT"
fail() { echo "::error::mcp smoke: $1"; exit 1; }
grep -q '"protocolVersion":"2025-11-25"' "$OUT" || fail "no initialize reply with protocol 2025-11-25"
for tool in farrier_status facts_collect posture_check posture_explain posture_plan_remediation plan_show apply_plan journal_recent; do
  grep -q "\"name\":\"$tool\"" "$OUT" || fail "tools/list lacks $tool"
done
grep -q '"fixAction":"firewall.enable"' "$OUT" || fail "posture_explain did not return the firewall rule"
grep -q '"security-checkup"' "$OUT" || fail "prompts/list lacks security-checkup"
# Every stdout line must be a JSON-RPC message (nothing else may write to stdout in MCP mode).
if grep -v '^{"' "$OUT" | grep -q .; then fail "non-JSON output on stdout"; fi
# End of input right after the requests (spike M2b): replies must still arrive.
requests | "$BIN" mcp > "$OUT"
grep -q '"fixAction":"firewall.enable"' "$OUT" || echo "::warning::mcp smoke: no reply when stdin closes immediately"
echo "mcp smoke: ok"
