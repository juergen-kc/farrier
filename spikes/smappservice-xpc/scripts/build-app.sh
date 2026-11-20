#!/usr/bin/env bash
# Builds FarrierSpike.app (client + helper + LaunchDaemon plist) and two "attacker" copies of the client.
#
# Environment:
#   SIGN_IDENTITY   e.g. "Apple Development: Your Name (XXXXXXXXXX)" or a Developer ID Application identity
#
# Output (./out):
#   FarrierSpike.app          the real thing. Install it to /Applications before testing.
#   attacker-adhoc            the client binary, re-signed ad hoc (no Team ID)
#   attacker-other-id         the client binary, same certificate, different identifier (dev.farrier.spike.other)
set -euo pipefail
cd "$(dirname "$0")/.."
: "${SIGN_IDENTITY:?set SIGN_IDENTITY (see: security find-identity -v -p codesigning)}"

OUT=out
APP="$OUT/FarrierSpike.app"
rm -rf "$OUT"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Library/LaunchDaemons"

echo "==> swift build (release)"
swift build -c release
BIN="$(swift build -c release --show-bin-path)"

echo "==> assembling $APP"
cp "$BIN/farrier-spike" "$APP/Contents/MacOS/"
cp "$BIN/farrier-spike-helper" "$APP/Contents/MacOS/"
cp support/Info.plist "$APP/Contents/Info.plist"
cp support/dev.farrier.spike.helper.plist "$APP/Contents/Library/LaunchDaemons/"

echo "==> signing (helper first, then the bundle; no --deep)"
codesign --force --sign "$SIGN_IDENTITY" --options runtime --timestamp \
  --identifier dev.farrier.spike.helper "$APP/Contents/MacOS/farrier-spike-helper"
codesign --force --sign "$SIGN_IDENTITY" --options runtime --timestamp "$APP"
codesign --verify --strict --verbose=2 "$APP"

echo "==> attacker copies"
cp "$BIN/farrier-spike" "$OUT/attacker-adhoc"
codesign --force --sign - "$OUT/attacker-adhoc"
cp "$BIN/farrier-spike" "$OUT/attacker-other-id"
codesign --force --sign "$SIGN_IDENTITY" --options runtime --timestamp \
  --identifier dev.farrier.spike.other "$OUT/attacker-other-id"

echo
echo "==> signatures"
for t in "$APP" "$APP/Contents/MacOS/farrier-spike-helper" "$OUT/attacker-adhoc" "$OUT/attacker-other-id"; do
  echo "--- $t"
  codesign -dvv "$t" 2>&1 | grep -E '^(Identifier|TeamIdentifier|CDHash)' || true
done

echo
echo "Next: install with"
echo "  sudo rm -rf /Applications/FarrierSpike.app && sudo ditto $APP /Applications/FarrierSpike.app && sudo chown -R root:wheel /Applications/FarrierSpike.app"
