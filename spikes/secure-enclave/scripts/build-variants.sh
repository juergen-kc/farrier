#!/usr/bin/env bash
# Builds se-spike once, then produces each signing variant in ./out.
#
# Environment:
#   DEVID_IDENTITY   "Developer ID Application: Your Name (TEAMID)"  (needed for V3 to V6)
#   TEAMID           your 10-character Team ID                        (needed for V4 and V6)
#   APPLEDEV_IDENTITY "Apple Development: …"                          (optional, V2)
#   NOTARY_PROFILE   notarytool keychain profile name                 (optional; notarizes V5)
#
# List your identities with: security find-identity -v -p codesigning
set -euo pipefail
cd "$(dirname "$0")/.."

OUT=out
rm -rf "$OUT"
mkdir -p "$OUT"

echo "==> swift build (release)"
swift build -c release
BIN="$(swift build -c release --show-bin-path)/se-spike"

sign() {  # sign <identity> <target> [extra codesign args…]
  local id="$1" target="$2"
  shift 2
  codesign --force --sign "$id" --identifier dev.farrier.spike --options runtime --timestamp "$@" "$target"
}

make_app() {  # make_app <name>
  local app="$OUT/$1.app"
  mkdir -p "$app/Contents/MacOS"
  cp "$BIN" "$app/Contents/MacOS/se-spike"
  cp support/Info.plist "$app/Contents/Info.plist"
  echo "$app"
}

echo "==> V1 linker-signed ad hoc (as built)"
cp "$BIN" "$OUT/v1-adhoc"

if [[ -n "${APPLEDEV_IDENTITY:-}" ]]; then
  echo "==> V2 Apple Development"
  cp "$BIN" "$OUT/v2-appledev"
  sign "$APPLEDEV_IDENTITY" "$OUT/v2-appledev"
else
  echo "--  V2 skipped (APPLEDEV_IDENTITY not set)"
fi

if [[ -n "${DEVID_IDENTITY:-}" ]]; then
  echo "==> V3 Developer ID + hardened runtime, bare binary, no entitlements"
  cp "$BIN" "$OUT/v3-devid"
  sign "$DEVID_IDENTITY" "$OUT/v3-devid"

  echo "==> V5 Developer ID app bundle, no entitlements"
  APP5="$(make_app v5-FarrierSpike)"
  sign "$DEVID_IDENTITY" "$APP5"

  if [[ -n "${TEAMID:-}" ]]; then
    sed "s/__TEAMID__/$TEAMID/" support/keychain-group.entitlements.template > "$OUT/kag.entitlements"

    echo "==> V4 Developer ID + keychain-access-groups entitlement, bare binary (no profile)"
    cp "$BIN" "$OUT/v4-devid-kag"
    sign "$DEVID_IDENTITY" "$OUT/v4-devid-kag" --entitlements "$OUT/kag.entitlements"

    echo "==> V6 Developer ID app bundle + keychain-access-groups entitlement (no profile)"
    APP6="$(make_app v6-FarrierSpike-kag)"
    sign "$DEVID_IDENTITY" "$APP6" --entitlements "$OUT/kag.entitlements"
  else
    echo "--  V4/V6 skipped (TEAMID not set)"
  fi

  if [[ -n "${NOTARY_PROFILE:-}" ]]; then
    echo "==> notarizing V5"
    ditto -c -k --keepParent "$APP5" "$OUT/v5.zip"
    xcrun notarytool submit "$OUT/v5.zip" --keychain-profile "$NOTARY_PROFILE" --wait
    xcrun stapler staple "$APP5"
  fi
else
  echo "--  V3 to V6 skipped (DEVID_IDENTITY not set)"
fi

echo
echo "==> signatures"
for t in "$OUT"/v1-adhoc "$OUT"/v2-appledev "$OUT"/v3-devid "$OUT"/v4-devid-kag "$OUT"/*.app; do
  [[ -e "$t" ]] || continue
  echo "--- $t"
  codesign -dvv "$t" 2>&1 | grep -E '^(Identifier|TeamIdentifier|CodeDirectory|Authority|Runtime)' || true
  codesign -d --entitlements :- "$t" 2>/dev/null | grep -A3 keychain-access-groups || true
done
