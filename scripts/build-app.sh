#!/usr/bin/env bash
# Builds and signs Farrier.app: the CLI as the main executable, the privileged helper, and its LaunchDaemon plist.
#
#   SIGN_IDENTITY="Developer ID Application: …" ./scripts/build-app.sh     # or an Apple Development identity
#   SIGN_IDENTITY=- ./scripts/build-app.sh                                  # ad hoc: structure check only (CI);
#                                                                           # an ad hoc helper refuses to start
#
# Install (root-owned, so nothing running as the user can modify it):
#   sudo ./scripts/install.sh            (root-owned app in /Applications, plus the `farrier` wrapper on PATH)
set -euo pipefail
cd "$(dirname "$0")/.."
: "${SIGN_IDENTITY:?set SIGN_IDENTITY (security find-identity -v -p codesigning), or - for ad hoc}"

VERSION=$(sed -n 's/.*static let string = "\(.*\)".*/\1/p' Sources/FarrierCore/Version.swift)
OUT=build
APP="$OUT/Farrier.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Library/LaunchDaemons" "$APP/Contents/Resources"

# UNIVERSAL=1 builds arm64 and x86_64 into one binary (releases do, so Intel Macs can run them too).
ARCH_ARGS=()
[[ "${UNIVERSAL:-}" == "1" ]] && ARCH_ARGS=(--arch arm64 --arch x86_64)
swift build -c release ${ARCH_ARGS[@]+"${ARCH_ARGS[@]}"} --product farrier
swift build -c release ${ARCH_ARGS[@]+"${ARCH_ARGS[@]}"} --product farrier-helper
BIN="$(swift build -c release ${ARCH_ARGS[@]+"${ARCH_ARGS[@]}"} --show-bin-path)"

cp "$BIN/farrier" "$BIN/farrier-helper" "$APP/Contents/MacOS/"
sed "s/__VERSION__/$VERSION/g" Packaging/Info.plist > "$APP/Contents/Info.plist"
cp Packaging/dev.farrier.helper.plist "$APP/Contents/Library/LaunchDaemons/"
# The bundled rule packs, sealed by the signature: the installed CLI uses them when no --rules path is given.
cp -R rules "$APP/Contents/Resources/rules"
install -m 755 scripts/uninstall.sh "$APP/Contents/Resources/uninstall.sh"

# The icon: System Settings shows it in Login Items when the user decides whether to allow the helper.
ICONSET="$OUT/AppIcon.iconset"
rm -rf "$ICONSET" && mkdir -p "$ICONSET"
for size in 16 32 128 256 512; do
  sips -z $size $size Packaging/AppIcon.png --out "$ICONSET/icon_${size}x${size}.png" >/dev/null
  sips -z $((size * 2)) $((size * 2)) Packaging/AppIcon.png --out "$ICONSET/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns"

SIGN_ARGS=(--force --sign "$SIGN_IDENTITY" --options runtime)
[[ "$SIGN_IDENTITY" != "-" ]] && SIGN_ARGS+=(--timestamp)  # timestamps need a real identity

# Helper first, then the bundle (which signs the main executable with the bundle id). No --deep.
codesign "${SIGN_ARGS[@]}" --identifier dev.farrier.helper "$APP/Contents/MacOS/farrier-helper"
codesign "${SIGN_ARGS[@]}" "$APP"
codesign --verify --strict --verbose=2 "$APP"

for t in "$APP" "$APP/Contents/MacOS/farrier-helper"; do
  codesign -dvv "$t" 2>&1 | grep -E '^(Identifier|TeamIdentifier)' | sed "s|^|$(basename "$t"): |"
done
echo "built $APP ($VERSION)"
