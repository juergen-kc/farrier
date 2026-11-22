#!/usr/bin/env bash
# Installs build/Farrier.app (from scripts/build-app.sh) and the `farrier` command.
#
#   sudo ./scripts/install.sh [--prefix /usr/local]
#
# - The app goes to /Applications, owned by root:wheel, so nothing running as the user can modify it (or the helper
#   inside it, which launchd runs as root).
# - `farrier` on PATH is a small wrapper script, not a symlink: through a symlink the binary can't find its own
#   bundle (docs/ARCHITECTURE.md). It goes to <prefix>/bin: /opt/homebrew on Apple silicon if that exists, else
#   /usr/local.
# - A running helper of an older build is restarted, so the new one answers.
# Afterwards, as the user: `farrier helper register`, then `farrier setup`.
set -euo pipefail
cd "$(dirname "$0")/.."

[[ $EUID -eq 0 ]] || { echo "run with sudo: sudo $0 $*" >&2; exit 1; }
SRC=build/Farrier.app
DEST=/Applications/Farrier.app
PREFIX=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
if [[ -z "$PREFIX" ]]; then
  if [[ -d /opt/homebrew/bin ]]; then PREFIX=/opt/homebrew; else PREFIX=/usr/local; fi
fi

[[ -d "$SRC" ]] || { echo "$SRC not found; run scripts/build-app.sh first" >&2; exit 1; }
codesign --verify --strict "$SRC"
TEAM=$(codesign -dv "$SRC" 2>&1 | sed -n 's/^TeamIdentifier=//p')
[[ -n "$TEAM" && "$TEAM" != "not set" ]] || { echo "$SRC has no Team ID (ad hoc build?); the helper wouldn't start" >&2; exit 1; }

rm -rf "$DEST"
ditto "$SRC" "$DEST"
chown -R root:wheel "$DEST"
chmod -R go-w "$DEST"
echo "installed $DEST (team $TEAM)"

mkdir -p "$PREFIX/bin"
WRAPPER="$PREFIX/bin/farrier"
# The prefix may be writable by the user (Homebrew's is), so nothing is written there through a path the user
# controls: the wrapper is made in a private root-owned directory, and `install -S` puts it in place with a rename,
# which replaces a symlink at the destination instead of following it.
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
cat > "$STAGE/farrier" <<'SH'
#!/bin/sh
# Farrier's command-line wrapper (scripts/install.sh). Not a symlink: the binary must run from inside its bundle.
exec /Applications/Farrier.app/Contents/MacOS/farrier "$@"
SH
install -S -m 0755 -o root -g wheel "$STAGE/farrier" "$WRAPPER"
echo "installed $WRAPPER"

# Remember where the wrapper went, so uninstall.sh finds it whatever --prefix was used.
STATE="/Library/Application Support/Farrier"
mkdir -p "$STATE" && chown root:wheel "$STATE" && chmod 755 "$STATE"
printf '%s\n' "$WRAPPER" > "$STAGE/wrapper-path"
install -S -m 0644 -o root -g wheel "$STAGE/wrapper-path" "$STATE/wrapper-path"

# launchd keeps an already running helper; restart it so the installed build answers (no-op if it isn't running).
launchctl kickstart -k system/dev.farrier.helper 2>/dev/null || true

echo
echo "next, as yourself (not sudo):"
echo "  farrier helper register     # then allow Farrier in System Settings → General → Login Items"
echo "  farrier setup               # the approval key (an admin dialog appears)"
