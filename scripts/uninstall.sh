#!/usr/bin/env bash
# Removes Farrier completely. Also shipped as Farrier.app/Contents/Resources/uninstall.sh.
#
#   sudo ./scripts/uninstall.sh [--purge]
#
# Always: unregisters the helper, deletes the approval key (the user's keychain item and the enrolled public key),
# removes the helper's authorization right and Full Disk Access grant, the app, the `farrier` wrapper and the helper's log.
# --purge also removes the journals, saved plans and posture exceptions. Without it they stay, so a reinstall
# keeps its history and exceptions.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run with sudo: sudo $0 $*" >&2; exit 1; }
PURGE=""
FORCE=""
for arg in "$@"; do
  case "$arg" in
    --purge) PURGE="--purge" ;;
    --force) FORCE=1 ;;       # remove the app even if the user-side cleanup failed
    *) echo "unknown option $arg" >&2; exit 2 ;;
  esac
done
# The bundle this script lives in (Contents/Resources/uninstall.sh), wherever it was installed (Homebrew's
# --appdir); /Applications/Farrier.app when it's run from a checkout.
HERE="$(cd "$(dirname "$0")" && pwd)"
if [[ "$HERE" == *.app/Contents/Resources ]]; then APP="${HERE%/Contents/Resources}"; else APP=/Applications/Farrier.app; fi
STATE="/Library/Application Support/Farrier"
USER_NAME="${SUDO_USER:-}"

# 1. The user's side, as the user (their keychain, their files, SMAppService unregistration from the app itself).
#    If it fails, stop before the app is gone: the app is what can retry it.
if [[ -x "$APP/Contents/MacOS/farrier" && -n "$USER_NAME" && "$USER_NAME" != "root" ]]; then
  if ! sudo -u "$USER_NAME" "$APP/Contents/MacOS/farrier" uninstall --yes $PURGE; then
    if [[ -z "$FORCE" ]]; then
      echo "the user-side cleanup failed (see above); nothing else was removed. Fix it and run this again," >&2
      echo "or add --force to remove the rest anyway." >&2
      exit 1
    fi
    echo "note: the user-side cleanup failed; continuing because of --force"
  fi
else
  echo "note: skipping the user-side cleanup (no app at $APP, or not run through sudo by a user)"
fi

# 2. Root's side.
launchctl bootout system/dev.farrier.helper 2>/dev/null || true
rm -f "$STATE/approval-key.pub"
WRAPPERS=(/opt/homebrew/bin/farrier /usr/local/bin/farrier)
[[ -f "$STATE/wrapper-path" ]] && WRAPPERS+=("$(head -n 1 "$STATE/wrapper-path")")
rm -f "$STATE/wrapper-path"
security authorizationdb remove dev.farrier.enroll-approval-key >/dev/null 2>&1 || true
# The Full Disk Access grant (System Settings keeps the entry otherwise, pointing at a removed app).
tccutil reset SystemPolicyAllFiles dev.farrier.app >/dev/null 2>&1 || true
if [[ -n "$PURGE" ]]; then
  rm -rf "$STATE"
else
  rmdir "$STATE" 2>/dev/null || true   # only if nothing (journal, exceptions) is left
fi
rm -f /Library/Logs/farrier-helper.log
for wrapper in "${WRAPPERS[@]}"; do
  # Only our wrapper, never someone else's `farrier`.
  if [[ -f "$wrapper" ]] && grep -q "Farrier.app/Contents/MacOS/farrier" "$wrapper"; then rm -f "$wrapper"; echo "removed $wrapper"; fi
done
rm -rf "$APP"
echo "removed $APP"
[[ -z "$PURGE" && -d "$STATE" ]] && echo "kept $STATE (journal, exceptions); remove it with --purge"
echo "Farrier is uninstalled."
