#!/usr/bin/env bash
# Removes Farrier completely. Also shipped as Farrier.app/Contents/Resources/uninstall.sh.
#
#   sudo ./scripts/uninstall.sh [--purge]
#
# Always: unregisters the helper, deletes the approval key (the user's keychain item and the enrolled public key),
# removes the helper's authorization right, the app, the `farrier` wrapper and the helper's log.
# --purge also removes the journals, saved plans and posture exceptions. Without it they stay, so a reinstall
# keeps its history and exceptions.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run with sudo: sudo $0 $*" >&2; exit 1; }
PURGE=""
[[ "${1:-}" == "--purge" ]] && PURGE="--purge"
APP=/Applications/Farrier.app
STATE="/Library/Application Support/Farrier"
USER_NAME="${SUDO_USER:-}"

# 1. The user's side, as the user (their keychain, their files, SMAppService unregistration from the app itself).
if [[ -x "$APP/Contents/MacOS/farrier" && -n "$USER_NAME" && "$USER_NAME" != "root" ]]; then
  sudo -u "$USER_NAME" "$APP/Contents/MacOS/farrier" uninstall --yes $PURGE || echo "note: the user-side cleanup reported a problem (see above)"
else
  echo "note: skipping the user-side cleanup (no app, or not run through sudo by a user)"
fi

# 2. Root's side.
launchctl bootout system/dev.farrier.helper 2>/dev/null || true
rm -f "$STATE/approval-key.pub"
security authorizationdb remove dev.farrier.enroll-approval-key >/dev/null 2>&1 || true
if [[ -n "$PURGE" ]]; then
  rm -rf "$STATE"
else
  rmdir "$STATE" 2>/dev/null || true   # only if nothing (journal, exceptions) is left
fi
rm -f /Library/Logs/farrier-helper.log
for wrapper in /opt/homebrew/bin/farrier /usr/local/bin/farrier; do
  # Only our wrapper, never someone else's `farrier`.
  if [[ -f "$wrapper" ]] && grep -q "Farrier.app/Contents/MacOS/farrier" "$wrapper"; then rm -f "$wrapper"; echo "removed $wrapper"; fi
done
rm -rf "$APP"
echo "removed $APP"
[[ -z "$PURGE" && -d "$STATE" ]] && echo "kept $STATE (journal, exceptions); remove it with --purge"
echo "Farrier is uninstalled."
