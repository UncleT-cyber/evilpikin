#!/usr/bin/env bash
#
# harden-macos.sh — operator-machine opsec for EvilPikin DEV on macOS.
#
# Implements two host-hardening steps so the tool's presence and captured
# session data don't leak into macOS metadata/telemetry:
#   1) Spotlight exclusion for the project folder (stops indexing/telemetry of
#      captured session data in .sandbox/).
#   2) Disable diagnostic upload (com.apple.analytics clientenabled=false).
#
# NOTE on Step 1: on modern macOS the system volume is read-only (SIP), so the
# CLI write to /.Spotlight-V100/VolumeConfiguration.plist is normally BLOCKED.
# We attempt it, and if it fails we print the exact GUI steps (the supported
# method) instead of aborting. Step 2 is GATED behind an interactive y/N prompt
# to honor the operator's "confirm before I touch system prefs" rule.
#
# Run on the Mac with:   sudo bash harden-macos.sh
#
set -uo pipefail

PROJECT_DIR="/Users/admin/evilpikin"
SPOTLIGHT_PLOT="/.Spotlight-V100/VolumeConfiguration.plist"

echo "== [1/2] Spotlight exclusion for ${PROJECT_DIR} =="
# Attempt the CLI write (works on some setups / older macOS). It is safe to
# ignore the failure below — the GUI steps achieve the same result.
sudo /bin/mkdir -p "$(dirname "$SPOTLIGHT_PLOT")" 2>/dev/null || true
if sudo /usr/bin/defaults write "$SPOTLIGHT_PLOT" Exclusions -array-add "$PROJECT_DIR" 2>/dev/null; then
  sudo /usr/bin/mdutil -E / >/dev/null 2>&1 || true
  echo "OK: added to Spotlight exclusions via CLI; reindex triggered."
else
  cat <<EOF
CLI write was blocked by macOS (read-only system volume / SIP) — this is expected.
Apply it via the GUI instead (supported method):
  1. System Settings -> Siri & Spotlight -> Privacy (the "Search Privacy" list)
  2. Click '+', navigate to:  ${PROJECT_DIR}
  3. Add it. Spotlight will stop indexing that folder (incl. .sandbox/).
EOF
fi

echo
echo "== [2/2] Disable diagnostic upload (com.apple.analytics) =="
echo "This writes /Library/Preferences/com.apple.analytics clientenabled=false"
echo "(system-wide; for a per-user-only change use:"
echo "   defaults write com.apple.analytics clientenabled -bool false   # no sudo)."
read -r -p "Apply diagnostic-upload disable? [y/N] " ans
if [[ "$ans" == "y" || "$ans" == "Y" ]]; then
  sudo /usr/bin/defaults write /Library/Preferences/com.apple.analytics clientenabled -bool false
  echo "Disabled diagnostic upload (system-wide)."
else
  echo "Skipped — diagnostic-upload change NOT applied (per confirm-before-touch guard)."
fi

echo
echo "Done."
