#!/bin/bash
#
# install.sh — ClickFix Defense Kit / WatchPost installer
# ------------------------------------------------------------------------------
# Installs the WatchPost persistence monitor as a per-user LaunchAgent that runs
# hourly. Idempotent: safe to re-run (it unloads any existing copy first).
#
# What it does:
#   1. Resolves this script's own directory (so paths work no matter where the
#      repo lives) and the current username.
#   2. Substitutes __USERNAME__ in the plist template, writing the result to
#      ~/Library/LaunchAgents/com.clickfixkit.watchpost.plist.
#   3. Makes watchpost.sh executable.
#   4. Runs an initial baseline (--init) so the first scheduled run has
#      something to diff against (otherwise the first real run would just be a
#      silent baseline).
#   5. Loads the agent with launchctl.
#
# Uninstall:
#   ./install.sh --uninstall
#
# This installer is intentionally NOT a `curl | bash` one-liner — that delivery
# pattern is exactly how ClickFix/AMOS infections start, and a security tool
# should never train you into it. Clone the repo, read the code, run locally.
# ------------------------------------------------------------------------------

set -euo pipefail

LABEL="com.clickfixkit.watchpost"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="$SCRIPT_DIR/com.clickfixkit.watchpost.plist"
WATCHPOST="$SCRIPT_DIR/watchpost.sh"
LAUNCH_AGENTS_DIR="$HOME/Library/LaunchAgents"
INSTALLED_PLIST="$LAUNCH_AGENTS_DIR/$LABEL.plist"
USERNAME="$(whoami)"

log() { printf '[install] %s\n' "$*"; }

unload_if_loaded() {
  # `launchctl list` exits non-zero if the label isn't loaded; tolerate that.
  if launchctl list "$LABEL" >/dev/null 2>&1; then
    log "Unloading existing agent..."
    launchctl unload "$INSTALLED_PLIST" 2>/dev/null || true
  fi
}

uninstall() {
  unload_if_loaded
  if [ -f "$INSTALLED_PLIST" ]; then
    rm -f "$INSTALLED_PLIST"
    log "Removed $INSTALLED_PLIST"
  fi
  log "Uninstalled. (Baseline state in ~/.local/state/watchpost was left intact.)"
  log "Delete it manually with: rm -rf ~/.local/state/watchpost"
}

install() {
  # Sanity checks.
  [ -f "$TEMPLATE" ]   || { log "ERROR: plist template not found at $TEMPLATE"; exit 1; }
  [ -f "$WATCHPOST" ]  || { log "ERROR: watchpost.sh not found at $WATCHPOST"; exit 1; }

  chmod +x "$WATCHPOST"
  mkdir -p "$LAUNCH_AGENTS_DIR"

  # Unload any prior copy so this is a clean (re)install.
  unload_if_loaded

  # Substitute the placeholder AND the hard-coded repo path in the template,
  # so the agent points at THIS clone's actual location.
  #   - __USERNAME__              -> current short username
  #   - the canonical repo path   -> this script's resolved directory
  log "Writing $INSTALLED_PLIST"
  /usr/bin/sed \
    -e "s|__USERNAME__|$USERNAME|g" \
    -e "s|/Users/$USERNAME/dev/clickfix-defense-kit/watchpost/watchpost.sh|$WATCHPOST|g" \
    "$TEMPLATE" > "$INSTALLED_PLIST"

  # Validate the generated plist before loading (catches bad substitutions).
  if ! plutil -lint "$INSTALLED_PLIST" >/dev/null; then
    log "ERROR: generated plist failed plutil -lint. Aborting."
    rm -f "$INSTALLED_PLIST"
    exit 1
  fi

  # Capture an initial baseline so the first scheduled run can diff.
  log "Capturing initial persistence baseline..."
  "$WATCHPOST" --init || true

  # Load the agent.
  log "Loading agent..."
  launchctl load "$INSTALLED_PLIST"

  log "Done. WatchPost will run hourly and at login."
  log ""
  log "NEXT STEPS:"
  log "  - Grant Full Disk Access to /bin/bash so it can read ~/Library reliably"
  log "    (System Settings > Privacy & Security > Full Disk Access)."
  log "  - The first login-item check will trigger an Automation permission prompt."
  log "  - Logs: ~/.local/state/watchpost/watchpost.{out,err}.log"
  log "  - Run a manual check any time: $WATCHPOST"
}

case "${1:-install}" in
  --uninstall|-u) uninstall ;;
  install|"")     install ;;
  -h|--help)
    cat <<'USAGE'
WatchPost installer

Usage:
  ./install.sh              Install + load the hourly LaunchAgent
  ./install.sh --uninstall  Unload and remove the LaunchAgent
  ./install.sh --help       This help
USAGE
    ;;
  *)
    log "Unknown argument: $1 (use --help)"
    exit 2
    ;;
esac
