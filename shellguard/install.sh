#!/usr/bin/env bash
# install.sh — ShellGuard installer (ClickFix Defense Kit)
# -----------------------------------------------------------------------------
# Idempotently adds a single `source` line for shellguard.zsh to your ~/.zshrc.
# Re-running it does nothing (no duplicate lines). Supports clean uninstall.
#
# Usage:
#   ./install.sh              # install (append source line to ~/.zshrc)
#   ./install.sh --uninstall  # remove the source line
#   ./install.sh --rc PATH    # target a different rc file (e.g. ~/.zshrc.local)
#   ./install.sh --help
#
# This installer is a plain, readable bash script. It does NOT pipe anything
# from the internet — which is the whole threat ShellGuard exists to stop.
# -----------------------------------------------------------------------------

set -euo pipefail

# Resolve the absolute path to shellguard.zsh sitting next to this installer,
# so the `source` line we write is stable regardless of where you run from.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" >/dev/null 2>&1 && pwd -P)"
GUARD_PATH="${SCRIPT_DIR}/shellguard.zsh"

RC_FILE="${HOME}/.zshrc"
MODE="install"

# Markers used to find/remove our managed block idempotently.
BEGIN_MARK="# >>> shellguard (clickfix-defense-kit) >>>"
END_MARK="# <<< shellguard (clickfix-defense-kit) <<<"

usage() {
  cat <<USAGE
ShellGuard installer

  ./install.sh              Install (adds a source line to ~/.zshrc)
  ./install.sh --uninstall  Remove the ShellGuard block from ~/.zshrc
  ./install.sh --rc PATH    Use a different rc file (default: ~/.zshrc)
  ./install.sh --help       Show this help

After installing, open a new terminal OR run:  source ~/.zshrc
USAGE
}

# --- parse args -------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --uninstall) MODE="uninstall"; shift ;;
    --rc)        RC_FILE="${2:?--rc needs a path}"; shift 2 ;;
    --help|-h)   usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# --- sanity checks ----------------------------------------------------------
if [[ "$MODE" == "install" && ! -f "$GUARD_PATH" ]]; then
  echo "ERROR: shellguard.zsh not found at: $GUARD_PATH" >&2
  exit 1
fi

# Ensure the rc file exists (create it empty if missing) for install.
if [[ "$MODE" == "install" && ! -e "$RC_FILE" ]]; then
  touch "$RC_FILE"
  echo "Created $RC_FILE"
fi

# is_installed: returns 0 if our managed block already exists in the rc file.
is_installed() {
  [[ -f "$RC_FILE" ]] && grep -qF "$BEGIN_MARK" "$RC_FILE"
}

# remove_block: strips the managed block (inclusive of markers) from rc file.
# Uses awk to filter out lines between BEGIN and END markers. We back up first.
remove_block() {
  [[ -f "$RC_FILE" ]] || return 0
  is_installed || return 0
  local backup="${RC_FILE}.shellguard.bak.$(date +%Y%m%d%H%M%S)"
  cp -p "$RC_FILE" "$backup"
  awk -v b="$BEGIN_MARK" -v e="$END_MARK" '
    $0 == b { skip=1; next }
    $0 == e { skip=0; next }
    skip != 1 { print }
  ' "$RC_FILE" > "${RC_FILE}.tmp"
  mv "${RC_FILE}.tmp" "$RC_FILE"
  echo "Removed existing ShellGuard block (backup: $backup)"
}

case "$MODE" in
  install)
    if is_installed; then
      echo "ShellGuard already installed in $RC_FILE — refreshing the block."
      remove_block
    fi
    {
      printf '\n%s\n' "$BEGIN_MARK"
      printf '# ClickFix command guard. Disable per-session with: export CLICKFIX_GUARD=0\n'
      printf '[[ -r "%s" ]] && source "%s"\n' "$GUARD_PATH" "$GUARD_PATH"
      printf '%s\n' "$END_MARK"
    } >> "$RC_FILE"
    echo "Installed ShellGuard -> $RC_FILE"
    echo "Sourcing: $GUARD_PATH"
    echo
    echo "Open a new terminal, or run:  source ~/.zshrc"
    ;;
  uninstall)
    if ! is_installed; then
      echo "ShellGuard is not installed in $RC_FILE — nothing to do."
      exit 0
    fi
    remove_block
    echo "Uninstalled ShellGuard from $RC_FILE"
    echo "Open a new terminal for the change to take effect."
    ;;
esac
