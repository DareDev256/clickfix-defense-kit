#!/usr/bin/env bash
#
# install.sh — ClickFix Defense Kit top-level installer
# ==============================================================================
# An interactive menu that installs (or uninstalls) each tool in the kit.
#
# Design principles:
#   - Idempotent: every per-tool installer is itself idempotent, so re-running
#     this menu never double-installs.
#   - Honest delivery: there is NO `curl | bash` here, on purpose. That delivery
#     pattern is the exact attack this kit exists to stop. Clone the repo, read
#     the (short, commented) source, and run this locally.
#   - macOS only. The persistence/clipboard/guest tools use launchd and native
#     macOS binaries.
#
# Usage:
#   ./install.sh                  Interactive menu (default)
#   ./install.sh --help           Show help
#
# Non-interactive shortcuts (handy for scripting / CI):
#   ./install.sh shellguard       Install ShellGuard
#   ./install.sh clipsentinel     Install ClipSentinel
#   ./install.sh watchpost        Install WatchPost
#   ./install.sh exposurescan     Make ExposureScan runnable + run a scan
#   ./install.sh canary           Make Canary runnable (then run it to plant)
#   ./install.sh guestmode        Make GuestMode runnable (dry-run by default)
#   ./install.sh all              Install the persistent tools (ShellGuard,
#                                 ClipSentinel, WatchPost) + make scripts runnable
#   ./install.sh uninstall        Interactive uninstall menu
#   ./install.sh uninstall <tool> Uninstall a specific tool
#   ./install.sh --verify         Run the integrity check only, then exit
#
# Integrity:
#   Before touching your system this script verifies the checkout: it refuses to
#   run if a tracked file was modified after cloning, and it reports whether the
#   checked-out tag carries a good signature. Override with --force, after you
#   have read the diff. See SECURITY.md -> "Verifying what you cloned".
# ==============================================================================

set -euo pipefail

KIT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" >/dev/null 2>&1 && pwd -P)"

# ---- pretty output -----------------------------------------------------------
if [ -t 1 ]; then
  BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GRN=$'\033[32m'
  YEL=$'\033[33m'; CYN=$'\033[36m'; RST=$'\033[0m'
else
  BOLD=''; DIM=''; RED=''; GRN=''; YEL=''; CYN=''; RST=''
fi

say()  { printf '%s\n' "$*"; }
info() { printf '%s[kit]%s %s\n' "$CYN" "$RST" "$*"; }
ok()   { printf '%s[ok]%s  %s\n' "$GRN" "$RST" "$*"; }
warn() { printf '%s[warn]%s %s\n' "$YEL" "$RST" "$*"; }
err()  { printf '%s[err]%s  %s\n' "$RED" "$RST" "$*" >&2; }

require_macos() {
  if [ "$(uname -s)" != "Darwin" ]; then
    err "This kit targets macOS. Detected: $(uname -s)."
    err "ShellGuard's zsh guard is portable, but the launchd/native tools are not."
    exit 1
  fi
}

run_installer() {
  # run_installer <tool-dir> <args...>
  local tool="$1"; shift
  local dir="$KIT_DIR/$tool"
  if [ ! -d "$dir" ]; then
    err "Missing tool directory: $dir"
    return 1
  fi
  if [ ! -f "$dir/install.sh" ]; then
    err "No install.sh in $dir"
    return 1
  fi
  chmod +x "$dir/install.sh" 2>/dev/null || true
  info "Running $tool installer: ./$tool/install.sh $*"
  ( cd "$dir" && ./install.sh "$@" )
}

make_runnable() {
  # make_runnable <tool-dir> <script>
  local tool="$1" script="$2"
  local path="$KIT_DIR/$tool/$script"
  if [ ! -f "$path" ]; then
    err "Missing $tool/$script"
    return 1
  fi
  chmod +x "$path"
  ok "Made executable: $tool/$script"
}

# ---- per-tool actions --------------------------------------------------------

install_shellguard()  { run_installer shellguard; }
uninstall_shellguard(){ run_installer shellguard --uninstall; }

install_clipsentinel()  { run_installer clipsentinel install; }
uninstall_clipsentinel(){ run_installer clipsentinel uninstall; }

install_watchpost()  { run_installer watchpost; }
uninstall_watchpost(){ run_installer watchpost --uninstall; }

install_exposurescan() {
  make_runnable exposurescan exposurescan.py
  info "ExposureScan is a read-only self-audit (no launchd install needed)."
  info "Running an initial scan now. For Apple Notes / browser surfaces you may"
  info "need to grant your terminal Full Disk Access, then re-run."
  ( cd "$KIT_DIR/exposurescan" && ./exposurescan.py ) || \
    warn "Scan exited non-zero (that can just mean it found a P0/P1 — read the report)."
  ok "ExposureScan ready: ./exposurescan/exposurescan.py --help"
}

install_canary() {
  make_runnable canary canary-gen.sh
  info "Canary plants DECOY honeytokens on YOUR machine. Nothing is planted yet."
  info "Run it interactively to choose locations:  ./canary/canary-gen.sh"
  info "Then wire a live alert:  ./canary/canary-gen.sh --canary-walkthrough"
  ok "Canary ready."
}

install_guestmode() {
  make_runnable guestmode setup-guestmode.sh
  info "GuestMode is DRY-RUN by default (changes nothing without --apply)."
  info "Preview the plan now:  ./guestmode/setup-guestmode.sh"
  info "Apply for real:        ./guestmode/setup-guestmode.sh --apply"
  ok "GuestMode ready."
}

install_all() {
  require_macos
  install_shellguard
  install_clipsentinel
  install_watchpost
  make_runnable exposurescan exposurescan.py
  make_runnable canary canary-gen.sh
  make_runnable guestmode setup-guestmode.sh
  ok "Persistent tools installed; ExposureScan/Canary/GuestMode made runnable."
  info "Run ./exposurescan/exposurescan.py to see your current blast radius."
}

# ---- interactive menus -------------------------------------------------------

print_banner() {
  say "${BOLD}ClickFix Defense Kit${RST} — defensive-use-only macOS toolkit"
  say "${DIM}Clone, read the source, run locally. No curl|bash, on purpose.${RST}"
  say ""
}

install_menu() {
  print_banner
  say "Install which tool?"
  say "  ${BOLD}1${RST}) ShellGuard    ${DIM}zsh execute-time command guard (the load-bearing block)${RST}"
  say "  ${BOLD}2${RST}) ExposureScan  ${DIM}read-only blast-radius self-audit (names & counts only)${RST}"
  say "  ${BOLD}3${RST}) ClipSentinel  ${DIM}clipboard copy-time early warning${RST}"
  say "  ${BOLD}4${RST}) GuestMode     ${DIM}standard non-admin account (containment)${RST}"
  say "  ${BOLD}5${RST}) Canary        ${DIM}honeytoken tripwire generator${RST}"
  say "  ${BOLD}6${RST}) WatchPost     ${DIM}persistence diff for unattended/headless Macs${RST}"
  say "  ${BOLD}a${RST}) All persistent tools + make the rest runnable"
  say "  ${BOLD}u${RST}) Uninstall menu"
  say "  ${BOLD}q${RST}) Quit"
  say ""
  printf 'Choice: '
  read -r choice
  case "$choice" in
    1) install_shellguard ;;
    2) install_exposurescan ;;
    3) require_macos; install_clipsentinel ;;
    4) require_macos; install_guestmode ;;
    5) install_canary ;;
    6) require_macos; install_watchpost ;;
    a|A) install_all ;;
    u|U) uninstall_menu ;;
    q|Q) say "Bye."; exit 0 ;;
    *) warn "Unknown choice: $choice" ;;
  esac
}

uninstall_menu() {
  print_banner
  say "Uninstall which tool?"
  say "  ${BOLD}1${RST}) ShellGuard    ${DIM}removes the ~/.zshrc source block${RST}"
  say "  ${BOLD}3${RST}) ClipSentinel  ${DIM}unloads + removes the LaunchAgent${RST}"
  say "  ${BOLD}6${RST}) WatchPost     ${DIM}unloads + removes the LaunchAgent${RST}"
  say "  ${DIM}(ExposureScan/Canary/GuestMode install nothing persistent —${RST}"
  say "  ${DIM} Canary: ./canary/canary-gen.sh --revert to remove planted decoys.)${RST}"
  say "  ${BOLD}q${RST}) Back / quit"
  say ""
  printf 'Choice: '
  read -r choice
  case "$choice" in
    1) uninstall_shellguard ;;
    3) uninstall_clipsentinel ;;
    6) uninstall_watchpost ;;
    q|Q) return 0 ;;
    *) warn "Unknown / nothing-to-uninstall choice: $choice" ;;
  esac
}

usage() {
  sed -n '3,48p' "${BASH_SOURCE[0]:-$0}" | sed 's/^# \{0,1\}//'
}

# ---- integrity ---------------------------------------------------------------
# Surface the protection that already exists rather than inventing a new one.
#
# Deliberately NOT a MANIFEST.sha256 in the tree: anyone who can edit a tracked
# file can also re-run `shasum > MANIFEST.sha256` and make the manifest report
# OK on a backdoored tree. `.git` is already a content-addressed manifest whose
# hashes chain to a commit ID you can compare against GitHub, so the useful
# check is `git status --porcelain` plus the tag signature.
#
# Returns 0 if the checkout looks clean, 1 otherwise. Never modifies anything.
verify_checkout() {
  local rc=0 dirty tag

  if ! command -v git >/dev/null 2>&1 || ! git -C "$KIT_DIR" rev-parse --git-dir >/dev/null 2>&1; then
    warn "Not a git checkout — cannot verify integrity."
    warn "Prefer 'git clone' over a downloaded zip so this check can run."
    return 1
  fi

  dirty="$(git -C "$KIT_DIR" status --porcelain 2>/dev/null || true)"
  if [ -n "$dirty" ]; then
    err "Tracked files have been MODIFIED since checkout:"
    printf '%s\n' "$dirty" | sed 's/^/      /'
    err "A security tool should not install from a tree you did not verify."
    err "Review with 'git diff', or re-run with --force if the changes are yours."
    rc=1
  else
    say "  ${GRN}ok${RST} working tree is clean (no tracked file modified)"
  fi

  say "  ${DIM}commit ${RST}$(git -C "$KIT_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)${DIM} — compare this against GitHub${RST}"

  tag="$(git -C "$KIT_DIR" describe --exact-match --tags 2>/dev/null || true)"
  if [ -n "$tag" ]; then
    if git -C "$KIT_DIR" verify-tag "$tag" >/dev/null 2>&1; then
      say "  ${GRN}ok${RST} tag $tag carries a good signature"
    else
      warn "tag $tag is not signed, or the signer is not in your allowed_signers."
      warn "See SECURITY.md -> 'Verifying what you cloned' to set that up."
    fi
  else
    warn "Not on a release tag. For the reviewed code, run: git checkout v0.1.1"
  fi

  return $rc
}

# ---- dispatch ----------------------------------------------------------------

main() {
  # --force anywhere in the args skips the integrity gate. Strip it so it does
  # not fall through to the command dispatch as an unknown command.
  local force=0 a
  local -a args=()
  for a in "$@"; do
    if [ "$a" = "--force" ]; then force=1; else args+=("$a"); fi
  done
  set -- ${args[@]+"${args[@]}"}

  case "${1:-}" in
    --verify)
      say "${BOLD}Checkout integrity${RST}"
      verify_checkout && { say ""; say "${GRN}Checkout verified.${RST}"; exit 0; }
      exit 1 ;;
  esac

  # Everything below touches the user's system, so gate it.
  case "${1:-}" in
    -h|--help|help) : ;;
    *)
      if [ "$force" -eq 0 ]; then
        say "${BOLD}Checkout integrity${RST}"
        if ! verify_checkout; then
          say ""
          err "Refusing to install from an unverified checkout. Use --force to override."
          exit 1
        fi
        say ""
      else
        warn "--force: skipping the integrity check."
      fi ;;
  esac

  case "${1:-}" in
    ""|menu)        install_menu ;;
    -h|--help|help) usage ;;
    shellguard)     install_shellguard ;;
    clipsentinel)   require_macos; install_clipsentinel ;;
    watchpost)      require_macos; install_watchpost ;;
    exposurescan)   install_exposurescan ;;
    canary)         install_canary ;;
    guestmode)      require_macos; install_guestmode ;;
    all)            install_all ;;
    uninstall)
      case "${2:-}" in
        "")           uninstall_menu ;;
        shellguard)   uninstall_shellguard ;;
        clipsentinel) uninstall_clipsentinel ;;
        watchpost)    uninstall_watchpost ;;
        *) err "Unknown uninstall target: ${2:-}"; exit 1 ;;
      esac ;;
    *) err "Unknown command: $1"; usage; exit 1 ;;
  esac
}

main "$@"
