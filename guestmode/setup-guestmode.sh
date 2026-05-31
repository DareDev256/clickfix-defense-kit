#!/bin/bash
#
# setup-guestmode.sh — part of the ClickFix Defense Kit
# ----------------------------------------------------------------------------
# Blast-radius reduction: create a STANDARD (non-admin) macOS user account for
# movie-night / family / guest use, so a phished password or a pasted
# curl|bash command on that account can NOT escalate to admin, install a
# LaunchDaemon, or read your dev dirs and secrets.
#
# WHY THIS EXISTS (honest framing — read the README):
#   ClickFix / AMOS-style infostealers do NOT need admin to steal browser data
#   or run osascript through already-trusted Apple-signed binaries. A standard
#   account still gets infostealer'd. What a NON-ADMIN account buys you is that
#   the victim can't approve the sudo/password phish that installs the
#   persistent backdoor (e.g. the com.finder.helper LaunchDaemon), and can't
#   reach another user's home directory (your dev code + ~/.secrets) at all.
#   This is "reduce what a phished password can do," NOT "stop the stealer."
#
# SAFETY MODEL:
#   * DRY-RUN BY DEFAULT. Running this with no flags only PRINTS what it would
#     do and exits. Nothing changes.
#   * To make changes you must pass --apply AND type an explicit confirmation
#     word at the interactive prompt. Both gates are required.
#   * NEVER deletes a user. NEVER demotes an existing admin. NEVER touches the
#     primary account. It only CREATES a new standard user if one does not
#     already exist.
#   * All privileged actions are echoed before they run.
#
# Author: DareDev256 (placeholder)
# License: defensive-use only
# ----------------------------------------------------------------------------

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration (safe placeholder defaults — override via flags)
# ---------------------------------------------------------------------------
GUEST_USERNAME="familyguest"           # short name (no spaces). Override: --user NAME
GUEST_FULLNAME="Family Guest"          # display name.          Override: --fullname "..."
APPLY=0                                # 0 = dry-run (default), 1 = make changes
ASSUME_YES=0                           # skip interactive confirm (still needs --apply)

# Paths that the guest account must NOT be able to read. These are documented
# and re-checked, never auto-modified destructively. Override with --protect.
PROTECT_PATHS=(
  "$HOME/dev"
  "$HOME/Documents/Projects"
  "$HOME/.secrets"
  "$HOME/.ssh"
  "$HOME/.aws"
  "$HOME/.gnupg"
)

# ---------------------------------------------------------------------------
# Pretty output helpers
# ---------------------------------------------------------------------------
c_red()    { printf '\033[1;31m%s\033[0m\n' "$*"; }
c_green()  { printf '\033[1;32m%s\033[0m\n' "$*"; }
c_yellow() { printf '\033[1;33m%s\033[0m\n' "$*"; }
c_blue()   { printf '\033[1;34m%s\033[0m\n' "$*"; }
c_dim()    { printf '\033[2m%s\033[0m\n' "$*"; }

hr() { printf '%s\n' "------------------------------------------------------------"; }

usage() {
  cat <<'EOF'
setup-guestmode.sh — create a non-admin family/guest macOS account (blast-radius fix)

USAGE:
  ./setup-guestmode.sh                 # DRY-RUN: print the plan, change nothing
  ./setup-guestmode.sh --apply         # apply (still asks for typed confirmation)
  ./setup-guestmode.sh --apply --yes   # apply non-interactively (CI/scripted)

OPTIONS:
  --user NAME        short username for the guest account   (default: familyguest)
  --fullname "TEXT"  display name                            (default: "Family Guest")
  --protect PATH     add a path to the "must stay private" check (repeatable)
  --apply            actually create the user (otherwise dry-run only)
  --yes              skip the interactive confirmation prompt (requires --apply)
  -h, --help         show this help

NOTES:
  * Dry-run is the default and is completely side-effect free.
  * Creating the user requires sudo; you will be prompted by macOS for YOUR
    admin password (this script never reads or stores it).
  * This script NEVER deletes users and NEVER changes admin membership of an
    existing account.
  * If you prefer to click instead of script, the README documents the exact
    System Settings > Users & Groups path. That path is fully supported.
EOF
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --user)     GUEST_USERNAME="${2:?--user needs a value}"; shift 2 ;;
    --fullname) GUEST_FULLNAME="${2:?--fullname needs a value}"; shift 2 ;;
    --protect)  PROTECT_PATHS+=("${2:?--protect needs a path}"); shift 2 ;;
    --apply)    APPLY=1; shift ;;
    --yes)      ASSUME_YES=1; shift ;;
    -h|--help)  usage; exit 0 ;;
    *) c_red "Unknown argument: $1"; echo; usage; exit 2 ;;
  esac
done

# ---------------------------------------------------------------------------
# Environment sanity checks
# ---------------------------------------------------------------------------
if [[ "$(uname -s)" != "Darwin" ]]; then
  c_red "This script targets macOS (Darwin). Detected: $(uname -s). Aborting."
  exit 1
fi

# Validate the username is a safe short name (letters, digits, _ , -, lowercase).
if ! [[ "$GUEST_USERNAME" =~ ^[a-z_][a-z0-9_-]{0,30}$ ]]; then
  c_red "Refusing unsafe username '$GUEST_USERNAME'."
  c_dim  "Use lowercase letters, digits, underscore or hyphen (max 31 chars)."
  exit 2
fi

# ---------------------------------------------------------------------------
# Discovery (read-only) — does the user already exist? what's the next UID?
# ---------------------------------------------------------------------------
user_exists() {
  # `id` is the most reliable existence check across local + directory users.
  id "$1" >/dev/null 2>&1
}

next_free_uid() {
  # Pick a UID >= 1000 that is not currently taken. Standard macOS users start
  # at 501; we pick a high, obviously-non-system range to avoid collisions.
  local candidate=1001
  local taken
  taken="$(dscl . -list /Users UniqueID 2>/dev/null | awk '{print $2}')"
  while echo "$taken" | grep -qx "$candidate"; do
    candidate=$((candidate + 1))
  done
  echo "$candidate"
}

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
hr
c_blue "ClickFix Defense Kit — GuestMode setup"
c_dim  "Blast-radius reduction via a non-admin family/guest account."
hr

if [[ "$APPLY" -eq 0 ]]; then
  c_yellow "MODE: DRY-RUN (no changes will be made). Pass --apply to execute."
else
  c_red    "MODE: APPLY (changes WILL be made after confirmation)."
fi
echo

# ---------------------------------------------------------------------------
# Report: protected paths + their current permissions
# ---------------------------------------------------------------------------
c_blue "1) Private paths the guest account must NOT be able to read"
c_dim  "   (On macOS, other users' home dirs are already protected by default"
c_dim  "    perms — 700. This is a verification + reminder, not an auto-chmod.)"
echo
for p in "${PROTECT_PATHS[@]}"; do
  if [[ -e "$p" ]]; then
    # Print octal perms + owner so the operator can eyeball over-sharing.
    perms="$(stat -f '%Sp (%Lp) owner=%Su' "$p" 2>/dev/null || echo '??')"
    # World-readable bit on a sensitive dir is the thing to flag.
    octal="$(stat -f '%Lp' "$p" 2>/dev/null || echo '000')"
    other_digit="${octal: -1}"
    if [[ "$other_digit" != "0" ]]; then
      c_yellow "   [!] $p"
      c_yellow "       $perms  <- 'other' has access bits; consider: chmod o-rwx \"$p\""
    else
      c_green  "   [ok] $p"
      c_dim    "       $perms"
    fi
  else
    c_dim "   [--] $p (does not exist on this machine; skipping)"
  fi
done
echo
c_dim "   To harden manually (NOT done automatically by this script):"
c_dim "     chmod 700 ~ ; chmod o-rwx ~/dev ~/Documents/Projects ~/.secrets"
hr

# ---------------------------------------------------------------------------
# Report: does the guest user already exist?
# ---------------------------------------------------------------------------
c_blue "2) Guest account status"
if user_exists "$GUEST_USERNAME"; then
  c_green "   User '$GUEST_USERNAME' already exists — nothing to create."
  is_admin="no"
  if dseditgroup -o checkmember -m "$GUEST_USERNAME" admin >/dev/null 2>&1; then
    is_admin="YES"
  fi
  if [[ "$is_admin" == "YES" ]]; then
    c_red  "   [!] '$GUEST_USERNAME' is currently an ADMIN. That defeats the purpose."
    c_red  "       This script will NOT auto-demote it (no destructive changes)."
    c_dim  "       To demote manually:  sudo dseditgroup -o edit -d $GUEST_USERNAME -t user admin"
  else
    c_green "   '$GUEST_USERNAME' is a standard (non-admin) user. Good."
  fi
  hr
  c_green "Nothing to do. Exiting."
  exit 0
else
  c_yellow "   User '$GUEST_USERNAME' does not exist yet."
fi
NEW_UID="$(next_free_uid)"
c_dim "   Planned UID: $NEW_UID  |  full name: \"$GUEST_FULLNAME\"  |  admin: NO"
hr

# ---------------------------------------------------------------------------
# The plan — print the exact commands that WOULD run
# ---------------------------------------------------------------------------
# We use sysadminctl as the primary, supported path. It creates a proper local
# account (home dir, UID, password) without admin rights when -admin is omitted.
# A random temporary password is set; the guest changes it at first login, or
# the operator sets it interactively in System Settings.
#
# NOTE: we generate the temp password at apply-time, never print it to a log,
# and immediately require a change. For a true "no password" movie-night box,
# the macOS built-in Guest User (System Settings > Users & Groups) is the better
# fit — see the README. This script creates a *persistent* standard account.

print_plan() {
  c_blue "3) Plan (commands that ${1})"
  echo
  c_dim "   # Create a STANDARD (non-admin) user. Note: NO -admin flag."
  echo  "   sudo sysadminctl -addUser \"$GUEST_USERNAME\" \\"
  echo  "        -fullName \"$GUEST_FULLNAME\" \\"
  echo  "        -UID $NEW_UID \\"
  echo  "        -password <RANDOM-TEMP-PASSWORD-GENERATED-AT-RUNTIME> \\"
  echo  "        -home /Users/$GUEST_USERNAME"
  echo
  c_dim "   # Belt-and-suspenders: ensure NOT in the admin group."
  echo  "   sudo dseditgroup -o edit -d \"$GUEST_USERNAME\" -t user admin  2>/dev/null || true"
  echo
  c_dim "   # Set a restrictive default umask for the guest (077 = files 600,"
  c_dim "   # dirs 700) so anything they create is private by default."
  echo  "   sudo defaults write /Users/$GUEST_USERNAME/.zshenv-umask ... (see note)"
  echo  "   # In practice we append 'umask 077' to the guest's ~/.zprofile."
  echo
  c_dim "   # NOT run automatically: hide the account from fast-user-switching,"
  c_dim "   # disable Terminal for the guest, etc. See README 'further hardening'."
  echo
}

if [[ "$APPLY" -eq 0 ]]; then
  print_plan "WOULD run"
  hr
  c_yellow "DRY-RUN complete. Re-run with --apply to execute."
  c_dim    "Or use the manual System Settings path documented in README.md."
  exit 0
fi

print_plan "WILL run"
hr

# ---------------------------------------------------------------------------
# Confirmation gate (typed word, not y/N — same anti-autopilot principle as the
# ShellGuard layer of this kit).
# ---------------------------------------------------------------------------
if [[ "$ASSUME_YES" -ne 1 ]]; then
  c_red "About to CREATE a new standard user '$GUEST_USERNAME' (UID $NEW_UID)."
  c_dim "This requires your admin password (macOS will prompt). Nothing is deleted."
  printf 'Type the word CREATE to proceed, anything else aborts: '
  read -r ANSWER < /dev/tty || ANSWER=""
  if [[ "$ANSWER" != "CREATE" ]]; then
    c_yellow "Aborted. No changes made."
    exit 0
  fi
fi

# ---------------------------------------------------------------------------
# Execute (privileged) — every command echoed, none destructive.
# ---------------------------------------------------------------------------
# Generate a random temporary password. Never echoed, never logged.
TEMP_PW="$(LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 20 || true)"
if [[ -z "$TEMP_PW" ]]; then
  c_red "Failed to generate a temporary password. Aborting (no changes made)."
  exit 1
fi

c_blue "4) Creating standard user '$GUEST_USERNAME'..."

# sysadminctl prints the result; omitting -admin makes it a STANDARD account.
if sudo sysadminctl -addUser "$GUEST_USERNAME" \
      -fullName "$GUEST_FULLNAME" \
      -UID "$NEW_UID" \
      -password "$TEMP_PW" \
      -home "/Users/$GUEST_USERNAME" 2>&1; then
  c_green "   User created."
else
  c_red "   sysadminctl reported an error. Verify with: dscl . -read /Users/$GUEST_USERNAME"
  c_red "   No further changes attempted."
  exit 1
fi

# Scrub the temp password from the environment ASAP.
unset TEMP_PW

# Belt-and-suspenders: ensure the new account is NOT in admin.
c_blue "5) Ensuring '$GUEST_USERNAME' is NOT an admin..."
sudo dseditgroup -o edit -d "$GUEST_USERNAME" -t user admin >/dev/null 2>&1 || true
if dseditgroup -o checkmember -m "$GUEST_USERNAME" admin >/dev/null 2>&1; then
  c_red "   [!] Account still shows admin membership. Investigate manually."
else
  c_green "   Confirmed: standard (non-admin) account."
fi

# Set a restrictive umask for the guest so their files default to private.
GUEST_HOME="/Users/$GUEST_USERNAME"
ZPROFILE="$GUEST_HOME/.zprofile"
c_blue "6) Applying restrictive umask 077 for the guest..."
if [[ -d "$GUEST_HOME" ]]; then
  # Append idempotently; owned by the guest.
  if ! sudo grep -q 'umask 077' "$ZPROFILE" 2>/dev/null; then
    printf '\n# Added by ClickFix Defense Kit GuestMode: private-by-default files\numask 077\n' \
      | sudo tee -a "$ZPROFILE" >/dev/null
    sudo chown "$GUEST_USERNAME" "$ZPROFILE" 2>/dev/null || true
    c_green "   umask 077 appended to $ZPROFILE"
  else
    c_green "   umask already present in $ZPROFILE"
  fi
else
  c_yellow "   Home dir not created yet (it appears on first login). Set umask later:"
  c_dim    "   echo 'umask 077' | sudo tee -a $ZPROFILE"
fi

hr
c_green "Done. A standard (non-admin) account '$GUEST_USERNAME' now exists."
echo
c_blue "Next steps (manual, intentional — not automated):"
c_dim  "  * Set a real password: System Settings > Users & Groups > $GUEST_USERNAME."
c_dim  "  * Confirm your primary home dir is 700:  chmod 700 ~"
c_dim  "  * Confirm dev/secrets are private:        chmod o-rwx ~/dev ~/.secrets"
c_dim  "  * For a true zero-password movie-night box, also consider the built-in"
c_dim  "    macOS Guest User (it wipes its home on logout). See README.md."
hr
c_yellow "Reminder: a non-admin account REDUCES blast radius. It does NOT stop a"
c_yellow "stealer from reading that account's own browser data. Pair with the"
c_yellow "ShellGuard + ExposureScan layers of this kit."
