#!/usr/bin/env bash
#
# preserve.sh — capture the evidence BEFORE you start cleaning up
# ==============================================================================
# Every instinct after an alert destroys the record that tells you what actually
# ran — and therefore how much of INCIDENT.md you truly need to work through.
# Rebooting clears process and network state. Deleting the suspicious plist
# removes the thing you would have identified it by. Even WatchPost makes it
# worse by design: after alerting it promotes the baseline, so the diff that
# proved something appeared is gone on the next run. (Use `watchpost.sh
# --no-update` during an incident — that is what the flag is for.)
#
# This writes a timestamped, read-only bundle. It reads; it never remediates.
#
# IF JAMF'S AFTERMATH IS INSTALLED, THIS DEFERS TO IT AND STOPS.
# Aftermath is free, Swift, purpose-built for macOS incident response, and
# collects a superset of what a shell script can. Reimplementing it would be
# worse code doing a solved job. This script's value is the ClickFix-specific
# ordering and the fact that it is already here — not the collection itself.
#   https://github.com/jamf/aftermath
#
# Usage:
#   ./preserve.sh                     bundle into ./clickfix-evidence-<stamp>
#   ./preserve.sh -o /Volumes/USB     bundle onto external media (preferred)
#   ./preserve.sh --no-aftermath      force the built-in collector
#   ./preserve.sh --log-hours 24      widen the unified-log window (default 6)
#
# Write the bundle to EXTERNAL media if you can. A bundle stored on the machine
# you are investigating is evidence the attacker can still reach.
#
# DEFENSIVE USE ONLY. Read-only. Nothing is transmitted anywhere.
# ==============================================================================

set -uo pipefail

STAMP="$(date '+%Y%m%d-%H%M%S')"
OUTBASE="."
USE_AFTERMATH=1
# Hours of unified log to pull. Kept small on purpose: see the note at the
# capture step. Raise it if you know the incident was longer ago.
LOG_HOURS="${PRESERVE_LOG_HOURS:-6}"

while [ $# -gt 0 ]; do
  case "$1" in
    -o|--out) OUTBASE="${2:-.}"; shift 2 ;;
    --no-aftermath) USE_AFTERMATH=0; shift ;;
    --log-hours) LOG_HOURS="${2:-6}"; shift 2 ;;
    -h|--help) sed -n '3,32p' "${BASH_SOURCE[0]:-$0}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) printf 'Unknown option: %s (try --help)\n' "$1" >&2; exit 1 ;;
  esac
done

if [ -t 1 ]; then
  B=$'\033[1m'; Y=$'\033[33m'; G=$'\033[32m'; D=$'\033[2m'; X=$'\033[0m'
else
  B=''; Y=''; G=''; D=''; X=''
fi

say()  { printf '%s\n' "$*"; }
step() { printf '%s->%s %s\n' "$B" "$X" "$*"; }

BUNDLE="$OUTBASE/clickfix-evidence-$STAMP"

# ---- defer to Aftermath if present -------------------------------------------
if [ "$USE_AFTERMATH" -eq 1 ]; then
  AFTERMATH=""
  for c in /usr/local/bin/aftermath /opt/homebrew/bin/aftermath "$(command -v aftermath 2>/dev/null || true)"; do
    [ -n "$c" ] && [ -x "$c" ] && { AFTERMATH="$c"; break; }
  done
  if [ -n "$AFTERMATH" ]; then
    say "${G}Jamf Aftermath found at $AFTERMATH${X}"
    say "${D}It collects a superset of what this script would. Deferring to it.${X}"
    say "${Y}Aftermath needs root. You will be prompted.${X}"
    say ""
    mkdir -p "$BUNDLE"
    sudo "$AFTERMATH" -o "$BUNDLE" || {
      say "${Y}Aftermath exited non-zero. Re-run with --no-aftermath for the built-in collector.${X}"
      exit 1
    }
    say ""
    say "${G}Done.${X} Bundle: $BUNDLE"
    say "Next: work INCIDENT.md in order. Start at step 0."
    exit 0
  fi
  say "${D}Jamf Aftermath not installed — using the built-in collector.${X}"
  say "${D}For a real investigation, prefer it: https://github.com/jamf/aftermath${X}"
  say ""
fi

# ---- built-in collector ------------------------------------------------------
mkdir -p "$BUNDLE"
chmod 700 "$BUNDLE"
say "${B}Collecting into $BUNDLE${X}"
say ""

cap() {
  # cap <filename> <description> <command...>
  local f="$BUNDLE/$1"; shift
  local desc="$1"; shift
  step "$desc"
  { printf '# %s\n# captured %s\n# command: %s\n\n' "$desc" "$(date)" "$*"; "$@" 2>&1; } > "$f" || true
}

cap system.txt        "system + OS version"        sw_vers
cap uptime.txt        "uptime (has it been rebooted since?)" uptime
cap processes.txt     "running processes"          ps auxww
cap network.txt       "established network connections" lsof -i -n -P
cap listening.txt     "listening ports"            netstat -anv
cap launchd-user.txt  "user LaunchAgents"          ls -la@ "$HOME/Library/LaunchAgents/"
cap launchd-lib.txt   "library LaunchAgents"       ls -la@ /Library/LaunchAgents/
cap launchd-daemon.txt "LaunchDaemons (root)"      ls -la@ /Library/LaunchDaemons/
cap privhelpers.txt   "privileged helper tools"    ls -la@ /Library/PrivilegedHelperTools/
cap loaded-agents.txt "loaded launchd jobs"        launchctl list
cap profiles.txt      "configuration profiles / MDM" profiles status -type enrollment
cap sysextensions.txt "system extensions"          systemextensionsctl list
cap kexts.txt         "third-party kernel extensions" kmutil showloaded --no-kernel-components
cap sip.txt           "SIP status"                 csrutil status
cap cron.txt          "crontab"                    crontab -l
cap sudoers.txt       "sudoers drop-ins"           ls -la /etc/sudoers.d/
cap ssh-authkeys.txt  "SSH authorized_keys"        cat "$HOME/.ssh/authorized_keys"
cap ssh-config.txt    "SSH client config (ProxyCommand injection)" cat "$HOME/.ssh/config"
cap sshd-config.txt   "sshd config"                cat /etc/ssh/sshd_config
cap downloads.txt     "Downloads with quarantine xattrs" ls -la@ "$HOME/Downloads"
cap shell-history.txt "zsh history"                cat "$HOME/.zsh_history"
cap bash-history.txt  "bash history"               cat "$HOME/.bash_history"
cap installed-apps.txt "applications"              ls -la /Applications
cap login-items.txt   "login items"                osascript -e 'tell application "System Events" to get the name of every login item'

# Origin URLs for recent downloads — the single most useful artifact for
# answering "where did this come from?", and it is not in `ls`.
step "download origin URLs (kMDItemWhereFroms)"
{
  printf '# Origin URL of each recent download.\n'
  printf '# This is what tells you which site delivered the payload.\n\n'
  find "$HOME/Downloads" -maxdepth 1 -type f -mtime -30 2>/dev/null | while IFS= read -r f; do
    printf '%s\n' "$f"
    mdls -name kMDItemWhereFroms "$f" 2>/dev/null | sed 's/^/    /'
    xattr -p com.apple.quarantine "$f" 2>/dev/null | sed 's/^/    quarantine: /'
    printf '\n'
  done
} > "$BUNDLE/download-origins.txt" 2>&1 || true

# Hash + signature verdict for every persistence plist. A name alone tells you
# nothing; a codesign verdict tells you whether it is Apple's.
step "hashing + codesign verdict for persistence plists"
{
  printf '# Every LaunchAgent/LaunchDaemon: sha256, and the codesign verdict of\n'
  printf '# its ProgramArguments target where one can be resolved.\n\n'
  for d in "$HOME/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons; do
    [ -d "$d" ] || continue
    printf '=== %s ===\n' "$d"
    find "$d" -maxdepth 1 -name '*.plist' 2>/dev/null | while IFS= read -r p; do
      printf '%s\n' "$p"
      shasum -a 256 "$p" 2>/dev/null | awk '{print "    sha256: " $1}'
      prog="$(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments:0' "$p" 2>/dev/null || \
              /usr/libexec/PlistBuddy -c 'Print :Program' "$p" 2>/dev/null || true)"
      if [ -n "$prog" ]; then
        printf '    program: %s\n' "$prog"
        codesign -dv --verbose=2 "$prog" 2>&1 | grep -E 'Authority|Identifier' | sed 's/^/    /' || \
          printf '    codesign: UNSIGNED or unresolvable\n'
      fi
      printf '\n'
    done
  done
} > "$BUNDLE/persistence-detail.txt" 2>&1 || true

# Unified log, bounded hard.
#
# NOTE: predicate choice matters enormously here. `eventMessage CONTAINS ...`
# forces a full scan of the log store and can run for many minutes on a busy
# machine — long enough that during an actual incident you would kill it and
# lose the artifact entirely. Filtering on `process`, which is indexed, returns
# in seconds. Narrower, and you actually get it.
step "unified log — sudo/osascript/curl activity (last ${LOG_HOURS}h)"
log show --last "${LOG_HOURS}h" --style syslog \
  --predicate 'process == "sudo" OR process == "osascript" OR process == "curl" OR process == "bash" OR process == "zsh"' \
  > "$BUNDLE/unified-log-exec.txt" 2>&1 || \
  printf 'unified log unavailable\n' > "$BUNDLE/unified-log-exec.txt"

# TCC: which apps hold the grants malware wants to inherit.
step "TCC grants (which apps hold FDA / Accessibility / Screen Recording)"
{
  for db in "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
            "/Library/Application Support/com.apple.TCC/TCC.db"; do
    [ -r "$db" ] || { printf '# unreadable (needs Full Disk Access): %s\n' "$db"; continue; }
    printf '=== %s ===\n' "$db"
    sqlite3 "file:$db?mode=ro" \
      'SELECT service, client, auth_value FROM access ORDER BY service;' 2>/dev/null || \
      printf '  (query failed)\n'
  done
} > "$BUNDLE/tcc-grants.txt" 2>&1 || true

# Freeze the bundle. Read-only so a later cleanup cannot quietly alter it.
step "sealing the bundle"
{
  printf '# ClickFix Defense Kit — evidence bundle\n'
  printf '# host: %s\n' "$(scutil --get LocalHostName 2>/dev/null || hostname)"
  printf '# captured: %s\n' "$(date)"
  printf '# collector: preserve.sh (built-in)\n\n'
  printf '# sha256 of every file in this bundle:\n'
  ( cd "$BUNDLE" && find . -type f ! -name MANIFEST.txt -exec shasum -a 256 {} \; | sort -k2 )
} > "$BUNDLE/MANIFEST.txt" 2>&1 || true

chmod -R a-w "$BUNDLE" 2>/dev/null || true

say ""
say "${G}Done.${X} Bundle: ${B}$BUNDLE${X}"
say "$(find "$BUNDLE" -type f | wc -l | tr -d ' ') files, read-only, MANIFEST.txt has the hashes."
say ""
say "${Y}Copy it to external media now${X} — a bundle left on the machine you are"
say "investigating is evidence the attacker can still reach."
say ""
say "Next: work ${B}INCIDENT.md${X} in order, starting at step 0. Or: ./panic.sh"
