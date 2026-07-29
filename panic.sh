#!/usr/bin/env bash
#
# panic.sh — print the incident-response checklist with nothing else running
# ==============================================================================
# You are having a bad morning. This prints INCIDENT.md to your terminal, with
# no network, no browser, and no dependencies beyond what macOS ships.
#
# Assume the machine is hostile and the network is off. That is the whole design
# constraint: the checklist has to be readable when nothing else works.
#
#   ./panic.sh              print the checklist
#   ./panic.sh --short      the ordered summary only (fits on a phone screen)
#   ./panic.sh --paper      plain text, no colour, ready to pipe to lpr
#   ./panic.sh --triage     print the checklist, then run local root-check probes
#
# DEFENSIVE USE ONLY. Reads files, prints text. Changes nothing, sends nothing.
# ==============================================================================

set -euo pipefail

KIT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" >/dev/null 2>&1 && pwd -P)"
DOC="$KIT_DIR/INCIDENT.md"

MODE="full"
case "${1:-}" in
  --short)  MODE="short" ;;
  --paper)  MODE="paper" ;;
  --triage) MODE="triage" ;;
  -h|--help)
    sed -n '3,20p' "${BASH_SOURCE[0]:-$0}" | sed 's/^# \{0,1\}//'
    exit 0 ;;
  "") ;;
  *) printf 'Unknown option: %s (try --help)\n' "$1" >&2; exit 1 ;;
esac

if [ -t 1 ] && [ "$MODE" != "paper" ]; then
  B=$'\033[1m'; R=$'\033[31m'; Y=$'\033[33m'; G=$'\033[32m'; D=$'\033[2m'; X=$'\033[0m'
else
  B=''; R=''; Y=''; G=''; D=''; X=''
fi

# ---- the ordered summary, inlined ------------------------------------------
# Deliberately hard-coded rather than parsed out of INCIDENT.md: if the repo is
# damaged or you are reading this from a USB stick, the ORDER is the part you
# cannot afford to lose. Everything else can be re-derived; the sequence cannot.
print_short() {
  cat <<EOF
${B}${R}INCIDENT — DO IT IN THIS ORDER${X}

  ${B}0${X}  ${R}Crypto first.${X} Seed on that machine? New wallet on a clean
     device, move funds NOW. This is the only step you cannot undo.

  ${B}1${X}  Machine OFF the network. Leave it powered on. ${Y}Do not reboot${X}
     (that destroys the evidence of what actually ran).

  ${B}2${X}  ${R}Sign out of ALL sessions — BEFORE changing any password.${X}
     A stolen cookie logs in without your password AND without 2FA.
     Change the password first and stop there, and they are still in.

  ${B}3${X}  Revoke third-party app access (OAuth). Survives password changes.

  ${B}4${X}  NOW change passwords. ${B}Email first${X} — it resets everything else.
     Every password saved in a browser is already gone.

  ${B}5${X}  Hunt mail persistence: forwarding, filters matching reset/verify/code,
     send-as aliases, delegated access, app-specific passwords, recovery
     address + phone. All invisible day to day. All survive a reset.

  ${B}6${X}  Rotate dev tokens, blast radius first:
     npm/PyPI publish tokens → cloud keys (${Y}disable, then delete${X}) →
     GitHub PATs → SSH/GPG → per-repo deploy keys + Actions secrets →
     hosting/Stripe → every .env value.

  ${B}7${X}  Apple ID: devices, password, app-specific passwords, trusted numbers.
     iCloud Keychain sync on = every synced credential, every device.

  ${B}8${X}  ${B}Did anything get root?${X} Did you type your Mac password into any
     prompt? New /Library/LaunchDaemons, PrivilegedHelperTools, config
     profile, or system extension?
       ${R}YES to any  → erase and reinstall. Restore DATA only.${X}
       ${G}NO to all   → targeted cleanup is defensible.${X}
     Cannot tell? Wipe. An unnecessary reinstall costs an afternoon.

  ${D}Full detail: ./panic.sh   or   INCIDENT.md${X}
EOF
}

# ---- local probes for step 8 -----------------------------------------------
# Read-only. These answer the "did it get root?" question with facts instead of
# memory, which is the one place in the list where guessing is expensive.
print_triage() {
  printf '\n%s%sStep 8 probes — did anything get root on THIS machine?%s\n\n' "$B" "$R" "$X"
  printf '%sRead-only. Nothing below changes anything.%s\n\n' "$D" "$X"

  printf '%s-- /Library/LaunchDaemons (system-wide, runs as root) --%s\n' "$B" "$X"
  ls -la /Library/LaunchDaemons/ 2>/dev/null | tail -n +2 || printf '  (none / unreadable)\n'

  printf '\n%s-- /Library/LaunchAgents --%s\n' "$B" "$X"
  ls -la /Library/LaunchAgents/ 2>/dev/null | tail -n +2 || printf '  (none / unreadable)\n'

  printf '\n%s-- ~/Library/LaunchAgents (per-user, no root needed) --%s\n' "$B" "$X"
  ls -la "$HOME/Library/LaunchAgents/" 2>/dev/null | tail -n +2 || printf '  (none)\n'

  printf '\n%s-- /Library/PrivilegedHelperTools --%s\n' "$B" "$X"
  ls -la /Library/PrivilegedHelperTools/ 2>/dev/null | tail -n +2 || printf '  (none)\n'

  printf '\n%s-- configuration profiles / MDM --%s\n' "$B" "$X"
  profiles status -type enrollment 2>/dev/null || printf '  (unavailable)\n'

  printf '\n%s-- system extensions --%s\n' "$B" "$X"
  systemextensionsctl list 2>/dev/null | head -20 || printf '  (unavailable)\n'

  printf '\n%s-- sudoers drop-ins --%s\n' "$B" "$X"
  ls -la /etc/sudoers.d/ 2>/dev/null | tail -n +2 || printf '  (none / unreadable without sudo)\n'

  printf '\n%s-- SSH authorized_keys (quieter persistence than a LaunchDaemon) --%s\n' "$B" "$X"
  if [ -f "$HOME/.ssh/authorized_keys" ]; then
    awk '{print "  " NR ": " $1 " " substr($2,1,24) "... " $3}' "$HOME/.ssh/authorized_keys" 2>/dev/null
    printf '  %sAny key here that you did not add is remote access.%s\n' "$Y" "$X"
  else
    printf '  (no authorized_keys — good)\n'
  fi

  printf '\n%s-- remote access services --%s\n' "$B" "$X"
  printf '  sshd (Remote Login): '
  if launchctl print-disabled system 2>/dev/null | grep -q '"com.openssh.sshd" => disabled'; then
    printf '%sdisabled%s\n' "$G" "$X"
  else
    printf '%senabled or unknown — check System Settings > General > Sharing%s\n' "$Y" "$X"
  fi
  printf '  Screen Sharing: '
  if launchctl print-disabled system 2>/dev/null | grep -q '"com.apple.screensharing" => disabled'; then
    printf '%sdisabled%s\n' "$G" "$X"
  else
    printf '%senabled or unknown%s\n' "$Y" "$X"
  fi

  printf '\n%s-- SIP --%s\n' "$B" "$X"
  csrutil status 2>/dev/null || printf '  (unavailable)\n'

  printf '\n%s-- recent Downloads (last 20) --%s\n' "$B" "$X"
  ls -lt "$HOME/Downloads" 2>/dev/null | head -21 | tail -n +2 || printf '  (none)\n'

  printf '\n%sIf anything above is unfamiliar, treat the answer to step 8 as YES.%s\n' "$B" "$X"
  printf '%sDo not delete it yet — run ./preserve.sh first if you want the record.%s\n\n' "$D" "$X"
}

# ---- main -------------------------------------------------------------------
case "$MODE" in
  short)
    print_short
    ;;
  triage)
    print_short
    print_triage
    ;;
  *)
    if [ ! -r "$DOC" ]; then
      # The document is gone but the order is what matters. Never leave the
      # user with nothing during an incident.
      printf '%s[panic] INCIDENT.md not found at %s%s\n\n' "$Y" "$DOC" "$X" >&2
      printf '%sFalling back to the built-in summary — the ordering is the part that matters.%s\n' "$D" "$X" >&2
      print_short
      exit 0
    fi

    print_short
    printf '\n%s%s\n' "$D" "$(printf '%.0s─' {1..76})"
    printf 'Full checklist below. Also readable on your phone at:\n'
    printf 'github.com/DareDev256/clickfix-defense-kit/blob/main/INCIDENT.md%s\n\n' "$X"

    # Strip markdown syntax for terminal reading. No pager: if you are having an
    # incident you want the whole thing scrollable in your buffer, not paged.
    sed -e 's/^# /\
/' -e 's/^## //' -e 's/\*\*//g' -e 's/^> //' -e 's/- \[ \]/  [ ]/' "$DOC"
    ;;
esac
