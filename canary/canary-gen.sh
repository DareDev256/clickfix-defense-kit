#!/usr/bin/env bash
#
# canary-gen.sh — Honeytoken tripwire generator (part of the ClickFix Defense Kit)
# ---------------------------------------------------------------------------------
# CONFIRMED-SECRET-OK: every credential-shaped string in this file and the
# templates/ directory is an OBVIOUSLY-FAKE placeholder (contains EXAMPLE / FAKE /
# PLACEHOLDER). They are decoy bait by design and carry no live access. Verified
# not a live key.
#
# DEFENSIVE USE ONLY. This script plants DECOY credentials on YOUR OWN machine so
# that if an infostealer (AMOS / Atomic / Poseidon, etc.) or a ClickFix-pasted
# payload reads or *uses* them, you get an alert telling you you've been breached.
#
# How the detection works (two independent layers):
#
#   LAYER A — NETWORK CALLBACK (canarytokens.org):
#       You mint a free token at canarytokens.org. The token is a credential that
#       is harmless until *used*. When an attacker takes the fake AWS key and runs
#       `aws sts get-caller-identity`, or opens the bait document, the token phones
#       home to Thinkst, who emails/webhooks YOU. You learn the breach happened AND
#       (often) the source IP. This script just scatters those tokens realistically.
#       HONEST LIMIT: it only fires when the credential is USED / the doc is OPENED.
#       An attacker who `cat`s the file and walks away triggers NOTHING here.
#
#   LAYER B — LOCAL READ (optional, macOS `log stream` / eslogger):
#       To catch the read-and-walk-away case, see `--watch-note`. It prints how to
#       use Apple's Endpoint Security tooling to alert the moment a decoy file is
#       OPENED locally — even with no network. This is heavier (root + Full Disk
#       Access) and is documented honestly as opt-in, not the default.
#
# This script writes ONLY obviously-fake placeholder values. It does not exfiltrate
# anything, makes no network calls itself, and touches nothing outside the decoy
# paths you choose. Every decoy is tagged with a unique MARKER so that if it later
# surfaces in a paste, a log, a leak, or a stealer dump, you can trace the source.
#
# Usage:
#   ./canary-gen.sh                         # interactive: pick locations, plant decoys
#   ./canary-gen.sh --here                  # plant the standard decoy set in CWD
#   ./canary-gen.sh --paths ~/.aws ~/Desktop # plant into specific dirs (non-interactive)
#   ./canary-gen.sh --token AKIA_FROM_CANARYTOKENS  # use a REAL canarytoken AWS key
#   ./canary-gen.sh --canary-walkthrough    # print the canarytokens.org minting guide
#   ./canary-gen.sh --watch-note            # print the local read-detection (eslogger) note
#   ./canary-gen.sh --list                  # list decoys this tool has planted
#   ./canary-gen.sh --revert                # remove all decoys this tool planted
#
# Exit codes: 0 ok, 1 usage error, 2 refused (safety guard).
#
set -euo pipefail

# --------------------------------------------------------------------------------
# Constants & state
# --------------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE_DIR="${SCRIPT_DIR}/templates"

# Ledger of everything we plant, so --list and --revert work and so a planted
# decoy is never confused with a real file. Stored in the user's state dir.
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/clickfix-defense-kit"
LEDGER="${STATE_DIR}/canary-ledger.tsv"   # columns: marker<TAB>path<TAB>kind<TAB>iso8601

# A token to embed in every decoy. If you minted a real canarytoken AWS key, pass
# it with --token so the planted ~/.aws/credentials actually beacons when used.
# Otherwise we embed an OBVIOUSLY-FAKE placeholder that has no network behaviour.
# (All three below are non-live placeholders — see CONFIRMED-SECRET-OK note above.)
CANARY_AWS_KEY="AKIA_PLACEHOLDER_EXAMPLE"       # placeholder, replace via --token
CANARY_AWS_SECRET="FAKE_PLACEHOLDER_SECRET_DO_NOT_USE_EXAMPLE"
CANARY_URL_TOKEN="http://canarytokens.com/REPLACE_WITH_YOUR_TOKEN/index.html"

RED=$'\e[1;31m'; GRN=$'\e[1;32m'; YEL=$'\e[1;33m'; CYA=$'\e[1;36m'; RST=$'\e[0m'

note()  { printf '%s[canary]%s %s\n' "$CYA" "$RST" "$*"; }
ok()    { printf '%s[canary]%s %s\n' "$GRN" "$RST" "$*"; }
warn()  { printf '%s[canary]%s %s\n' "$YEL" "$RST" "$*" >&2; }
die()   { printf '%s[canary]%s %s\n' "$RED" "$RST" "$*" >&2; exit "${2:-1}"; }

# --------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------

# Generate a short, unique, traceable marker for a decoy. Format:
#   CANARY-<8 hex>-<unix epoch>
# The marker is embedded inside every decoy file (in a comment) so that if the
# fake credential ever turns up in a stealer log, paste, or breach dump, you can
# grep your ledger and know exactly which decoy leaked and when you planted it.
gen_marker() {
  local rand
  if command -v openssl >/dev/null 2>&1; then
    rand="$(openssl rand -hex 4)"
  else
    # Fallback: use the kernel RNG so we never depend on a single tool.
    rand="$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  fi
  printf 'CANARY-%s-%s' "$rand" "$(date +%s)"
}

ensure_state() {
  mkdir -p "$STATE_DIR"
  [ -f "$LEDGER" ] || printf 'marker\tpath\tkind\tcreated\n' > "$LEDGER"
}

# Record a planted decoy in the ledger.
record() {
  local marker="$1" path="$2" kind="$3"
  printf '%s\t%s\t%s\t%s\n' "$marker" "$path" "$kind" "$(date +%FT%T%z)" >> "$LEDGER"
}

# Refuse to overwrite a file that we did NOT plant. We only ever clobber our own
# decoys (so re-running is safe) — never a user's real ~/.aws/credentials or .env.
guard_target() {
  local target="$1"
  if [ -e "$target" ]; then
    if grep -q 'CANARY-' "$target" 2>/dev/null; then
      warn "Decoy already present at ${target} — refreshing it."
      return 0
    fi
    die "REFUSING to overwrite existing non-decoy file: ${target}
     (It does not contain a CANARY- marker, so it may be a real file.)
     Move/rename it yourself first, or choose a different location." 2
  fi
}

# Render a template, substituting the marker and token placeholders, to a target.
# Uses a sed-free / awk-free substitution loop so there are no escaping traps.
render_template() {
  local template="$1" target="$2" marker="$3"
  [ -f "$template" ] || die "Template not found: ${template}"
  mkdir -p "$(dirname "$target")"
  # Read template, replace placeholders line by line (POSIX-safe, no sed needed).
  local line out=""
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line//@@MARKER@@/$marker}"
    line="${line//@@AWS_KEY@@/$CANARY_AWS_KEY}"
    line="${line//@@AWS_SECRET@@/$CANARY_AWS_SECRET}"
    line="${line//@@CANARY_URL@@/$CANARY_URL_TOKEN}"
    line="${line//@@CREATED@@/$(date +%FT%T%z)}"
    out+="${line}"$'\n'
  done < "$template"
  printf '%s' "$out" > "$target"
  chmod 600 "$target"   # tempting perms for a "real" secret; also keeps it private
}

# --------------------------------------------------------------------------------
# Decoy planters — one per decoy kind. Each plants a single decoy into a directory.
# --------------------------------------------------------------------------------

plant_aws_creds() {
  local dir="$1" marker; marker="$(gen_marker)"
  local target="${dir%/}/credentials"
  guard_target "$target"
  render_template "${TEMPLATE_DIR}/aws-credentials.decoy" "$target" "$marker"
  record "$marker" "$target" "aws-credentials"
  ok "Planted fake AWS credentials  -> ${target}  [${marker}]"
}

plant_dotenv() {
  local dir="$1" marker; marker="$(gen_marker)"
  local target="${dir%/}/.env"
  guard_target "$target"
  render_template "${TEMPLATE_DIR}/dotenv.decoy" "$target" "$marker"
  record "$marker" "$target" "dotenv"
  ok "Planted fake .env             -> ${target}  [${marker}]"
}

plant_passwords() {
  local dir="$1" marker; marker="$(gen_marker)"
  local target="${dir%/}/passwords.txt"
  guard_target "$target"
  render_template "${TEMPLATE_DIR}/passwords.decoy" "$target" "$marker"
  record "$marker" "$target" "passwords"
  ok "Planted bait passwords.txt    -> ${target}  [${marker}]"
}

# Plant the "standard set" appropriate for a given directory. Some decoys only
# make sense in certain spots (AWS creds belong in an .aws dir), so we choose.
plant_set_for_dir() {
  local dir="$1"
  mkdir -p "$dir"
  case "$dir" in
    *.aws) plant_aws_creds "$dir" ;;
    *Desktop|*Documents)
        plant_passwords "$dir"; plant_dotenv "$dir" ;;
    *)  plant_dotenv "$dir" ;;
  esac
}

# --------------------------------------------------------------------------------
# Subcommands
# --------------------------------------------------------------------------------

do_list() {
  ensure_state
  note "Decoys planted by this tool (from ${LEDGER}):"
  if [ "$(wc -l < "$LEDGER")" -le 1 ]; then
    echo "  (none yet — run the planter first)"
    return 0
  fi
  # Pretty-print the ledger; flag any decoy that has since been deleted.
  # NOTE: this loop PRINTS $kind, so the field must not be named _kind — under
  # `set -u` an underscore-prefixed read target left $kind unbound and aborted
  # `--list` on any non-empty ledger (fixed 2026-07-29).
  tail -n +2 "$LEDGER" | while IFS=$'\t' read -r marker path kind _created; do
    if [ -e "$path" ]; then
      printf '  %s%-22s%s %-18s %s\n' "$GRN" "$marker" "$RST" "$kind" "$path"
    else
      printf '  %s%-22s%s %-18s %s %s(MISSING — read/moved/deleted?)%s\n' \
        "$YEL" "$marker" "$RST" "$kind" "$path" "$RED" "$RST"
    fi
  done
}

do_revert() {
  ensure_state
  note "Removing all decoys this tool planted..."
  tail -n +2 "$LEDGER" | while IFS=$'\t' read -r marker path _kind _created; do
    if [ -e "$path" ] && grep -q "$marker" "$path" 2>/dev/null; then
      rm -f "$path" && ok "Removed ${path}  [${marker}]"
    fi
  done
  # Reset the ledger header only.
  printf 'marker\tpath\tkind\tcreated\n' > "$LEDGER"
  ok "Revert complete. Ledger cleared."
}

# Interactive location picker. Offers the canonical tempting locations a stealer
# is known to grab, lets the user toggle them, then plants.
do_interactive() {
  ensure_state
  note "Pick where to plant decoys. These are the locations infostealers target."
  echo
  local -a CANDIDATES=(
    "$HOME/.aws"          # AMOS/Atomic grab ~/.aws/credentials
    "$HOME/Desktop"       # 'passwords.txt' bait, high-traffic for a smash-and-grab
    "$HOME/Documents"
    "$HOME"               # ~/.env at home root
  )
  local -a CHOSEN=()
  local i=1
  for c in "${CANDIDATES[@]}"; do
    printf '  %d) %s\n' "$i" "$c"; i=$((i+1))
  done
  echo "  a) all of the above"
  echo
  printf 'Enter numbers (space-separated), "a" for all, or a custom path: '
  read -r answer < /dev/tty || answer="a"

  if [ "$answer" = "a" ] || [ -z "$answer" ]; then
    CHOSEN=("${CANDIDATES[@]}")
  else
    for tok in $answer; do
      if [[ "$tok" =~ ^[0-9]+$ ]] && [ "$tok" -ge 1 ] && [ "$tok" -le "${#CANDIDATES[@]}" ]; then
        CHOSEN+=("${CANDIDATES[$((tok-1))]}")
      elif [ -d "$tok" ] || [[ "$tok" == /* || "$tok" == ~* ]]; then
        # Treat as a custom directory path; expand a leading ~.
        CHOSEN+=("${tok/#\~/$HOME}")
      else
        warn "Ignoring unrecognized choice: ${tok}"
      fi
    done
  fi

  [ "${#CHOSEN[@]}" -gt 0 ] || die "No valid locations chosen."
  echo
  for dir in "${CHOSEN[@]}"; do
    plant_set_for_dir "$dir"
  done
  echo
  print_post_plant_summary
}

print_post_plant_summary() {
  ok "Done. Decoys are in place."
  cat <<EOF

${CYA}NEXT STEPS${RST}
  1. Mint a REAL canarytoken so a *used* decoy actually alerts you:
         ${0##*/} --canary-walkthrough
     Then re-plant with your real key:
         ${0##*/} --token AKIA<your-real-canarytoken-key> --paths ~/.aws
  2. (Optional, heavier) Turn on LOCAL read-detection to catch a decoy that is
     merely READ (not used):
         ${0##*/} --watch-note
  3. Audit what you planted any time:  ${0##*/} --list
  4. Clean up:                         ${0##*/} --revert

${YEL}HONEST LIMITS (read these):${RST}
  - A placeholder decoy (no real token) does NOT alert you on its own. It is a
    tripwire ONLY if (a) you used --token with a real canarytoken, or (b) you
    enabled the local read-watch. A bare placeholder is just bait + a marker you
    can later grep for in a breach dump.
  - canarytokens fire on USE/OPEN, never on a silent read. Pair with --watch-note
    for read detection.
  - This is detection, not prevention. It tells you AFTER the fact. The zsh
    ShellGuard layer of this kit is what blocks the paste in the first place.
EOF
}

print_canary_walkthrough() {
  cat <<'EOF'
================================================================================
  canarytokens.org — free honeytoken minting walkthrough
================================================================================

WHAT IT IS
  canarytokens.org (by Thinkst) hands you a credential that is harmless until
  someone USES it. The moment it's used, Thinkst alerts YOU (email or webhook)
  with a timestamp and, usually, the source IP. It is free and needs no account.

WHICH TOKEN TYPE TO PICK (best -> situational)
  1. AWS keys  ............ HIGHEST signal. Drop into ~/.aws/credentials. Any
                            stealer / curious attacker who runs
                            `aws sts get-caller-identity` trips it. Auto-scanners
                            (TruffleHog-style) validate keys, so it can fire on a
                            dry test even without manual use.
  2. Fast Redirect / URL .. Embed in a fake `backup.sh` or a bookmark. Fires when
                            the URL is requested.
  3. Web bug / image ...... Embed in a bait .docx / .pdf ("wallet-seed.pdf").
                            Fires when the document is OPENED and rendered.

STEP BY STEP (AWS key example)
  1. Open https://canarytokens.org in a browser.
  2. Select token type:  "AWS keys".
  3. In "Email" enter the address you want the breach alert sent to,
     OR paste a "Webhook URL" (e.g. your private Discord webhook) to get the
     alert in a channel instead of email.
  4. In "Reminder note" type something you'll recognise later, e.g.:
         "ClickFix kit decoy — ~/.aws/credentials on <machine-name>"
     This note is echoed back in the alert so you instantly know WHICH decoy fired.
  5. Click "Create my Canarytoken".
  6. You'll be shown an Access Key ID (AKIA...) and a Secret Access Key.
     COPY BOTH.
  7. Re-plant the decoy with the real key so it actually beacons:
         ./canary-gen.sh --token AKIA<the-key-you-got> --paths ~/.aws
     (Then hand-edit the planted ~/.aws/credentials to paste the SECRET too, or
      keep the placeholder secret — the AKIA id alone is enough for the AWS
      canarytoken to fire on `sts get-caller-identity`.)
  8. Test it: from a THROWAWAY shell run
         aws sts get-caller-identity
     You should receive your own alert within seconds. Now you KNOW the wiring
     works. Delete the test result; leave the decoy in place.

KNOWN TELL (be aware, document honestly)
  AWS canarytokens return a username that contains a Thinkst beacon domain when
  queried, so a careful attacker who inspects the identity can notice it's a
  honeytoken and avoid using it. That's fine — most automated stealers don't
  bother, and the local read-watch (./canary-gen.sh --watch-note) covers the
  careful-attacker case.

WEBHOOK TIP
  Routing alerts to a private Discord/Slack webhook beats email for a solo dev:
  you'll actually see it. Put the webhook in canarytokens.org's "Webhook URL"
  field at mint time. Never commit the webhook URL to git.
================================================================================
EOF
}

print_watch_note() {
  cat <<'EOF'
================================================================================
  OPTIONAL LOCAL READ-DETECTION (macOS) — catch a decoy that is merely READ
================================================================================

WHY YOU MIGHT WANT THIS
  canarytokens only fire when a credential is USED or a document is OPENED-and-
  rendered. An attacker who does `cat ~/.aws/credentials` and walks away triggers
  NOTHING. To catch that, you need the OS to tell you the file was opened. macOS
  ships two ways to do this. Both are HEAVIER and PERMISSION-GATED. This is opt-in.

  Honest cost: you must run a watcher as root AND grant Full Disk Access (and for
  eslogger, the responsible terminal app needs FDA in System Settings > Privacy &
  Security). Asking a freshly-compromised machine to grant root+FDA to a new tool
  is itself the trust profile of malware — so only do this on a machine you trust,
  and prefer a signed/notarized helper if you distribute it.

--------------------------------------------------------------------------------
OPTION 1 — `log stream` (no root for some events; lightest to try first)
--------------------------------------------------------------------------------
  macOS unified logging can surface file activity. This is coarse and noisy but
  needs no custom code. Watch for processes touching your decoy paths:

    log stream --style compact --predicate \
      'eventMessage CONTAINS[c] "credentials" OR eventMessage CONTAINS[c] ".env"' \
      | grep -i -E 'credentials|\.env|passwords\.txt'

  Pipe matches to a notifier (replace the decoy path check as needed):

    log stream --style compact \
      --predicate 'eventMessage CONTAINS[c] "/.aws/credentials"' \
    | while IFS= read -r line; do
        osascript -e 'display notification "Decoy ~/.aws/credentials was touched" \
          with title "CANARY TRIPPED" sound name "Basso"'
      done

  Caveat: unified logging does NOT reliably emit a clean "file was open()'d"
  event for every read; coverage varies by macOS version. For authoritative
  open-detection use Option 2.

--------------------------------------------------------------------------------
OPTION 2 — `eslogger` (Apple Endpoint Security; authoritative, needs root + FDA)
--------------------------------------------------------------------------------
  `eslogger` ships with macOS and is pre-entitled for Endpoint Security. It emits
  one JSON event per file open. Subscribe to NOTIFY_OPEN and filter to your decoy
  paths. Requires sudo (root) and Full Disk Access on the running terminal.

    # 1. Grant Full Disk Access:
    #    System Settings > Privacy & Security > Full Disk Access > add your
    #    terminal app (Terminal.app / Ghostty / iTerm). Restart the terminal.
    #
    # 2. Stream open() events, filter to decoy paths, alert via Discord/osascript:

    DECOYS='/Users/you/.aws/credentials|/Users/you/Desktop/passwords.txt|/Users/you/.env'

    sudo eslogger open 2>/dev/null \
    | /usr/bin/jq -c --arg re "$DECOYS" '
        select(.event.open.file.target.path | test($re))
        | { ts: .time,
            path: .event.open.file.target.path,
            proc: .process.executable.path,
            pid:  .process.audit_token.pid }' \
    | while IFS= read -r hit; do
        path=$(printf '%s' "$hit" | /usr/bin/jq -r .path)
        proc=$(printf '%s' "$hit" | /usr/bin/jq -r .proc)
        osascript -e "display notification \"$proc opened $path\" \
          with title \"CANARY TRIPPED (local read)\" sound name \"Basso\""
        # Optional: also POST $hit to your private Discord webhook here.
      done

  What you learn: the EXACT process, pid, and timestamp that opened a decoy —
  even if nothing ever hit the network. This is the only layer that catches the
  read-and-walk-away attacker.

--------------------------------------------------------------------------------
PERSISTENCE (run it unattended)
--------------------------------------------------------------------------------
  To keep the watcher running, wrap Option 2 in a LaunchDaemon (root domain) at
  /Library/LaunchDaemons/com.clickfixkit.canary-watch.plist with RunAtLoad +
  KeepAlive, pointing at a small script that runs the eslogger pipeline above.
  Sign/notarize the helper if you distribute it — an unsigned root background
  process that reads files is, correctly, suspicious-looking.

LAYERING (all three cover different failure modes)
  - canarytoken  -> fires when the decoy is USED REMOTELY (key used / doc opened)
  - eslogger     -> fires when the decoy is READ LOCALLY (cat / cp, no network)
  - a firewall   -> (e.g. Objective-See LuLu) sees the outbound callback itself
  Use them together; no single layer is sufficient.
================================================================================
EOF
}

usage() {
  cat <<EOF
canary-gen.sh — honeytoken tripwire generator (ClickFix Defense Kit)

  ./canary-gen.sh                         Interactive: choose locations, plant decoys
  ./canary-gen.sh --here                  Plant the standard decoy set in the CWD
  ./canary-gen.sh --paths DIR [DIR ...]   Plant into specific directories
  ./canary-gen.sh --token AKIA...         Use a REAL canarytoken AWS key in decoys
  ./canary-gen.sh --canary-walkthrough    Print the canarytokens.org minting guide
  ./canary-gen.sh --watch-note            Print the local read-detection (eslogger) note
  ./canary-gen.sh --list                  List decoys this tool has planted
  ./canary-gen.sh --revert                Remove all decoys this tool planted
  ./canary-gen.sh --help                  This help

DEFENSIVE USE ONLY. Plants obviously-fake decoy credentials on YOUR machine so a
breach trips an alert. See README.md for the full threat model and honest limits.
EOF
}

# --------------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------------
main() {
  [ -d "$TEMPLATE_DIR" ] || die "templates/ directory missing next to this script."

  local mode="interactive"
  local -a paths=()

  while [ "$#" -gt 0 ]; do
    case "$1" in
      --help|-h)            usage; exit 0 ;;
      --canary-walkthrough) print_canary_walkthrough; exit 0 ;;
      --watch-note)         print_watch_note; exit 0 ;;
      --list)               do_list; exit 0 ;;
      --revert)             do_revert; exit 0 ;;
      --here)               mode="paths"; paths+=("$PWD"); shift ;;
      --paths)              mode="paths"; shift
                            while [ "$#" -gt 0 ] && [[ "$1" != --* ]]; do
                              paths+=("${1/#\~/$HOME}"); shift
                            done ;;
      --token)              shift
                            [ "$#" -gt 0 ] || die "--token needs an AKIA... value"
                            CANARY_AWS_KEY="$1"
                            note "Using provided canarytoken AWS key for decoys."
                            shift ;;
      *) die "Unknown argument: $1  (try --help)" ;;
    esac
  done

  ensure_state

  case "$mode" in
    interactive) do_interactive ;;
    paths)
      [ "${#paths[@]}" -gt 0 ] || die "No --paths given."
      for dir in "${paths[@]}"; do
        plant_set_for_dir "$dir"
      done
      echo
      print_post_plant_summary ;;
  esac
}

main "$@"
