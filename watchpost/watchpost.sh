#!/bin/bash
#
# watchpost.sh — ClickFix Defense Kit
# ------------------------------------------------------------------------------
# A zero-dependency macOS persistence + login-item change monitor.
#
# WHAT IT DOES
#   1. Snapshots ("baselines") the places macOS malware plants persistence:
#        - ~/Library/LaunchAgents          (per-user agents)
#        - /Library/LaunchAgents           (all-user agents)
#        - /Library/LaunchDaemons          (system daemons, root-loaded)
#        - the current user's crontab       (crontab -l)
#        - login items                      (System Events)
#   2. On every subsequent run it diffs the CURRENT state against the saved
#      baseline and fires a macOS notification listing any NEW entries.
#      A plist whose CONTENT changed (same path, different sha256) is flagged
#      as TAMPER — the loudest signal.
#   3. After alerting, it (optionally) promotes the current state to the new
#      baseline so you only get alerted ONCE per change (same "alert on state
#      change, not every run" discipline as a well-behaved cron job).
#
# WHAT IT IS NOT
#   This is NOT a real-time blocker. It cannot stop a LaunchAgent from being
#   written or loaded — it only tells you, after the fact, that one appeared.
#   For real-time, signing-aware persistence interdiction use Objective-See's
#   free BlockBlock (https://objective-see.org/products/blockblock.html) and
#   LuLu for outbound-network alerting. WatchPost is the lightweight,
#   headless, cron-friendly tripwire that complements them — ideal for an
#   unattended Mac (e.g. a Mac Mini) where BlockBlock's GUI prompts are
#   useless because nobody is sitting at the screen.
#
# THE AMOS / ClickFix ANGLE (why these specific paths)
#   2025-era AMOS/Atomic infostealer variants gained persistence by dropping a
#   LaunchDaemon (observed label: com.finder.helper) into /Library/LaunchDaemons
#   with RunAtLoad + KeepAlive, installed via `sudo -S cp ...` using a password
#   phished through a fake osascript dialog. A new plist appearing in one of the
#   monitored directories — especially a system daemon you did not create — is
#   exactly the signal this tool surfaces.
#
# SAFETY
#   Read-only. Never writes to or deletes any LaunchAgent/Daemon. The only file
#   it writes is its own baseline JSON in the state directory.
#
# REQUIREMENTS / TCC NOTE
#   Reading ~/Library and /Library/LaunchDaemons, and enumerating login items
#   via System Events, can hit macOS TCC (Privacy) walls. Grant Full Disk
#   Access to the interpreter (/bin/bash) or to the Terminal/launchd context
#   running this script. Login-item enumeration triggers an Automation prompt
#   the first time. /Library/LaunchDaemons is only fully readable as root —
#   run the root LaunchDaemon variant (see README) to cover it.
# ------------------------------------------------------------------------------

set -u  # treat unset variables as errors (caught one real bug during dev)

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------

# Where the baseline snapshot lives. Override with WATCHPOST_STATE_DIR.
STATE_DIR="${WATCHPOST_STATE_DIR:-$HOME/.local/state/watchpost}"
BASELINE_FILE="$STATE_DIR/baseline.json"
# ARMED_FILE proves this machine was previously baselined. Without it, a missing
# baseline is indistinguishable from a first run — and v0.1.x treated it as one,
# so `rm baseline.json` made the next run silently absorb whatever persistence
# had just been planted. It also holds the HMAC key for the baseline.
ARMED_FILE="$STATE_DIR/.armed"

# Directories we treat as persistence surfaces. Each line: a label and a path.
# We use a parallel-array approach (bash 3.2 ships with macOS — no associative
# arrays guaranteed) so this runs on a stock Mac with no Homebrew bash.
PERSIST_LABELS=(
  "user-launchagents"
  "global-launchagents"
  "global-launchdaemons"
)
PERSIST_PATHS=(
  "$HOME/Library/LaunchAgents"
  "/Library/LaunchAgents"
  "/Library/LaunchDaemons"
)

# Flags (can be overridden by command-line args, see bottom of file):
#   --no-update : alert on diffs but do NOT promote current state to baseline
#                 (useful for dry-runs / repeated investigation of the same change)
#   --init      : just (re)write the baseline silently, no diffing, no alerts
UPDATE_BASELINE=1
INIT_ONLY=0

# ------------------------------------------------------------------------------
# Small helpers
# ------------------------------------------------------------------------------

log() {
  # Timestamped stderr log so cron/launchd output is readable.
  printf '[watchpost %s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2
}

# JSON-escape a string for safe inclusion in our hand-rolled JSON baseline.
# We avoid jq so the tool has ZERO dependencies. This handles the characters
# that actually appear in file paths / labels (backslash, quote, control chars).
json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"   # backslash first
  s="${s//\"/\\\"}"   # double quote
  s="${s//$'\t'/\\t}" # tab
  s="${s//$'\n'/\\n}" # newline
  s="${s//$'\r'/\\r}" # carriage return
  printf '%s' "$s"
}

# sha256 of a file. Uses shasum (always present on macOS). Empty on failure.
file_sha256() {
  shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'
}

# codesign verdict for a binary path: "apple", "signed", "adhoc",
# "unsigned", or "unknown". Used to annotate NEW persistence entries so an
# unsigned ProgramArguments target screams louder than a notarized one.
codesign_verdict() {
  local target="$1"
  [ -z "$target" ] && { printf 'unknown'; return; }
  [ ! -e "$target" ] && { printf 'missing'; return; }

  local out
  out="$(codesign -dv --verbose=4 "$target" 2>&1)"
  if [ $? -ne 0 ]; then
    # codesign exits non-zero for unsigned code
    if printf '%s' "$out" | grep -qi 'not signed'; then
      printf 'unsigned'
    else
      printf 'unknown'
    fi
    return
  fi

  if printf '%s' "$out" | grep -qi 'Authority=Apple'; then
    printf 'apple'
  elif printf '%s' "$out" | grep -qi 'adhoc'; then
    printf 'adhoc'
  else
    printf 'signed'
  fi
}

# Extract the first ProgramArguments entry (the executable) from a plist.
# Falls back to the Program key. Uses plutil (built in). Empty if neither.
plist_program() {
  local plist="$1"
  local prog

  # ProgramArguments is an array; element 0 is the executable.
  prog="$(plutil -extract 'ProgramArguments.0' raw -o - "$plist" 2>/dev/null)"
  if [ -n "$prog" ]; then
    printf '%s' "$prog"
    return
  fi
  # Some plists use the scalar Program key instead.
  prog="$(plutil -extract 'Program' raw -o - "$plist" 2>/dev/null)"
  printf '%s' "$prog"
}

# Fire a macOS notification banner. Best-effort: if osascript is unavailable
# (headless ssh with no GUI session) this silently no-ops and we rely on the
# stderr log / launchd log instead.
notify() {
  local title="$1"
  local message="$2"
  # Escape double quotes for the AppleScript string literals.
  local t="${title//\"/\\\"}"
  local m="${message//\"/\\\"}"
  osascript -e "display notification \"$m\" with title \"$t\" sound name \"Basso\"" 2>/dev/null || true
}

# ------------------------------------------------------------------------------
# State collection
# ------------------------------------------------------------------------------
#
# We collect the current persistence state into a flat, line-oriented form:
#
#   plist<TAB>LABEL<TAB>/absolute/path/to/file.plist<TAB>SHA256<TAB>PROGRAM
#   cron<TAB>user-crontab<TAB>LINE_HASH<TAB>-<TAB>raw_cron_line
#   login<TAB>login-items<TAB>NAME<TAB>-<TAB>-
#
# This intermediate form is easy to diff. We then render it to JSON for the
# persisted baseline (for human readability + week-over-week tooling).
# ------------------------------------------------------------------------------

collect_state() {
  local i label dir plist sha prog

  # --- LaunchAgents / LaunchDaemons directories ---
  i=0
  while [ $i -lt ${#PERSIST_PATHS[@]} ]; do
    label="${PERSIST_LABELS[$i]}"
    dir="${PERSIST_PATHS[$i]}"
    i=$((i + 1))

    [ -d "$dir" ] || continue

    # Only *.plist files. Use a glob; guard against the no-match literal.
    for plist in "$dir"/*.plist; do
      [ -e "$plist" ] || continue   # skip the literal "*.plist" if dir empty
      sha="$(file_sha256 "$plist")"
      prog="$(plist_program "$plist")"
      printf 'plist\t%s\t%s\t%s\t%s\n' "$label" "$plist" "$sha" "$prog"
    done
  done

  # --- User crontab ---
  # crontab -l returns non-zero / "no crontab" when empty; suppress noise.
  # We hash each non-comment, non-blank line so a new cron job is a new entry.
  while IFS= read -r line; do
    case "$line" in
      ''|'#'*) continue ;;  # skip blanks and comments
    esac
    local lhash
    lhash="$(printf '%s' "$line" | shasum -a 256 | awk '{print $1}')"
    printf 'cron\tuser-crontab\t%s\t-\t%s\n' "$lhash" "$line"
  done < <(crontab -l 2>/dev/null)

  # --- Login items (System Events / Automation) ---
  # This can trigger a TCC Automation prompt the first time. If denied,
  # osascript errors and we simply skip login items rather than failing.
  local login_items
  login_items="$(osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null)"
  if [ -n "$login_items" ]; then
    # AppleScript returns a comma-space separated list. Split it.
    local IFS_SAVE="$IFS"
    IFS=','
    for item in $login_items; do
      # Trim leading/trailing whitespace.
      item="${item#"${item%%[![:space:]]*}"}"
      item="${item%"${item##*[![:space:]]}"}"
      [ -z "$item" ] && continue
      printf 'login\tlogin-items\t%s\t-\t-\n' "$item"
    done
    IFS="$IFS_SAVE"
  fi
}

# ------------------------------------------------------------------------------
# Baseline persistence (state -> JSON and back)
# ------------------------------------------------------------------------------
#
# The baseline JSON is an array of objects, one per state line:
#   { "kind":"plist", "label":"...", "key":"...", "hash":"...", "extra":"..." }
# where for plists: key=path, hash=sha256, extra=program
#       for cron:   key=line-hash, hash="-", extra=raw line
#       for login:  key=name, hash="-", extra="-"
#
# We never use the JSON for diffing logic (we diff the flat text form). The JSON
# exists for humans and for any week-over-week tooling that wants structured
# data. Diff uses a normalized "identity" string per entry (see entry_identity).
# ------------------------------------------------------------------------------

# Convert one tab-delimited state line into a JSON object string.
line_to_json() {
  local line="$1"
  local kind label key hash extra
  IFS=$'\t' read -r kind label key hash extra <<<"$line"
  printf '  {"kind":"%s","label":"%s","key":"%s","hash":"%s","extra":"%s"}' \
    "$(json_escape "$kind")" \
    "$(json_escape "$label")" \
    "$(json_escape "$key")" \
    "$(json_escape "$hash")" \
    "$(json_escape "$extra")"
}

# Render a full state blob (the multi-line text) into a JSON array file.
# Integrity tagging.
#
# HONEST LIMITS, stated up front: the HMAC key lives in ARMED_FILE at mode 0600
# under the same user this tool runs as. An attacker already running as that
# user can read the key and forge a tag. This is NOT tamper-proofing against a
# determined local attacker; it is tamper-EVIDENCE against everything cheaper
# than that — a stealer that blindly rewrites or deletes the baseline, a
# half-finished cleanup, corruption. The tamper-proof variant is the root-owned
# daemon writing to /var/db/watchpost at 0600, which a user-level compromise
# cannot touch. Documented, not oversold.
baseline_key() {
  if [ ! -f "$ARMED_FILE" ]; then
    ( umask 077; head -c 32 /dev/urandom | shasum -a 256 | cut -d' ' -f1 > "$ARMED_FILE" )
    chmod 600 "$ARMED_FILE" 2>/dev/null || true
  fi
  cat "$ARMED_FILE"
}

baseline_tag() {
  # baseline_tag <file> -> HMAC-SHA256 of its contents
  openssl dgst -sha256 -hmac "$(baseline_key)" "$1" 2>/dev/null | awk '{print $NF}'
}

write_baseline() {
  local state="$1"
  local out="$2"
  mkdir -p "$(dirname "$out")"
  chmod 700 "$(dirname "$out")" 2>/dev/null || true

  {
    printf '{\n'
    printf '  "generated_at": "%s",\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')"
    printf '  "host": "%s",\n' "$(json_escape "$(scutil --get LocalHostName 2>/dev/null || hostname)")"
    printf '  "entries": [\n'
    local first=1
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      if [ $first -eq 1 ]; then
        first=0
      else
        printf ',\n'
      fi
      line_to_json "$line"
    done <<<"$state"
    printf '\n  ]\n'
    printf '}\n'
  } > "$out"

  # 0600, not the default 0644. This file enumerates every persistence entry on
  # the machine; it should not be world-readable.
  chmod 600 "$out" 2>/dev/null || true
  baseline_tag "$out" > "$out.tag" 2>/dev/null || true
  chmod 600 "$out.tag" 2>/dev/null || true
}

# Build a set of stable "identity" keys for the diff. Two runs are compared by
# these identity strings; anything present now but not in the baseline is NEW.
#
# Identity intentionally INCLUDES the plist hash, so a same-path/different-hash
# plist produces a DIFFERENT identity => shows up as "new" => we then detect it
# specifically as TAMPER by checking whether the path existed before.
entry_identity() {
  local line="$1"
  local kind label key hash extra
  IFS=$'\t' read -r kind label key hash extra <<<"$line"
  case "$kind" in
    plist) printf 'plist|%s|%s|%s' "$label" "$key" "$hash" ;;
    cron)  printf 'cron|%s' "$key" ;;     # key is already the line hash
    login) printf 'login|%s' "$key" ;;
    *)     printf 'other|%s' "$key" ;;
  esac
}

# The path-only identity (no hash) — used to decide NEW vs TAMPER for plists.
entry_path_key() {
  local line="$1"
  local kind label key hash extra
  IFS=$'\t' read -r kind label key hash extra <<<"$line"
  case "$kind" in
    plist) printf 'plist|%s|%s' "$label" "$key" ;;
    *)     entry_identity "$line" ;;
  esac
}

# Extract the stored baseline as the same flat text form, so we can compare
# apples to apples. We parse the JSON with a tolerant sed/awk pass (no jq).
# Because WE wrote the JSON with a known, simple shape, this is safe.
read_baseline_state() {
  local file="$1"
  [ -f "$file" ] || return 0
  # Pull each object's fields. Our objects are one-per-line in the array.
  # Match: {"kind":"X","label":"Y","key":"Z","hash":"H","extra":"E"}
  /usr/bin/sed -n 's/.*"kind":"\([^"]*\)","label":"\([^"]*\)","key":"\(.*\)","hash":"\([^"]*\)","extra":"\(.*\)"}.*/\1\t\2\t\3\t\4\t\5/p' "$file" \
    | while IFS=$'\t' read -r kind label key hash extra; do
        # Un-escape the minimal JSON escapes we introduced.
        unesc() {
          local v="$1"
          v="${v//\\\"/\"}"
          v="${v//\\t/$'\t'}"
          v="${v//\\n/$'\n'}"
          v="${v//\\r/$'\r'}"
          v="${v//\\\\/\\}"
          printf '%s' "$v"
        }
        printf '%s\t%s\t%s\t%s\t%s\n' \
          "$(unesc "$kind")" "$(unesc "$label")" "$(unesc "$key")" \
          "$(unesc "$hash")" "$(unesc "$extra")"
      done
}

# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------

main() {
  mkdir -p "$STATE_DIR"

  local current_state
  current_state="$(collect_state)"

  chmod 700 "$STATE_DIR" 2>/dev/null || true

  # A MISSING baseline on a machine that was previously armed is an ALERTABLE
  # EVENT, not a first run. Deleting the baseline is the cheapest way to blind
  # this tool, and treating it as a first run is exactly the behaviour an
  # attacker wants: the next run re-baselines and their persistence becomes
  # "normal". Refuse, loudly, unless the operator explicitly re-inits.
  if [ ! -f "$BASELINE_FILE" ] && [ -f "$ARMED_FILE" ] && [ "$INIT_ONLY" -eq 0 ]; then
    log "BASELINE MISSING on a machine that was previously armed: $BASELINE_FILE"
    log "This is not a first run. Something deleted the baseline."
    log "If this was you, re-arm deliberately:  $0 --init"
    notify "WatchPost: BASELINE MISSING" \
      "The persistence baseline was deleted. Refusing to silently re-baseline. Re-arm with --init."
    return 2
  fi

  # Tamper check on an existing baseline.
  if [ -f "$BASELINE_FILE" ] && [ -f "$BASELINE_FILE.tag" ] && [ "$INIT_ONLY" -eq 0 ]; then
    local want have
    want="$(cat "$BASELINE_FILE.tag" 2>/dev/null || true)"
    have="$(baseline_tag "$BASELINE_FILE")"
    if [ -n "$want" ] && [ -n "$have" ] && [ "$want" != "$have" ]; then
      log "BASELINE TAMPERED: integrity tag does not match $BASELINE_FILE"
      log "Someone edited the baseline directly — most likely to pre-seed an entry"
      log "so that a later malicious plant would diff as already-known."
      notify "WatchPost: BASELINE TAMPERED" \
        "The stored baseline was modified outside WatchPost. Treat persistence as unverified."
      return 2
    fi
  fi

  # First-ever run, or explicit --init: write baseline and exit quietly.
  if [ ! -f "$BASELINE_FILE" ] || [ "$INIT_ONLY" -eq 1 ]; then
    write_baseline "$current_state" "$BASELINE_FILE"
    log "Baseline written to $BASELINE_FILE ($(printf '%s\n' "$current_state" | grep -c . ) entries). No diffing on first run."
    notify "WatchPost armed" "Persistence baseline captured. You'll be alerted on changes."
    return 0
  fi

  # Load previous state.
  local baseline_state
  baseline_state="$(read_baseline_state "$BASELINE_FILE")"

  # Build a lookup of baseline identities and baseline path-keys.
  # We write them to temp files and use grep -F for O(1)-ish membership tests
  # without relying on bash 4 associative arrays.
  local tmp_base_id tmp_base_path
  tmp_base_id="$(mktemp -t watchpost.baseid)"
  tmp_base_path="$(mktemp -t watchpost.basepath)"
  # shellcheck disable=SC2064
  trap "rm -f '$tmp_base_id' '$tmp_base_path'" EXIT

  while IFS= read -r line; do
    [ -z "$line" ] && continue
    entry_identity "$line" >>"$tmp_base_id"
    printf '\n' >>"$tmp_base_id"
    entry_path_key "$line" >>"$tmp_base_path"
    printf '\n' >>"$tmp_base_path"
  done <<<"$baseline_state"

  # Walk current state; collect anything whose identity is NOT in the baseline.
  local new_lines=""
  local new_count=0
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    local id
    id="$(entry_identity "$line")"
    if ! grep -Fxq "$id" "$tmp_base_id"; then
      # This entry is new-or-changed. Determine NEW vs TAMPER for plists.
      local kind label key hash extra
      IFS=$'\t' read -r kind label key hash extra <<<"$line"

      local verdict="NEW"
      local sign=""
      if [ "$kind" = "plist" ]; then
        local pathkey
        pathkey="$(entry_path_key "$line")"
        if grep -Fxq "$pathkey" "$tmp_base_path"; then
          # Same path existed before but hash differs => content changed.
          verdict="TAMPER"
        fi
        # Annotate the executable's code-signing status.
        sign="$(codesign_verdict "$extra")"
      fi

      new_count=$((new_count + 1))
      case "$kind" in
        plist)
          new_lines+="  [$verdict/$sign] $label: $key"$'\n'
          new_lines+="      -> $extra"$'\n'
          ;;
        cron)
          new_lines+="  [NEW] crontab: $extra"$'\n'
          ;;
        login)
          new_lines+="  [NEW] login item: $key"$'\n'
          ;;
        *)
          new_lines+="  [NEW] $kind: $key"$'\n'
          ;;
      esac
    fi
  done <<<"$current_state"

  if [ "$new_count" -eq 0 ]; then
    log "No persistence changes detected."
    # Promote to baseline anyway (handles legitimate removals so they don't
    # keep re-appearing as 'gone'; removals are not alerted on by design —
    # an attacker ADDS persistence, that's our signal).
    [ "$UPDATE_BASELINE" -eq 1 ] && write_baseline "$current_state" "$BASELINE_FILE"
    return 0
  fi

  # We have changes. Build a concise notification + a fuller stderr report.
  log "DETECTED $new_count new/changed persistence entr$( [ "$new_count" -eq 1 ] && echo y || echo ies ):"
  printf '%s' "$new_lines" >&2

  # Notification body is length-limited by macOS; summarize.
  local summary
  summary="$new_count new persistence entr$( [ "$new_count" -eq 1 ] && echo y || echo ies ) detected. Check log / baseline."
  # Include the first changed item inline for at-a-glance context.
  local first_item
  first_item="$(printf '%s' "$new_lines" | head -n 1 | sed 's/^[[:space:]]*//')"
  notify "WatchPost: persistence change" "$summary
$first_item"

  # Promote current state to the new baseline so we alert once per change.
  if [ "$UPDATE_BASELINE" -eq 1 ]; then
    write_baseline "$current_state" "$BASELINE_FILE"
    log "Baseline updated. Future runs compare against the new state."
  else
    log "--no-update set: baseline NOT updated; this change will alert again next run."
  fi

  return 0
}

# ------------------------------------------------------------------------------
# Arg parsing
# ------------------------------------------------------------------------------

while [ $# -gt 0 ]; do
  case "$1" in
    --no-update) UPDATE_BASELINE=0 ;;
    --init)      INIT_ONLY=1 ;;
    -h|--help)
      cat <<'USAGE'
watchpost.sh — macOS persistence + login-item change monitor

Usage:
  watchpost.sh            Diff current persistence state vs baseline, alert on new
  watchpost.sh --init     (Re)write the baseline silently, no diffing/alerts
  watchpost.sh --no-update Alert on diffs but do NOT advance the baseline
  watchpost.sh --help     This help

Environment:
  WATCHPOST_STATE_DIR     Override baseline dir (default ~/.local/state/watchpost)

This is a periodic tripwire, NOT a real-time blocker. For real-time persistence
interdiction use Objective-See BlockBlock. See README.md.
USAGE
      exit 0
      ;;
    *)
      log "Unknown argument: $1 (use --help)"
      exit 2
      ;;
  esac
  shift
done

main
