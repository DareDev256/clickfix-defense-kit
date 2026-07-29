#!/usr/bin/env bash
#
# test-watchpost-baseline.sh — the baseline must not be blindable
# ==============================================================================
# WatchPost's entire value is "this persistence entry is NEW". That claim rests
# on the stored baseline, which lives in the user's own home directory — writable
# by exactly the malware this tool exists to catch.
#
# Three attacks, all of which worked before v0.2.0:
#   A. Edit the baseline to pre-seed the attacker's future entry, so the real
#      plant later diffs as already-known.
#   B. Delete the baseline. The next run said "No diffing on first run" and
#      silently absorbed whatever was planted.
#   C. Delete the kit's own LaunchAgents. WatchPost is silent on removals by
#      design, so its own disabling went unreported.
#
# Everything runs in a throwaway HOME + WATCHPOST_STATE_DIR. Nothing outside the
# temp dir is read or written, and no real LaunchAgent is touched.
# ==============================================================================

set -uo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")/.." >/dev/null 2>&1 && pwd -P)"
WP="$ROOT/watchpost/watchpost.sh"

if [ -t 1 ]; then
  R=$'\033[1;31m'; G=$'\033[1;32m'; X=$'\033[0m'
else
  R=''; G=''; X=''
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/watchpost-test.XXXXXX")"
cleanup() { [ -n "${TMP:-}" ] && [ -d "$TMP" ] && rm -rf -- "$TMP"; }
trap cleanup EXIT INT TERM

pass=0; fail=0; r=0
export WATCHPOST_STATE_DIR="$TMP/state"
export HOME="$TMP/home"
mkdir -p "$HOME/Library/LaunchAgents"

# Keep the test hermetic and quiet: no notifications, no host lookups.
export PATH="$TMP/bin:$PATH"
mkdir -p "$TMP/bin"
for stub in osascript crontab scutil systemextensionsctl profiles; do
  printf '#!/bin/sh\nexit 0\n' > "$TMP/bin/$stub"
  chmod +x "$TMP/bin/$stub"
done

run_wp() { bash "$WP" "$@" >"$TMP/out.txt" 2>&1; printf '%s' "$?"; }

check() {
  # check <name> <0|1 result>
  if [ "$2" -eq 1 ]; then
    printf '  %sok%s %s\n' "$G" "$X" "$1"
    pass=$((pass + 1))
  else
    printf '  %sx%s  %s\n' "$R" "$X" "$1"
    printf '      last output:\n'
    sed 's/^/        /' "$TMP/out.txt" | head -12
    fail=$((fail + 1))
  fi
}

printf 'WatchPost baseline integrity\n\n'

# --- arm ---------------------------------------------------------------------
run_wp --init >/dev/null
BASE="$WATCHPOST_STATE_DIR/baseline.json"
if [ -f "$BASE" ]; then r=1; else r=0; fi
check "arming writes a baseline" "$r"

MODE="$(stat -f '%Lp' "$BASE" 2>/dev/null || stat -c '%a' "$BASE" 2>/dev/null)"
if [ "$MODE" = "600" ]; then r=1; else r=0; fi
check "baseline is mode 0600, not world-readable" "$r"

if [ -f "$WATCHPOST_STATE_DIR/.armed" ]; then r=1; else r=0; fi
check "an 'armed' marker is written so a later deletion is detectable" "$r"

# --- A. pre-seed the baseline ------------------------------------------------
# Edit the stored baseline directly, as malware would, to plant its own future
# entry. The integrity tag must catch that the file changed outside WatchPost.
printf '{"generated_at":"now","host":"x","entries":[{"kind":"launchagent","path":"/tmp/evil.plist"}]}\n' > "$BASE"
rc="$(run_wp)"
if grep -q "TAMPERED" "$TMP/out.txt"; then r=1; else r=0; fi
check "A. editing the baseline directly is detected (was: silently trusted)" "$r"
if [ "$rc" != "0" ]; then r=1; else r=0; fi
check "A. tampered baseline exits non-zero" "$r"

# --- B. delete the baseline --------------------------------------------------
# The cheapest way to blind the tool. Must NOT be treated as a first run.
rm -f "$BASE" "$BASE.tag"
rc="$(run_wp)"
if grep -q "BASELINE MISSING" "$TMP/out.txt"; then r=1; else r=0; fi
check "B. deleting the baseline alerts (was: 'No diffing on first run')" "$r"
if [ "$rc" != "0" ]; then r=1; else r=0; fi
check "B. deletion exits non-zero" "$r"
if [ ! -f "$BASE" ]; then r=1; else r=0; fi
check "B. refuses to silently re-baseline after a deletion" "$r"

# --- explicit re-arm is still allowed ----------------------------------------
run_wp --init >/dev/null
if [ -f "$BASE" ]; then r=1; else r=0; fi
check "an explicit --init still re-arms deliberately" "$r"

# --- C. a genuinely new plant is still reported ------------------------------
# The whole point: after all the hardening, the tool must still do its job.
cat > "$HOME/Library/LaunchAgents/com.evil.helper.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>Label</key><string>com.evil.helper</string>
  <key>ProgramArguments</key><array><string>/tmp/helper</string></array>
  <key>RunAtLoad</key><true/>
</dict></plist>
PLIST
run_wp --no-update >/dev/null
if grep -q "com.evil.helper" "$TMP/out.txt"; then r=1; else r=0; fi
check "C. a newly planted LaunchAgent is still reported" "$r"

printf '\n'
if [ "$fail" -eq 0 ]; then
  printf '%s%d/%d%s baseline integrity checks pass.\n' "$G" "$pass" "$pass" "$X"
  exit 0
fi
printf '%s%d/%d%s pass — %d FAILED.\n' "$R" "$pass" "$((pass + fail))" "$X" "$fail"
exit 1
