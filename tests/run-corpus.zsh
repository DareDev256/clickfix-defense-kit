#!/bin/zsh
# run-corpus.zsh — assert the shared grammar against tests/corpus.tsv
# ---------------------------------------------------------------------------
# Runs every corpus row through lib/clickfix-grammar.zsh and asserts the
# verdict matches. Exits non-zero with a per-row diff on any mismatch.
#
# This executes NOTHING from the corpus. Each command string is passed to
# clickfix_check as data and never reaches a shell.
#
# Usage: tests/run-corpus.zsh [--verbose]
# ---------------------------------------------------------------------------

emulate -L zsh
setopt local_options no_glob no_nomatch pipe_fail

typeset -r ROOT=${0:A:h:h}
typeset -r CORPUS=$ROOT/tests/corpus.tsv
typeset -r GRAMMAR=$ROOT/lib/clickfix-grammar.zsh

typeset VERBOSE=0
[[ ${1:-} == (-v|--verbose) ]] && VERBOSE=1

typeset RED=$'\033[1;31m' GRN=$'\033[1;32m' YEL=$'\033[1;33m' DIM=$'\033[2m' RST=$'\033[0m'
[[ -t 1 ]] || { RED=''; GRN=''; YEL=''; DIM=''; RST='' }

if [[ ! -r $GRAMMAR ]]; then
  print -u2 -- "${RED}FATAL${RST}: cannot read $GRAMMAR"
  exit 2
fi
if [[ ! -r $CORPUS ]]; then
  print -u2 -- "${RED}FATAL${RST}: cannot read $CORPUS"
  exit 2
fi

source "$GRAMMAR"

typeset -i pass=0 fail=0 lineno=0
typeset -a failures

while IFS= read -r line || [[ -n $line ]]; do
  (( lineno++ ))
  [[ -z ${line//[[:space:]]/} ]] && continue
  [[ ${line[1]} == '#' ]] && continue

  typeset expected=${line%%$'\t'*}
  typeset cmd=${line#*$'\t'}

  if [[ $expected == $line || -z $cmd ]]; then
    print -u2 -- "${YEL}SKIP${RST} line $lineno: no TAB separator"
    continue
  fi
  if [[ $expected != (block|warn|silent) ]]; then
    print -u2 -- "${RED}FATAL${RST} line $lineno: bad verdict '$expected'"
    exit 2
  fi

  clickfix_check "$cmd"
  typeset got=$CLICKFIX_VERDICT

  if [[ $got == $expected ]]; then
    (( pass++ ))
    (( VERBOSE )) && print -r -- "${GRN}ok${RST}   ${DIM}${expected}${RST}  $cmd"
  else
    (( fail++ ))
    failures+=( "line $lineno: expected ${expected}, got ${got}"$'\n'"    $cmd" )
  fi
done < "$CORPUS"

# ---------------------------------------------------------------------------
# DRIFT ASSERTION
# ---------------------------------------------------------------------------
# The corpus proves the grammar is correct. This proves both tools actually USE
# it. v0.1.0's README claimed ClipSentinel was "kept in lockstep with
# ShellGuard's grammar" while the two silently disagreed on 6 of 13 payloads,
# because each file carried its own copy. A private host list or a private
# detection regex reappearing in either tool is the exact defect that caused
# that, so it fails the build.
typeset -i drift=0
typeset t
for t in shellguard/shellguard.zsh clipsentinel/clipsentinel.sh; do
  typeset f=$ROOT/$t
  [[ -r $f ]] || continue
  if ! grep -q 'clickfix-grammar.zsh' "$f"; then
    print -u2 -- "${RED}DRIFT${RST}: $t does not source lib/clickfix-grammar.zsh"
    (( drift++ ))
  fi
  if grep -qE '^[^#]*(sh\.rustup\.rs|raw\.githubusercontent\.com|get\.docker\.com)' "$f"; then
    print -u2 -- "${RED}DRIFT${RST}: $t carries its own host allowlist — trust data belongs only in lib/"
    (( drift++ ))
  fi
  if grep -qE "^[^#]*(curl\|wget\|fetch)\)?\[\^" "$f"; then
    print -u2 -- "${RED}DRIFT${RST}: $t carries its own detection regex"
    (( drift++ ))
  fi
done

print -r -- ""
if (( fail == 0 && drift == 0 )); then
  print -r -- "${GRN}${pass}/${pass}${RST} corpus rows pass; both tools share one grammar."
  exit 0
fi
if (( fail == 0 )); then
  print -r -- "${RED}${drift} drift check(s) FAILED${RST} (corpus itself is green: ${pass}/${pass})."
  exit 1
fi

print -r -- "${RED}FAILURES (${fail}):${RST}"
typeset f
for f in "${failures[@]}"; do
  print -r -- "  ${RED}x${RST} $f"
done
print -r -- ""
print -r -- "${RED}$((pass))/$((pass + fail))${RST} corpus rows pass — ${fail} FAILED."
exit 1
