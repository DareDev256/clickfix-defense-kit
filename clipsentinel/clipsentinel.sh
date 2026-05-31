#!/bin/zsh
# ==============================================================================
# clipsentinel.sh — macOS clipboard watchdog for the ClickFix Defense Kit
# ==============================================================================
#
# WHY THIS EXISTS
#   ClickFix / FakeCAPTCHA attacks work by SILENTLY copying a malicious shell
#   command to your clipboard, then telling you (via a fake "verify you are
#   human" page) to open Terminal and paste it. The dangerous moment is the
#   PASTE. This watcher fires the *earliest possible* warning: the instant the
#   dangerous text is COPIED, before it ever reaches a terminal.
#
#   It is a COMPANION to ShellGuard (the zsh accept-line guard). ShellGuard does
#   the authoritative blocking at EXECUTE time. ClipSentinel is advisory only —
#   a clipboard watcher physically cannot stop a paste (there is no macOS API
#   for that). It warns; it does not block. Treat it as a smoke alarm, not a
#   sprinkler.
#
# HOW IT WORKS
#   Polls `pbpaste` once per second. Hashes the current clipboard text and
#   compares to the last-seen hash, so we only inspect on a genuine *change*
#   (the same cheap "changeCount-style" discipline, done in pure shell). When
#   newly-copied text matches the ClickFix shell grammar, it raises a macOS
#   notification (and optionally a modal dialog) via osascript.
#
#   CPU cost is negligible: one pbpaste + one sha on a short string per second.
#
# NO EXTERNAL DEPENDENCIES — uses only pbpaste, shasum/md5, and osascript, all
# shipped with macOS.
#
# CONFIG (environment variables, all optional)
#   CLIPSENTINEL_INTERVAL   poll interval in seconds (default 1)
#   CLIPSENTINEL_DIALOG     "1" to also raise a blocking modal dialog (default 0,
#                           notification only — less intrusive)
#   CLIPSENTINEL_LOG        path to an append-only event log (default: none)
#   CLIPSENTINEL_DISABLE    "1" to make this script exit immediately (kill switch)
#
# DEFENSIVE-USE ONLY. This tool detects and warns about download-and-execute
# patterns so a human is not tricked into running them. It does not run, store,
# or transmit clipboard contents anywhere.
# ==============================================================================

emulate -L zsh
setopt no_unset pipe_fail

# ---- Kill switch -------------------------------------------------------------
if [[ "${CLIPSENTINEL_DISABLE:-0}" == "1" ]]; then
  print -r -- "[clipsentinel] CLIPSENTINEL_DISABLE=1 — exiting." >&2
  exit 0
fi

# ---- Tunables ----------------------------------------------------------------
typeset -i INTERVAL=${CLIPSENTINEL_INTERVAL:-1}
(( INTERVAL < 1 )) && INTERVAL=1
typeset DIALOG="${CLIPSENTINEL_DIALOG:-0}"
typeset LOGFILE="${CLIPSENTINEL_LOG:-}"

# ---- Required tools ----------------------------------------------------------
# pbpaste and osascript are mandatory and ship with macOS. Fail loudly if not
# on macOS (e.g. someone ran this on Linux by mistake).
if ! command -v pbpaste >/dev/null 2>&1; then
  print -r -- "[clipsentinel] FATAL: pbpaste not found — this tool is macOS-only." >&2
  exit 1
fi
if ! command -v osascript >/dev/null 2>&1; then
  print -r -- "[clipsentinel] FATAL: osascript not found — this tool is macOS-only." >&2
  exit 1
fi

# Pick whatever hashing tool exists. We only need change-detection, not
# cryptographic strength, so md5 is fine as a fallback.
if command -v shasum >/dev/null 2>&1; then
  _hash() { shasum -a 256 | cut -d' ' -f1; }
elif command -v md5 >/dev/null 2>&1; then
  _hash() { md5 -q; }
else
  _hash() { cksum | cut -d' ' -f1; }
fi

# ==============================================================================
# DANGEROUS-PATTERN MATCHER
#
# Kept deliberately in lockstep with ShellGuard's grammar so the two layers
# agree on what "dangerous" means. We match the *kill chain*, not the mere
# presence of curl — matching bare `curl` would train users to ignore the
# warning. We require:
#   - download piped INTO an interpreter        (curl|wget|fetch ... | sh/bash/...)
#   - eval/exec of a command substitution        (eval $(curl ...))
#   - base64 decode piped into an interpreter     (base64 -d ... | sh)
#   - a long base64 blob piped into base64        (echo <blob> | base64 -d ...)
#   - bash /dev/tcp reverse-shell redirects
#   - osascript piped into a shell
#
# ALLOWLIST: well-known legitimate installers (rustup, Homebrew, nvm, oh-my-zsh,
# Docker, Deno, Bun, get.docker.com, etc.) are suppressed. False positives are
# the #1 reason users disable a guard, so we err toward not crying wolf on the
# canonical install one-liners. The allowlist is host-based and intentionally
# narrow.
# ==============================================================================

# Trusted install hostnames. If a download-pipe references ONLY these hosts,
# we stay quiet. (Tighten or extend to taste — but keep it short.)
typeset -a ALLOWLIST_HOSTS
ALLOWLIST_HOSTS=(
  'sh.rustup.rs'
  'static.rust-lang.org'
  'get.docker.com'
  'raw.githubusercontent.com/ohmyzsh'   # oh-my-zsh installer
  'raw.githubusercontent.com/Homebrew'  # Homebrew installer
  'raw.githubusercontent.com/nvm-sh'    # nvm installer
  'deno.land'
  'bun.sh'
  'install.sh'                           # generic local installer path token
)

# Returns 0 (true) if the text matches the dangerous ClickFix shell grammar.
_is_dangerous() {
  local buf="$1"

  # Regex pieces (POSIX ERE via zsh =~). Mirror of ShellGuard.
  local re='(curl|wget|fetch)[^|;]*(\|[[:space:]]*(sudo[[:space:]]+)?(sh|bash|zsh|python[0-9.]*|perl|ruby|node|osascript))'
  re+='|(eval|exec)[[:space:]]+["'"'"']?\$\((curl|wget|fetch)'
  re+='|base64[[:space:]]+(--?d(ecode)?|-D)[^|]*\|[[:space:]]*(sh|bash|zsh|python[0-9.]*|perl|ruby)'
  re+='|(echo|printf)[[:space:]]+[A-Za-z0-9+/=]{40,}[^|]*\|[[:space:]]*base64'
  re+='|/dev/(tcp|udp)/'
  re+='|osascript[^|]*\|[[:space:]]*(sh|bash|zsh)'

  if [[ "$buf" =~ $re ]]; then
    return 0
  fi
  return 1
}

# Returns 0 (true) if EVERY URL/host reference in the buffer is on the
# allowlist — i.e. this looks like a known-good installer and we should stay
# quiet. If there is any off-allowlist host, we do NOT suppress.
_is_allowlisted() {
  local buf="$1"
  local h matched=0 hit
  for h in "${ALLOWLIST_HOSTS[@]}"; do
    if [[ "$buf" == *"$h"* ]]; then
      matched=1
      break
    fi
  done
  (( matched == 1 )) && return 0
  return 1
}

# ==============================================================================
# NOTIFY
#
# Two surfaces:
#   1. Always: a macOS notification banner with a distinct alarming sound
#      (Basso) so the warning is felt, not just seen.
#   2. Optional (CLIPSENTINEL_DIALOG=1): a modal "display dialog" that the user
#      must dismiss. More intrusive; off by default to avoid alert fatigue.
#
# We pass the clipboard text to osascript via argv ("$1" of the AppleScript),
# NOT by interpolating it into the script source — that avoids AppleScript
# string-injection from crafted clipboard content. We also show only a short,
# clearly-truncated preview.
# ==============================================================================
_notify() {
  local preview="$1"

  # Truncate to a short, safe preview (single line, max ~120 chars).
  preview="${preview//$'\n'/ }"
  preview="${preview//$'\r'/ }"
  if (( ${#preview} > 120 )); then
    preview="${preview[1,117]}..."
  fi

  # Notification banner. `with title`/`subtitle` are static strings we control;
  # the untrusted clipboard preview is passed as a parameter (item 1 of argv)
  # and concatenated INSIDE AppleScript, so shell/AppleScript metacharacters in
  # the clipboard cannot break out.
  /usr/bin/osascript \
    - "$preview" <<'APPLESCRIPT' >/dev/null 2>&1
on run argv
  set thePreview to item 1 of argv
  display notification ("Do NOT paste into Terminal: " & thePreview) ¬
    with title "⚠️ ClipSentinel: dangerous shell command copied" ¬
    subtitle "ClickFix attack pattern detected on your clipboard" ¬
    sound name "Basso"
end run
APPLESCRIPT

  # Optional blocking modal.
  if [[ "$DIALOG" == "1" ]]; then
    /usr/bin/osascript \
      - "$preview" <<'APPLESCRIPT' >/dev/null 2>&1
on run argv
  set thePreview to item 1 of argv
  display dialog ("A download-and-execute command was just copied to your clipboard:" & return & return & thePreview & return & return & "This is the signature of a ClickFix / FakeCAPTCHA scam. Do NOT paste it into Terminal unless you typed it yourself and trust the source.") ¬
    with title "⚠️ ClipSentinel — possible ClickFix attack" ¬
    with icon caution ¬
    buttons {"I understand"} default button "I understand"
end run
APPLESCRIPT
  fi
}

# Append an event to the log if a logfile is configured. We log the PREVIEW
# only (truncated), with a timestamp — never the full payload, never anywhere
# off-machine.
_log_event() {
  [[ -z "$LOGFILE" ]] && return 0
  local preview="$1"
  preview="${preview//$'\n'/ }"
  (( ${#preview} > 120 )) && preview="${preview[1,117]}..."
  print -r -- "$(date '+%Y-%m-%dT%H:%M:%S%z')  DANGEROUS_COPY  ${preview}" >> "$LOGFILE" 2>/dev/null || true
}

# ==============================================================================
# MAIN LOOP
# ==============================================================================
print -r -- "[clipsentinel] watching clipboard (interval=${INTERVAL}s, dialog=${DIALOG}). Ctrl-C to stop." >&2

typeset last_hash=""
typeset cur cur_hash

# Seed last_hash with whatever is already on the clipboard at startup, WITHOUT
# alerting — we only want to fire on NEW copies after we start, not on whatever
# was there before.
cur="$(pbpaste 2>/dev/null || true)"
last_hash="$(print -r -- "$cur" | _hash)"

while true; do
  # Re-check the kill switch each loop so it can be toggled live via env on a
  # respawn (and so a future control file could flip it).
  if [[ "${CLIPSENTINEL_DISABLE:-0}" == "1" ]]; then
    print -r -- "[clipsentinel] CLIPSENTINEL_DISABLE=1 — exiting." >&2
    exit 0
  fi

  cur="$(pbpaste 2>/dev/null || true)"
  cur_hash="$(print -r -- "$cur" | _hash)"

  # Only inspect on an actual clipboard CHANGE. This is the cheap path: most
  # loop iterations do nothing beyond a hash comparison.
  if [[ "$cur_hash" != "$last_hash" ]]; then
    last_hash="$cur_hash"

    if [[ -n "$cur" ]] && _is_dangerous "$cur"; then
      if _is_allowlisted "$cur"; then
        # Known-good installer one-liner — stay quiet (but note it on the log
        # so a curious user can audit suppressions).
        [[ -n "$LOGFILE" ]] && print -r -- "$(date '+%Y-%m-%dT%H:%M:%S%z')  ALLOWLISTED_COPY  (suppressed)" >> "$LOGFILE" 2>/dev/null || true
      else
        _notify "$cur"
        _log_event "$cur"
      fi
    fi
  fi

  sleep "$INTERVAL"
done
