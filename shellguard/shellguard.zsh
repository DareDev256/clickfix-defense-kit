# shellguard.zsh — ClickFix Defense Kit
# -----------------------------------------------------------------------------
# A zsh ZLE accept-line guard that intercepts dangerous "download-and-execute" /
# "decode-and-execute" commands BEFORE they run, prints a plain-language warning
# explaining what the command does, and requires confirmation before executing.
#
# WHY accept-line (and not preexec):
#   A ZLE widget that wraps `accept-line` can refuse to run a command simply by
#   NOT calling the builtin accept-line. preexec fires too late to cleanly abort
#   and cannot reliably read a typed confirmation from /dev/tty because ZLE still
#   owns the keyboard at that point. The accept-line layer is the load-bearing,
#   authoritative interception point.
#
# THREAT MODEL — "ClickFix" / FakeCAPTCHA:
#   A malicious page silently copies a shell command to the clipboard and tells
#   the victim to open Terminal, paste, and hit Enter "to verify you are human".
#   Gatekeeper/notarization/XProtect do NOT stop a pasted command (no quarantine
#   xattr, no file-launch event). The only thing standing between the victim and
#   a stealer is the human not hitting Enter on autopilot. This guard breaks the
#   autopilot at the exact execute moment.
#
# WHAT CHANGED IN v0.1.1:
#   Detection no longer lives in this file. It lives in
#   ../lib/clickfix-grammar.zsh, shared with ClipSentinel so the two layers
#   cannot drift apart. v0.1.0's regex-over-raw-string approach silently passed
#   9 of 13 realistic ClickFix payloads — see ../tests/corpus.tsv, which now
#   asserts every one of them, and SECURITY.md for the full write-up.
#
# DEFENSIVE USE ONLY. This tool does not exfiltrate, log values, or phone home.
# -----------------------------------------------------------------------------

# Guard against double-sourcing.
[[ -n ${_CLICKFIX_GUARD_LOADED:-} ]] && return 0
typeset -g _CLICKFIX_GUARD_LOADED=1

# ---------------------------------------------------------------------------
# Load the shared grammar
# ---------------------------------------------------------------------------
# %x is the file currently being sourced, which is what we need here — $0 is
# not reliable for a sourced file.
typeset -g _CLICKFIX_GUARD_DIR=${${(%):-%x}:A:h}
typeset -g _CLICKFIX_GRAMMAR_PATH=${CLICKFIX_GRAMMAR_PATH:-${_CLICKFIX_GUARD_DIR:h}/lib/clickfix-grammar.zsh}

# Fail LOUDLY. A guard that silently does nothing is worse than no guard,
# because the user believes they are protected.
if [[ ! -r $_CLICKFIX_GRAMMAR_PATH ]]; then
  print -u2 -- "[shellguard] FATAL: cannot read ${_CLICKFIX_GRAMMAR_PATH}"
  print -u2 -- "[shellguard] THE GUARD IS NOT ACTIVE. Re-clone the kit, or set CLICKFIX_GRAMMAR_PATH."
  return 1
fi
source "$_CLICKFIX_GRAMMAR_PATH" || {
  print -u2 -- "[shellguard] FATAL: grammar failed to load — THE GUARD IS NOT ACTIVE."
  return 1
}

# ---------------------------------------------------------------------------
# Configuration (override in ~/.zshrc AFTER sourcing this file)
# ---------------------------------------------------------------------------

# The exact phrase required to allow a `block`-tier command through. A full
# phrase (not y/N) is intentional: a single keypress is too easy to
# muscle-memory through, and defeating that autopilot is the whole point.
: ${CLICKFIX_GUARD_PHRASE:=I-UNDERSTAND}

# Set CLICKFIX_GUARD=0 to disable the guard entirely (scripted sessions).
: ${CLICKFIX_GUARD:=1}

# Trusted-installer allowlists live in the shared grammar as
# CLICKFIX_ALLOW_HOSTS and CLICKFIX_ALLOW_URL_PREFIXES. Extend them in ~/.zshrc
# AFTER sourcing this file, e.g.:
#   CLICKFIX_ALLOW_HOSTS+=( my.internal.ci )
#   CLICKFIX_ALLOW_URL_PREFIXES+=( raw.githubusercontent.com/my-org/ )
# Prefer the URL-prefix form for ANY host the public can publish to. Adding a
# multi-tenant host to CLICKFIX_ALLOW_HOSTS tells an attacker where to stage a
# payload that this guard will wave through — that was CVE-shaped bug #1 in
# v0.1.0 and it is worth not reintroducing locally.

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

# _clickfix_banner <tier>
# Everything goes to /dev/tty: inside a ZLE widget the line editor owns the
# terminal, so ordinary stdout is not reliable.
_clickfix_banner() {
  emulate -L zsh
  local tier=$1
  local shown

  # The buffer is attacker-controlled. Never print it raw — a payload can emit
  # ANSI to scroll this warning off screen or paint a fake confirmation line
  # into our own banner.
  shown=$(clickfix_sanitize_for_display "$BUFFER" 12)

  {
    if [[ $tier == block ]]; then
      printf '\n\033[1;41;97m  ClickFix / download-and-execute guard  \033[0m\n'
      printf '\033[1;31mThis command can run code from the internet on your Mac:\033[0m\n\n'
    else
      printf '\n\033[1;43;30m  ClickFix guard — heads up  \033[0m\n'
      printf '\033[1;33mThis command has the shape of a download-and-execute attack:\033[0m\n\n'
    fi
    printf '\033[0;33m    %s\033[0m\n\n' "$shown"
    printf '\033[1mWhat it does:\033[0m\n'
    local r
    for r in "${CLICKFIX_REASONS[@]}"; do
      printf '    \xE2\x80\xA2 %s\n' "$r"
    done
    printf '\n\033[2mIf a website, CAPTCHA, video player, or AI answer told you to paste\n'
    printf 'this, it is almost certainly an attack. Legit installers rarely need\n'
    printf 'you to pipe a download straight into a shell.\033[0m\n\n'
  } > /dev/tty
}

# ---------------------------------------------------------------------------
# Reading the confirmation
# ---------------------------------------------------------------------------
# _clickfix_read_reply <prompt>
# Read a typed line from the terminal from INSIDE a ZLE widget, into $REPLY.
#
# This is subtler than it looks and v0.1.0 got it wrong. While a ZLE widget is
# running, the line editor holds the terminal in raw mode with echo disabled.
# A bare `read -r < /dev/tty` therefore (a) shows the user nothing as they
# type, and (b) never returns, because in raw mode the Enter key sends CR and
# `read` only terminates on LF. The confirmation gate — the entire point of the
# block tier — could not actually be completed.
#
# So we save the terminal state, restore canonical line-buffered mode with echo
# for the duration of the read, and put it back exactly as it was afterwards.
# The restore runs on every path, including when the user hits Ctrl-C.
_clickfix_read_reply() {
  emulate -L zsh
  local prompt=$1
  REPLY=''

  # Preferred path: zsh's own minibuffer reader. It is written for use inside a
  # widget, so it drives ZLE's input loop rather than fighting it, and it gets
  # echo and line-editing right without touching the terminal mode at all.
  if autoload -Uz read-from-minibuffer 2>/dev/null && \
     whence -w read-from-minibuffer >/dev/null 2>&1; then
    read-from-minibuffer "$prompt" 2>/dev/null && { REPLY=${REPLY%$'\r'}; return 0 }
  fi

  # Fallback for a non-ZLE context (or a zsh without the function): restore a
  # canonical, echoing terminal for the duration of the read, then put it back
  # exactly as it was. `stty sane` rather than individual flags — setting
  # icanon/echo/icrnl piecemeal was observed NOT to enable CR->NL translation,
  # so Enter never terminated the read and the gate could not be completed.
  local saved=''
  saved=$(stty -g < /dev/tty 2>/dev/null)
  stty sane < /dev/tty 2>/dev/null
  {
    printf '%s' "$prompt" > /dev/tty
    IFS= read -r REPLY < /dev/tty
  } always {
    [[ -n $saved ]] && stty "$saved" < /dev/tty 2>/dev/null
  }
  REPLY=${REPLY%$'\r'}
  return 0
}

# ---------------------------------------------------------------------------
# The guard widget
# ---------------------------------------------------------------------------

_clickfix_guard() {
  emulate -L zsh
  setopt local_options no_unset

  # Escape hatch: env-disabled → behave like the normal accept-line.
  if [[ ${CLICKFIX_GUARD:-1} == 0 ]]; then
    _clickfix_call_original
    return
  fi

  local buf=$BUFFER
  if [[ -z ${buf//[[:space:]]/} ]]; then
    _clickfix_call_original
    return
  fi

  clickfix_check "$buf"

  if [[ $CLICKFIX_VERDICT == silent ]]; then
    _clickfix_call_original
    return
  fi

  zle -M ""   # clear any ZLE status line
  _clickfix_banner "$CLICKFIX_VERDICT"

  local answer=''

  if [[ $CLICKFIX_VERDICT == warn ]]; then
    # 'warn' tier: one Enter proceeds. These rules (two-step download,
    # look-alike characters, disk-image mounts) have real false-positive rates.
    # Demanding the full phrase here would train the user to type it
    # reflexively, which would hollow out the 'block' tier as well.
    _clickfix_read_reply 'Press \033[1mEnter\033[0m to run it, or type \033[1manything\033[0m then Enter to abort: '
    answer=$REPLY
    if [[ -z $answer ]]; then
      printf '\033[2m[shellguard] proceeding.\033[0m\n' > /dev/tty
      _clickfix_call_original
      return
    fi
  else
    printf 'To RUN it anyway, type exactly: \033[1;32m%s\033[0m\n' "$CLICKFIX_GUARD_PHRASE" > /dev/tty
    _clickfix_read_reply 'Anything else (or Enter) aborts: '
    answer=$REPLY
    if [[ $answer == "$CLICKFIX_GUARD_PHRASE" ]]; then
      printf '\033[2m[shellguard] confirmed — running.\033[0m\n' > /dev/tty
      _clickfix_call_original
      return
    fi
  fi

  # Aborted: wipe the buffer and redraw a clean prompt.
  printf '\033[1;32m[shellguard] aborted. Nothing was run.\033[0m\n' > /dev/tty
  BUFFER=''
  zle reset-prompt
  return 0
}

# _clickfix_call_original
# Invoke the previously-bound accept-line widget if we captured one, otherwise
# fall back to the builtin. This keeps zsh-autosuggestions and
# zsh-syntax-highlighting working instead of clobbering their wrappers.
_clickfix_call_original() {
  if [[ -n ${_clickfix_orig_accept_line:-} ]] \
     && [[ ${_clickfix_orig_accept_line} != _clickfix_guard ]] \
     && zle -l | grep -qx -- "${_clickfix_orig_accept_line}"; then
    zle "${_clickfix_orig_accept_line}"
  else
    zle .accept-line
  fi
}

# ---------------------------------------------------------------------------
# Warn at PASTE time too (earlier than Enter).
# When zsh bracketed-paste is active, a multiline ClickFix payload lands in
# $BUFFER literally (it will NOT auto-execute — good). We additionally scan the
# just-pasted region so the user sees a heads-up the moment they paste. This is
# advisory only; the authoritative block is at accept-line.
# ---------------------------------------------------------------------------
_clickfix_bracketed_paste() {
  emulate -L zsh
  if [[ -n ${_clickfix_orig_bracketed_paste:-} ]] \
     && zle -l | grep -qx -- "${_clickfix_orig_bracketed_paste}"; then
    zle "${_clickfix_orig_bracketed_paste}"
  else
    zle .bracketed-paste
  fi

  [[ ${CLICKFIX_GUARD:-1} == 0 ]] && return 0

  local pasted=''
  if [[ -n ${YANK_START:-} && -n ${YANK_END:-} ]]; then
    pasted=${BUFFER[$((YANK_START + 1)),$YANK_END]}
  else
    pasted=$BUFFER
  fi

  [[ -z $pasted ]] && return 0
  clickfix_check "$pasted"
  if [[ $CLICKFIX_VERDICT != silent ]]; then
    zle -M "shellguard: pasted text looks like a download-and-execute command — review it before pressing Enter."
  fi
}

# ---------------------------------------------------------------------------
# Wire up the widgets (idempotent; safe to re-source).
# ---------------------------------------------------------------------------
() {
  emulate -L zsh

  # Capture the currently-bound accept-line widget so we can chain to it,
  # but only if it isn't already our own guard (avoid recursive self-binding).
  local current_accept
  current_accept=$(zle -l -L accept-line 2>/dev/null | awk '{print $NF}')
  if [[ -n $current_accept && $current_accept != _clickfix_guard && $current_accept != accept-line ]]; then
    typeset -g _clickfix_orig_accept_line=$current_accept
  fi

  local current_bp
  current_bp=$(zle -l -L bracketed-paste 2>/dev/null | awk '{print $NF}')
  if [[ -n $current_bp && $current_bp != _clickfix_bracketed_paste && $current_bp != bracketed-paste ]]; then
    typeset -g _clickfix_orig_bracketed_paste=$current_bp
  fi

  zle -N accept-line _clickfix_guard
  zle -N bracketed-paste _clickfix_bracketed_paste
}
