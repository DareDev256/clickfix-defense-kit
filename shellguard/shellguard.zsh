# shellguard.zsh — ClickFix Defense Kit
# -----------------------------------------------------------------------------
# A zsh ZLE accept-line guard that intercepts dangerous "download-and-execute" /
# "decode-and-execute" commands BEFORE they run, prints a plain-language warning
# explaining what the command does, and forces the user to type a confirmation
# phrase (read from /dev/tty) before it will execute. Otherwise it aborts.
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
#   The payload is usually a curl|sh, an eval $(curl ...), or a base64 -d | sh.
#   Gatekeeper/notarization/XProtect do NOT stop a pasted command (no quarantine
#   xattr, no file-launch event). The only thing standing between the victim and
#   a stealer is the human not hitting Enter on autopilot. This guard breaks the
#   autopilot by demanding a TYPED phrase at the exact execute moment.
#
# DEFENSIVE USE ONLY. This tool does not exfiltrate, log values, or phone home.
# -----------------------------------------------------------------------------

# Guard against double-sourcing.
[[ -n ${_CLICKFIX_GUARD_LOADED:-} ]] && return 0
typeset -g _CLICKFIX_GUARD_LOADED=1

# ---------------------------------------------------------------------------
# Configuration (override in ~/.zshrc AFTER sourcing this file)
# ---------------------------------------------------------------------------

# The exact phrase the user must type to allow a flagged command through.
# A full word/phrase (not y/N) is intentional: a single keypress is too easy to
# muscle-memory through, and defeating that autopilot is the whole point.
: ${CLICKFIX_GUARD_PHRASE:=I-UNDERSTAND}

# Set CLICKFIX_GUARD=0 in the environment to disable the guard entirely
# (useful for non-interactive/scripted sessions or trusted automation).
: ${CLICKFIX_GUARD:=1}

# Space-separated allowlist of trusted hostnames. If a flagged command's only
# download URL points at one of these well-known installer hosts, the guard
# stays quiet — prompting on legit `rustup`/`brew`/`nvm` installers is the #1
# way users get annoyed and disable the guard, which trains them to ignore it.
# Override/extend in ~/.zshrc, e.g.:
#   CLICKFIX_GUARD_ALLOW_HOSTS+=( my.internal.ci )
typeset -ga CLICKFIX_GUARD_ALLOW_HOSTS
: ${CLICKFIX_GUARD_ALLOW_HOSTS:=}
if (( ${#CLICKFIX_GUARD_ALLOW_HOSTS} == 0 )); then
  CLICKFIX_GUARD_ALLOW_HOSTS=(
    sh.rustup.rs
    static.rust-lang.org
    get.docker.com
    raw.githubusercontent.com   # ohmyzsh, nvm, etc. — see note below
    raw.github.com
    install.python-poetry.org
    get.pnpm.io
    deb.nodesource.com
    brew.sh
    bun.sh
    sdkman.io
    get.sdkman.io
  )
fi

# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------
# The regexes are deliberately TIGHT: they require the dangerous SHAPE
# (pipe-to-interpreter, eval/exec of a command substitution, decode-then-pipe),
# NOT the mere presence of `curl`. `curl https://example.com` on its own is fine
# and must NOT prompt — over-prompting trains users to ignore the guard.
#
# zsh regex note: we use `[[ $buf =~ $re ]]` which uses ERE (extended regex)
# on macOS/zsh. We keep patterns ERE-portable (no \s; use [[:space:]]).

# Build the master detection regex as an array of alternatives, then join.
typeset -ga _clickfix_patterns
_clickfix_patterns=(
  # 1) curl/wget/fetch ... | [sudo] <interpreter>
  #    download piped straight into a shell or scripting interpreter.
  '(curl|wget|fetch)[^|;&]*\|[[:space:]]*(sudo[[:space:]]+)?(sh|bash|zsh|dash|ksh|python[0-9.]*|perl|ruby|node|php|osascript)([[:space:]]|$)'

  # 2) eval/exec/source/. of a curl/wget/fetch command substitution.
  #    eval "$(curl ...)" or exec $(wget ...) etc.
  '(eval|exec|source|\.)[[:space:]]+["'\'']?\$\((curl|wget|fetch)'

  # 2b) process substitution feeding a remote download into source/eval/a shell.
  #    source <(curl ...)  /  bash <(curl ...)  /  . <(wget ...)
  '(source|eval|exec|\.|sh|bash|zsh|dash)[[:space:]]+<\([[:space:]]*(curl|wget|fetch)'

  # 3) base64 decode piped into a shell.
  #    base64 -d | sh   /   base64 --decode | bash   /   base64 -D | zsh
  'base64[[:space:]]+(--?d(ecode)?|-D)[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(sh|bash|zsh|dash|python[0-9.]*)([[:space:]]|$)'

  # 4) echo/printf of a long base64-looking blob piped into base64 then a shell,
  #    OR piped directly into a shell. Catches `echo <blob> | base64 -d | sh`.
  '(echo|printf)[[:space:]]+["'\'']?[A-Za-z0-9+/=]{40,}["'\'']?[[:space:]]*\|[[:space:]]*(base64|openssl|sh|bash|zsh)'

  # 5) python/perl/ruby/node inline program (-c / -e / --eval) that downloads
  #    + executes. e.g. python3 -c 'import urllib...; exec(urlopen(...).read())',
  #    perl -e 'system("curl ... | sh")', node -e 'http.get(...,eval)'.
  '(python[0-9.]*|perl|ruby|node)[[:space:]]+(-c|-e|--eval)[[:space:]]+["'\''].*(urllib|urlopen|requests\.get|http|exec\(|eval\(|os\.system|system\(|subprocess|child_process|`)'

  # 6) curl/wget output piped into osascript (AppleScript) — AMOS uses osascript
  #    for the fake password dialog. Any `| osascript` of remote content is hostile.
  '(curl|wget|fetch)[^|;&]*\|[[:space:]]*osascript'

  # 7) osascript output piped into a shell (decode-and-run via AppleScript).
  'osascript[^|]*\|[[:space:]]*(sh|bash|zsh)([[:space:]]|$)'

  # 8) bash /dev/tcp or /dev/udp reverse-shell redirect.
  '/dev/(tcp|udp)/[0-9a-zA-Z.]+/[0-9]+'
)

# Join alternatives into one regex.
typeset -g _clickfix_master_re="${(j:|:)_clickfix_patterns}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# _clickfix_explain <buffer>
# Prints a short plain-language description of WHAT the flagged command does,
# so the user understands the risk instead of pattern-matching on red text.
_clickfix_explain() {
  emulate -L zsh
  local buf=$1
  local -a reasons

  [[ $buf == *'/dev/tcp/'* || $buf == *'/dev/udp/'* ]] && \
    reasons+=( "Opens a raw network connection (possible reverse shell)." )

  if [[ $buf =~ '(curl|wget|fetch)[^|;&]*\|[[:space:]]*(sudo[[:space:]]+)?(sh|bash|zsh|dash|ksh|python|perl|ruby|node|php)' ]]; then
    reasons+=( "Downloads code from the internet and pipes it STRAIGHT into a shell/interpreter — it runs without you ever reading it." )
  fi
  if [[ $buf =~ '(eval|exec|source|\.)[[:space:]]+["'\'']?\$\((curl|wget|fetch)' ]]; then
    reasons+=( "Runs the output of a remote download as a command (eval/exec of \$(curl ...))." )
  fi
  if [[ $buf =~ 'base64[[:space:]]+(--?d(ecode)?|-D)' ]]; then
    reasons+=( "Decodes hidden/obfuscated base64 text and executes it (a classic way to hide the real payload)." )
  fi
  if [[ $buf == *'| osascript'* || $buf =~ 'osascript[^|]*\|[[:space:]]*(sh|bash|zsh)' ]]; then
    reasons+=( "Involves osascript/AppleScript — infostealers use this to pop a FAKE password prompt." )
  fi
  if [[ $buf =~ '(python|perl|ruby|node)[[:space:]]+-c' ]]; then
    reasons+=( "Runs an inline script that fetches and executes remote code." )
  fi

  (( ${#reasons} == 0 )) && reasons=( "Matches a download-and-execute / decode-and-execute pattern." )

  local r
  for r in $reasons; do
    printf '    \xE2\x80\xA2 %s\n' "$r" > /dev/tty
  done
}

# _clickfix_extract_hosts <buffer>
# Echoes the hostnames of any http(s) URLs found in the buffer, one per line.
# Used to compare against the trusted-host allowlist.
_clickfix_extract_hosts() {
  emulate -L zsh
  local buf=$1
  # Grab http(s)://host/... occurrences. -o = only-matching, -E = ERE.
  # We strip scheme and path to leave the bare host.
  print -r -- "$buf" \
    | grep -oE 'https?://[^[:space:]/"'\''`)]+' 2>/dev/null \
    | sed -E 's#^https?://##; s#/.*$##; s#:[0-9]+$##; s#^[^@]*@##' 2>/dev/null
}

# _clickfix_all_hosts_trusted <buffer>
# Returns 0 (true) only if the buffer contains at least one URL AND every URL
# host is in the allowlist. If there are no URLs (e.g. base64/dev-tcp payloads),
# returns 1 (false) so the guard still prompts.
_clickfix_all_hosts_trusted() {
  emulate -L zsh
  local buf=$1
  local -a hosts
  hosts=( ${(f)"$(_clickfix_extract_hosts "$buf")"} )

  (( ${#hosts} == 0 )) && return 1   # no URL to vouch for → not auto-trusted

  local h trusted allowed
  for h in $hosts; do
    trusted=0
    for allowed in $CLICKFIX_GUARD_ALLOW_HOSTS; do
      # Exact match or subdomain of an allowed host.
      if [[ $h == $allowed || $h == *.$allowed ]]; then
        trusted=1
        break
      fi
    done
    (( trusted )) || return 1   # one untrusted host is enough to prompt
  done
  return 0
}

# ---------------------------------------------------------------------------
# The guard widget
# ---------------------------------------------------------------------------
# We chain to whatever `accept-line` widget already exists (zsh-syntax-highlighting,
# zsh-autosuggestions, oh-my-zsh, etc. all wrap accept-line). We captured the
# prior binding name at install time into $_clickfix_orig_accept_line below.

_clickfix_guard() {
  emulate -L zsh
  setopt local_options no_unset

  # Escape hatch: env-disabled → behave like the normal accept-line.
  if [[ ${CLICKFIX_GUARD:-1} == 0 ]]; then
    _clickfix_call_original
    return
  fi

  local buf=$BUFFER

  # Empty / whitespace-only buffers: nothing to inspect.
  if [[ -z ${buf// /} ]]; then
    _clickfix_call_original
    return
  fi

  # Fast path: does the buffer match any dangerous pattern at all?
  if [[ ! $buf =~ $_clickfix_master_re ]]; then
    _clickfix_call_original
    return
  fi

  # Matched something dangerous-shaped. Before alarming, check the allowlist:
  # if EVERY URL in the command points at a trusted installer host, let it pass
  # silently. (base64 / dev-tcp payloads have no URL → never auto-trusted.)
  if _clickfix_all_hosts_trusted "$buf"; then
    _clickfix_call_original
    return
  fi

  # --- DANGER PATH: warn loudly and demand a typed confirmation. -----------
  # All prompt/output and the read MUST go to /dev/tty, because inside a ZLE
  # widget the line editor owns the keyboard; a bare `read` misbehaves.

  zle -M ""   # clear any ZLE status line

  {
    printf '\n\033[1;41;97m  ClickFix / download-and-execute guard  \033[0m\n'
    printf '\033[1;31mThis command can run code from the internet on your Mac:\033[0m\n\n'
    printf '\033[0;33m    %s\033[0m\n\n' "$buf"
    printf '\033[1mWhat it does:\033[0m\n'
  } > /dev/tty
  _clickfix_explain "$buf"

  {
    printf '\n\033[2mIf a website/CAPTCHA/AI answer told you to paste this, it is almost\n'
    printf 'certainly an attack. Legit installers rarely need you to pipe to a shell.\033[0m\n\n'
    printf 'To RUN it anyway, type exactly: \033[1;32m%s\033[0m\n' "$CLICKFIX_GUARD_PHRASE"
    printf 'Anything else (or Enter) aborts: '
  } > /dev/tty

  local answer=''
  # Read the typed confirmation directly from the terminal device.
  IFS= read -r answer < /dev/tty

  if [[ $answer == "$CLICKFIX_GUARD_PHRASE" ]]; then
    printf '\033[2m[shellguard] confirmed — running.\033[0m\n' > /dev/tty
    _clickfix_call_original
    return
  fi

  # Aborted: wipe the buffer and redraw a clean prompt.
  printf '\033[1;32m[shellguard] aborted. Nothing was run.\033[0m\n' > /dev/tty
  BUFFER=''
  zle reset-prompt
  return 0
}

# _clickfix_call_original
# Invoke the previously-bound accept-line widget if we captured one, otherwise
# fall back to the builtin (.accept-line). This keeps zsh-autosuggestions and
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
# Optional: warn at PASTE time too (earlier than Enter).
# When zsh bracketed-paste is active, a multiline ClickFix payload lands in
# $BUFFER literally (it will NOT auto-execute — good). We additionally scan the
# just-pasted region so the user sees a heads-up the moment they paste, before
# they even hit Enter. This is advisory only; the real block is at accept-line.
# ---------------------------------------------------------------------------
_clickfix_bracketed_paste() {
  emulate -L zsh
  # Run the normal bracketed-paste first so the text lands in $BUFFER.
  if [[ -n ${_clickfix_orig_bracketed_paste:-} ]] \
     && zle -l | grep -qx -- "${_clickfix_orig_bracketed_paste}"; then
    zle "${_clickfix_orig_bracketed_paste}"
  else
    zle .bracketed-paste
  fi

  [[ ${CLICKFIX_GUARD:-1} == 0 ]] && return 0

  # Inspect only the region that was just pasted, if zsh exposed it.
  local pasted=''
  if [[ -n ${YANK_START:-} && -n ${YANK_END:-} ]]; then
    pasted=${BUFFER[$((YANK_START + 1)),$YANK_END]}
  else
    pasted=$BUFFER
  fi

  if [[ -n $pasted && $pasted =~ $_clickfix_master_re ]] \
     && ! _clickfix_all_hosts_trusted "$pasted"; then
    zle -M "shellguard: pasted text looks like a download-and-execute command — review before pressing Enter."
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
  # `zle -lL accept-line` prints e.g. "zle -N accept-line orig-widget".
  # If accept-line is the builtin, the listing is empty; default to .accept-line.
  if [[ -n $current_accept && $current_accept != _clickfix_guard && $current_accept != accept-line ]]; then
    typeset -g _clickfix_orig_accept_line=$current_accept
  fi

  # Same for bracketed-paste.
  local current_bp
  current_bp=$(zle -l -L bracketed-paste 2>/dev/null | awk '{print $NF}')
  if [[ -n $current_bp && $current_bp != _clickfix_bracketed_paste && $current_bp != bracketed-paste ]]; then
    typeset -g _clickfix_orig_bracketed_paste=$current_bp
  fi

  zle -N accept-line _clickfix_guard
  zle -N bracketed-paste _clickfix_bracketed_paste
}
