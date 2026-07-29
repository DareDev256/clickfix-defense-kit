#!/bin/zsh
# downloadtriage.zsh — ClickFix Defense Kit
# =============================================================================
# "I downloaded this. Should I open it?"
#
# ShellGuard watches the shell prompt. That is one execution path, and macOS has
# many. A double-clicked .command, a .pkg whose preinstall script runs as ROOT, a
# .app from a mounted DMG, a Script Editor lure — none of them ever touch a zsh
# prompt, so none of them can be caught at accept-line.
#
# This closes the DELIVER stage: it inspects what is already sitting in your
# Downloads folder, BEFORE you double-click it.
#
# WHY .pkg IS THE IMPORTANT CASE
#   An installer package can carry preinstall/postinstall scripts that run as
#   root, and the user is *conditioned* to type an admin password into
#   Installer.app — it looks exactly like a legitimate install. GuestMode's
#   "a phished password cannot escalate" framing does not cover it, because the
#   escalation is the documented behaviour of the installer. So this tool
#   expands the package and runs its scripts through the SAME grammar that
#   guards your shell prompt (../lib/clickfix-grammar.zsh).
#
# IT NEVER EXECUTES ANYTHING.
#   `pkgutil --expand-full` unpacks; it does not run. DMGs are NOT mounted
#   unless you pass --mount, because mounting is itself an attack step in
#   current campaigns. Nothing here opens, launches, or installs.
#
# Usage:
#   ./downloadtriage.zsh                  triage ~/Downloads (last 30 days)
#   ./downloadtriage.zsh <path>           triage one file or directory
#   ./downloadtriage.zsh --all            no date filter
#   ./downloadtriage.zsh --days N         change the window (default 30)
#   ./downloadtriage.zsh --mount          allow DMG mounting for deep inspection
#   ./downloadtriage.zsh --json           machine-readable summary
#
# Exit: 0 nothing notable · 2 something wants your attention · 1 usage error
#
# DEFENSIVE USE ONLY. Read-only. No network. Nothing leaves the machine.
# =============================================================================

emulate -L zsh
setopt local_options no_nomatch pipe_fail

typeset -r ROOT=${0:A:h:h}
typeset -r GRAMMAR=$ROOT/lib/clickfix-grammar.zsh

typeset TARGET="$HOME/Downloads"
typeset -i DAYS=30 ALLTIME=0 ALLOW_MOUNT=0 JSON=0

while (( $# )); do
  case $1 in
    --all)    ALLTIME=1; shift ;;
    --days)   DAYS=${2:-30}; shift 2 ;;
    --mount)  ALLOW_MOUNT=1; shift ;;
    --json)   JSON=1; shift ;;
    -h|--help) sed -n '3,40p' ${0:A} | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*)       print -u2 -- "Unknown option: $1 (try --help)"; exit 1 ;;
    *)        TARGET=$1; shift ;;
  esac
done

if [[ ! -r $GRAMMAR ]]; then
  print -u2 -- "[downloadtriage] FATAL: cannot read $GRAMMAR"
  exit 1
fi
source "$GRAMMAR"

if [[ -t 1 ]] && (( ! JSON )); then
  B=$'\033[1m'; R=$'\033[1;31m'; Y=$'\033[33m'; G=$'\033[32m'; D=$'\033[2m'; X=$'\033[0m'
else
  B=''; R=''; Y=''; G=''; D=''; X=''
fi

typeset -i N_SEEN=0 N_FLAG=0
typeset -a JSON_ROWS

# ---------------------------------------------------------------------------
# Fact gathering — each returns a short string, never executes the target
# ---------------------------------------------------------------------------

# Gatekeeper only inspects files carrying com.apple.quarantine. A file WITHOUT
# it either never came from a download-aware app, or had it stripped — and
# stripping it is a documented step in "the app is damaged, right-click Open"
# social engineering.
_quarantine() {
  local q
  q=$(xattr -p com.apple.quarantine "$1" 2>/dev/null)
  if [[ -z $q ]]; then
    print -r -- "ABSENT"
  else
    print -r -- "present"
  fi
}

# The origin URL. This is the single most useful fact about a download and it
# is invisible in `ls`.
_origin() {
  local o
  o=$(mdls -raw -name kMDItemWhereFroms "$1" 2>/dev/null \
        | tr -d '\n' | sed -E 's/[(){}"]//g; s/^[[:space:]]*//; s/,.*$//')
  [[ -z $o || $o == '(null)' || $o == 'null' ]] && o=''
  print -r -- "$o"
}

# Gatekeeper's own verdict, plus who signed it.
#
# The assessment TYPE matters. `spctl -a` with no type assumes an executable, so
# running it against a .pkg or an archive returns "rejected / no usable
# signature" for perfectly legitimate files. Reporting that as a finding is how
# you end up telling someone the official Signal installer is unsigned.
_assess() {
  local out verdict auth kind=$2
  case $kind in
    pkg|mpkg) out=$(spctl -a -vv -t install "$1" 2>&1) ;;
    *)        out=$(spctl -a -vv "$1" 2>&1) ;;
  esac
  if print -r -- "$out" | grep -q 'accepted'; then
    verdict=accepted
  elif print -r -- "$out" | grep -q 'rejected'; then
    verdict=REJECTED
  else
    verdict=unknown
  fi
  auth=$(print -r -- "$out" | grep -m1 'origin=' | sed 's/.*origin=//')
  [[ -z $auth ]] && auth=$(codesign -dv --verbose=2 "$1" 2>&1 | grep -m1 'Authority=' | sed 's/.*Authority=//')
  [[ -z $auth ]] && auth='unsigned'
  print -r -- "${verdict}|${auth}"
}

# ---------------------------------------------------------------------------
# The important one: expand a .pkg and read its install scripts
# ---------------------------------------------------------------------------
# `pkgutil --expand-full` writes the package's contents to disk. It does NOT
# run anything. A pre/postinstall script here executes as ROOT at install time.
_scan_pkg_scripts() {
  # Every local is declared ONCE here. Re-running `local body` inside the loop
  # made zsh echo "body=$'...'" into stdout — the script's own debug noise
  # landing in the report.
  local pkg=$1
  local tmp findings='' s body
  tmp=$(mktemp -d "${TMPDIR:-/tmp}/dltriage.XXXXXX") || return 1

  if ! pkgutil --expand-full "$pkg" "$tmp/x" >/dev/null 2>&1; then
    rm -rf -- "$tmp"
    print -r -- "UNREADABLE"
    return 0
  fi

  # ONE glob. Two overlapping patterns reported every script twice.
  for s in "$tmp"/x/**/(preinstall|postinstall)(N.); do
    [[ -f $s ]] || continue
    body=$(<"$s")
    [[ -z ${body//[[:space:]]/} ]] && continue

    # The payoff of the shared grammar: the same tokenizer that guards the
    # shell prompt now reads an installer script that would run as root.
    clickfix_check "$body"
    findings+="${s:t}:${CLICKFIX_VERDICT}"$'\n'
    if [[ $CLICKFIX_VERDICT != silent ]]; then
      findings+="  REASONS:${(j:; :)CLICKFIX_REASONS}"$'\n'
      # Keep a sanitized excerpt so the user can see it with their own eyes.
      # Indent via sed, not a zsh substitution: ${x//$'\n'/...} does not expand
      # the replacement, so it emitted a literal $'\n' into the report.
      findings+="  --- script contents ---"$'\n'
      findings+="$(clickfix_sanitize_for_display "$body" 20 | sed 's/^/  /')"$'\n'
    fi
  done

  rm -rf -- "$tmp"
  [[ -z $findings ]] && print -r -- "NONE" || print -r -- "$findings"
}

# ---------------------------------------------------------------------------
# Per-file triage
# ---------------------------------------------------------------------------
_triage_one() {
  local f=$1
  local ext=${f:e:l} name=${f:t}
  local -a notes
  local tier=ok

  (( N_SEEN++ ))

  local q=$(_quarantine "$f")
  local origin=$(_origin "$f")

  # Gatekeeper assessment is only MEANINGFUL for things macOS would actually
  # launch. `spctl -a` "rejects" an ordinary .txt or .png too, and reporting
  # that as a finding is crying wolf on every document in the folder — which is
  # how a tool earns itself being ignored. Assess only what can execute.
  # Only ask Gatekeeper about things Gatekeeper actually judges.
  #
  #   .app / .pkg   — signed and notarized as a unit. Assess these.
  #   .dmg          — the signature lives on the .app INSIDE. Assessing the
  #                   image itself returns "no usable signature" for legitimate
  #                   installers, so we say nothing rather than something false.
  #   .zip/.tar/.gz — archives are not signed. Never assess.
  #   .sh/.command  — plain text. Not signed; we READ them instead.
  local -i assessable=0
  case $ext in
    app|pkg|mpkg) assessable=1 ;;
  esac
  # An executable binary (not a text script) is also fair game.
  if [[ -x $f && ! -d $f && $ext != (sh|command|terminal|scpt|applescript|py|rb|pl) ]]; then
    file -b "$f" 2>/dev/null | grep -qi 'mach-o' && assessable=1
  fi

  local verdict='n/a' auth='n/a' assess
  if (( assessable )); then
    assess=$(_assess "$f" "$ext")
    verdict=${assess%%|*}
    auth=${assess#*|}
  fi

  # --- risk rules -----------------------------------------------------------

  # Directly-executable-by-double-click script types. These are the ClickFix
  # delivery formats that never involve a shell prompt.
  case $ext in
    command|terminal|scpt|applescript|workflow|shortcut)
      notes+=( "Double-clicking this RUNS it. '.${ext}' opens straight into Terminal/Script Editor." )
      tier=warn
      # If it is a plain-text script, read it with the shared grammar.
      if [[ $ext == (command|terminal) && -r $f ]]; then
        local body=$(<"$f")
        clickfix_check "$body"
        if [[ $CLICKFIX_VERDICT != silent ]]; then
          notes+=( "Its contents match a download-and-execute pattern: ${(j:; :)CLICKFIX_REASONS}" )
          tier=danger
        fi
      fi
      ;;
  esac

  # The root-escalation case.
  if [[ $ext == pkg || $ext == mpkg ]]; then
    local sc=$(_scan_pkg_scripts "$f")
    if [[ $sc == UNREADABLE ]]; then
      notes+=( "Could not expand the package to read its install scripts." )
      [[ $tier == ok ]] && tier=warn
    elif [[ $sc != NONE ]]; then
      if print -r -- "$sc" | grep -q ':block'; then
        notes+=( "Its install script matches a download-and-execute pattern — and .pkg scripts run as ROOT." )
        tier=danger
      elif print -r -- "$sc" | grep -q ':warn'; then
        notes+=( "Its install script has a suspicious shape. .pkg scripts run as ROOT." )
        [[ $tier != danger ]] && tier=warn
      else
        notes+=( "Has install scripts (they run as root); grammar found nothing hostile in them." )
      fi
      PKG_DETAIL=$sc
    fi
  fi

  # A missing quarantine flag on something executable means Gatekeeper will not
  # inspect it at all.
  if [[ $q == ABSENT && $ext == (app|pkg|mpkg|dmg|command|terminal|scpt) ]]; then
    notes+=( "No quarantine flag — Gatekeeper will NOT check this on open. Either it did not arrive via a browser, or the flag was stripped." )
    [[ $tier == ok ]] && tier=warn
  fi

  if (( assessable )) && [[ $verdict == REJECTED ]]; then
    notes+=( "Gatekeeper REJECTS this (unsigned, unnotarized, or tampered)." )
    tier=danger
  fi

  # Origin host, checked against the grammar's known malware-staging hosts.
  if [[ -n $origin ]]; then
    local host=${${origin#*://}%%/*}
    local risky
    for risky in $CLICKFIX_HIGH_RISK_HOSTS; do
      if [[ ${(L)host} == ${(L)risky} || ${(L)host} == *.${(L)risky} ]]; then
        notes+=( "Downloaded from ${host} — a host commonly used to stage malware payloads." )
        if (( assessable )) || [[ $ext == (dmg|command|terminal|scpt|sh|zip) ]]; then
          tier=danger
        elif [[ $tier == ok ]]; then
          tier=warn   # a .txt from a risky host is worth noting, not alarming
        fi
      fi
    done
  fi

  # Any downloaded shell script, not just .command — read it, do not assess it.
  if [[ $ext == (sh|bash|zsh) && -r $f && ! -d $f ]]; then
    local sbody=$(<"$f")
    clickfix_check "$sbody"
    if [[ $CLICKFIX_VERDICT != silent ]]; then
      notes+=( "Downloaded shell script whose contents match a download-and-execute pattern: ${(j:; :)CLICKFIX_REASONS}" )
      tier=danger
    fi
  fi

  if [[ $ext == dmg ]]; then
    if (( ALLOW_MOUNT )); then
      notes+=( "Disk image — mount requested; inspect the .app inside for its real signature." )
    else
      notes+=( "Disk image not mounted (mounting is itself a delivery step), so its signature was not checked — that lives on the app inside. Re-run with --mount to inspect." )
    fi
  fi

  # --- output ---------------------------------------------------------------
  (( ${#notes} == 0 )) && return 0
  [[ $tier != ok ]] && (( N_FLAG++ ))

  if (( JSON )); then
    JSON_ROWS+=( "{\"file\":\"${name//\"/\\\"}\",\"tier\":\"$tier\",\"quarantine\":\"$q\",\"gatekeeper\":\"$verdict\",\"signer\":\"${auth//\"/\\\"}\",\"origin\":\"${origin//\"/\\\"}\"}" )
    return 0
  fi

  local badge
  case $tier in
    danger) badge="${R}[!]${X}" ;;
    warn)   badge="${Y}[?]${X}" ;;
    *)      badge="${D}[.]${X}" ;;
  esac

  print -r -- ""
  print -r -- "$badge ${B}${name}${X}"
  [[ -n $origin ]] && print -r -- "    ${D}from${X} $origin"
  if (( assessable )); then
    print -r -- "    ${D}quarantine${X} $q   ${D}gatekeeper${X} $verdict   ${D}signer${X} $auth"
  else
    print -r -- "    ${D}quarantine${X} $q   ${D}(Gatekeeper does not judge this file type)${X}"
  fi
  local n
  for n in "${notes[@]}"; do
    print -r -- "    • $n"
  done
  if [[ -n ${PKG_DETAIL:-} && $tier != ok ]]; then
    print -r -- "    ${D}--- install script ---${X}"
    print -r -- "$PKG_DETAIL" | sed 's/^/    /'
    PKG_DETAIL=''
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if [[ ! -e $TARGET ]]; then
  print -u2 -- "No such path: $TARGET"
  exit 1
fi

(( JSON )) || {
  print -r -- "${B}Download triage${X} ${D}— $TARGET${X}"
  print -r -- "${D}Read-only. Nothing is opened, mounted, installed or executed.${X}"
}

typeset -a files
if [[ -d $TARGET ]]; then
  if (( ALLTIME )); then
    files=( "$TARGET"/*(.N) "$TARGET"/*.app(N/) "$TARGET"/*.pkg(N) )
  else
    files=( ${(f)"$(find "$TARGET" -maxdepth 1 \( -type f -o -name '*.app' \) -mtime -${DAYS} 2>/dev/null)"} )
  fi
else
  files=( "$TARGET" )
fi

typeset f
for f in "${files[@]}"; do
  [[ -z $f || ! -e $f ]] && continue
  [[ ${f:t} == .* ]] && continue
  _triage_one "$f"
done

if (( JSON )); then
  print -r -- "{\"scanned\":$N_SEEN,\"flagged\":$N_FLAG,\"items\":[${(j:,:)JSON_ROWS}]}"
else
  print -r -- ""
  if (( N_FLAG == 0 )); then
    print -r -- "${G}Nothing notable${X} across $N_SEEN item(s)."
  else
    print -r -- "${R}${N_FLAG}${X} of $N_SEEN item(s) want your attention."
    print -r -- "${D}A [!] on a .pkg matters most: its install scripts run as root, and you are${X}"
    print -r -- "${D}conditioned to type an admin password into Installer.app.${X}"
  fi
fi

(( N_FLAG > 0 )) && exit 2
exit 0
