# WatchPost

A **zero-dependency, periodic persistence + login-item change monitor** for macOS.
Part of the [ClickFix Defense Kit](../).

WatchPost takes a snapshot ("baseline") of the places macOS malware plants
persistence, then on each scheduled run diffs the current state against that
baseline and fires a notification listing anything **new**. A persistence file
whose *contents* changed (same path, different hash) is flagged as **TAMPER** —
the loudest signal.

It exists for one specific, narrow job: **be a simple cron-based tripwire on an
unattended Mac** — the kind of headless machine (e.g. a Mac Mini) where a GUI
prompt tool is useless because nobody is sitting at the screen.

---

## Honest scope — read this first

**WatchPost is NOT a real-time blocker. It cannot stop persistence from being
installed.** It is an *after-the-fact* diff that tells you something appeared.

If you want real-time, signing-aware persistence **interdiction** (a popup the
moment something tries to install a LaunchAgent, with allow/block), use
Objective-See's free tools — they do this better than any poll-and-diff script
could, and you should not rebuild them:

- **[BlockBlock](https://objective-see.org/products/blockblock.html)** —
  real-time persistence monitoring + allow/block.
- **[KnockKnock](https://objective-see.org/products/knockknock.html)** —
  on-demand snapshot of everything persistently installed.
- **[LuLu](https://objective-see.org/products/lulu.html)** —
  outbound-connection (exfil) firewall.

On a Mac you sit in front of, install those. WatchPost's only genuinely
non-duplicative slice is the **headless, notification-wired, cron-scheduled
baseline-diff** for machines where BlockBlock's interactive prompts can't reach
you. Use it *alongside* the Objective-See suite, not instead of it.

---

## What it watches

| Surface | Path / source | Why |
|---|---|---|
| Per-user agents | `~/Library/LaunchAgents` | Most common user-level persistence |
| All-user agents | `/Library/LaunchAgents` | Persistence for any logged-in user |
| System daemons | `/Library/LaunchDaemons` | Root-loaded persistence (e.g. the AMOS `com.finder.helper` daemon) |
| Scheduled jobs | `crontab -l` (current user) | cron-based persistence |
| Login items | System Events (`osascript`) | GUI login-item persistence |

For each LaunchAgent/Daemon plist it records the **sha256** and the executable
(`ProgramArguments[0]` / `Program`). New entries are annotated with a
`codesign` verdict (`apple` / `signed` / `adhoc` / `unsigned` / `missing`), so an
**unsigned** persistence target shouts louder than a notarized one.

### The ClickFix / AMOS connection

2025-era AMOS/Atomic macOS infostealer variants added persistence by dropping a
`LaunchDaemon` (observed label `com.finder.helper`) into `/Library/LaunchDaemons`
with `RunAtLoad` + `KeepAlive`, installed via `sudo -S cp …` using a password
phished through a fake `osascript` dialog. A new, unsigned plist appearing in a
monitored directory is exactly what WatchPost surfaces — after the fact, as an
early-as-possible "something changed while you weren't looking" alert.

---

## Install

```bash
# Clone the repo, then:
cd clickfix-defense-kit/watchpost
./install.sh
```

This:
1. Makes `watchpost.sh` executable.
2. Writes `~/Library/LaunchAgents/com.clickfixkit.watchpost.plist` (with your
   username and this clone's real path substituted in).
3. Captures an initial baseline (`watchpost.sh --init`).
4. Loads the agent. It then runs **at login and every hour**.

> **No `curl | bash` installer on purpose.** That delivery pattern is exactly how
> ClickFix/AMOS infections start. A security tool should never train you into it.
> Clone, read the code, run locally.

### Uninstall

```bash
./install.sh --uninstall
```

(Leaves your baseline in `~/.local/state/watchpost` — delete it manually if you
want: `rm -rf ~/.local/state/watchpost`.)

---

## Manual use

```bash
./watchpost.sh            # diff current state vs baseline, alert on new entries
./watchpost.sh --init     # (re)write the baseline silently — no diffing/alerts
./watchpost.sh --no-update # alert on diffs but DON'T advance the baseline
./watchpost.sh --help
```

Override the baseline location with `WATCHPOST_STATE_DIR`.

### `--no-update` is the incident flag

**During an incident, always run `--no-update`.** A normal run promotes the
current state to the baseline after alerting, so you only get told once per
change. That is the right default for a monitor and the wrong one for an
investigation: the next run erases the diff that proved something appeared.
Capture first (`../preserve.sh`), investigate with `--no-update`, and re-arm only
when you are done.

### Baseline integrity

The baseline lives in your home directory, which means it is writable by exactly
the malware this tool exists to catch. Three things now hold:

- It is written **0600** (it enumerates every persistence entry on the machine)
  inside a **0700** state directory, and carries an HMAC tag.
- **Editing it directly is detected.** Pre-seeding the baseline with an entry the
  attacker intends to create later would make the real plant diff as
  already-known. A tag mismatch aborts the run and alerts.
- **Deleting it is an alert, not a first run.** An `.armed` marker records that
  this machine was baselined before. Without it, `rm baseline.json` made the next
  run print "No diffing on first run" and silently absorb whatever had just been
  planted. WatchPost now refuses, and tells you to re-arm deliberately with
  `--init`.

> **Honest limit.** The HMAC key sits in the state directory at 0600, under the
> same user this tool runs as. Anyone already running as you can read it and
> forge a tag. This is tamper-**evidence**, not tamper-proofing: it catches a
> stealer that blindly rewrites or deletes the file; it does not stop a targeted
> attacker who knows WatchPost is installed. The version that would is a
> root-owned daemon writing to `/var/db/watchpost`, which a user-level compromise
> cannot touch. Not built yet, and not claimed.

After an alert, the baseline is promoted to the current state, so you are
notified **once per change** (not every hour for the same item) — the same
"alert on state change, not on every run" discipline a good cron job follows.
By design, WatchPost alerts on **additions and tampering, not removals** — an
attacker *adds* persistence; a missing plist is usually you cleaning up.

---

## Permissions (TCC) — important

macOS Privacy (TCC) controls gate some of what WatchPost reads. You will likely
need to grant:

- **Full Disk Access** to `/bin/bash` (the interpreter the LaunchAgent runs).
  Without it, reading `~/Library` can fail with `EPERM` mid-session, and
  `/Library/LaunchDaemons` may be partially unreadable.
  *System Settings → Privacy & Security → Full Disk Access.*
- **Automation → System Events** — the first login-item enumeration triggers an
  Automation consent prompt. Approve it, or login items are silently skipped.

> Asking for Full Disk Access is *also* what malware does. That's the honest
> tension in any defensive tool — read the (short, commented) source before you
> grant it. Nothing here decrypts secrets, reads file contents, or makes any
> network connection. It hashes plist files, lists names, and notifies.

---

## Root coverage (full `/Library/LaunchDaemons`)

The default install runs as **your user**, which is correct for `~/Library`,
notifications, and login items — but a user agent cannot fully read root-owned
`/Library/LaunchDaemons`. For complete system-daemon coverage, additionally run
WatchPost from a **root LaunchDaemon** with its own state directory, e.g.:

```bash
sudo cp watchpost.sh /usr/local/bin/watchpost.sh
# Create a LaunchDaemon plist (RunProgram as root) that sets
#   WATCHPOST_STATE_DIR=/var/db/watchpost
# and route alerts to a log / webhook instead of osascript (root has no GUI).
sudo launchctl load /Library/LaunchDaemons/com.clickfixkit.watchpost.root.plist
```

A root daemon has no Aqua session, so `osascript` notifications and login-item
enumeration won't work there — use the user agent for those, and the root daemon
purely for the system-daemon hash diff. (This mirrors why headless machines need
the notification routed somewhere reachable — a log you tail, or a chat webhook —
rather than a desktop banner.)

---

## How it works (internals)

1. **Collect** current state into a flat, tab-delimited form (`plist` / `cron` /
   `login` rows), hashing each plist and extracting its executable.
2. **Persist** that as a small, human-readable JSON baseline in
   `~/.local/state/watchpost/baseline.json` — no `jq`, no dependencies.
3. **Diff** by comparing per-entry *identity strings* (which include the plist
   hash) against the baseline. Anything not present before is **new**; a new
   identity at a path that *did* exist before is **TAMPER**.
4. **Alert** via an `osascript` banner (sound: `Basso`) and a fuller stderr
   report (captured to the launchd log), then promote the baseline.

Pure POSIX-ish bash + built-in macOS tools (`shasum`, `plutil`, `codesign`,
`osascript`, `crontab`, `sed`, `awk`). No Homebrew, no Python, no network.

---

## Files

| File | Purpose |
|---|---|
| `watchpost.sh` | The monitor: baseline, diff, alert. |
| `com.clickfixkit.watchpost.plist` | LaunchAgent template (hourly + at login). |
| `install.sh` | Substitutes paths, lints, baselines, loads the agent. |
| `README.md` | This file. |

---

## Defensive use only

WatchPost is a self-defense tripwire for your own machines. It reads names and
hashes of persistence entries you already have the right to inspect. It does not
exfiltrate anything, does not phone home, and makes no claim to *prevent* an
infection — it raises the odds you *notice* one quickly. Pair it with
BlockBlock/LuLu for the real-time half.
