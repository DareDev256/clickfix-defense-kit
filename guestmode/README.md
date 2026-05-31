# GuestMode — one machine, one blast radius

Part of the **ClickFix Defense Kit**. This is the *blast-radius reduction*
layer: a small, safe setup script (and a fully-documented manual path) for
creating a **standard, non-admin** macOS account to use for movie night,
family, kids, or guests — so the day your nephew pastes a "verify you're human"
command into Terminal, or types the family password into a fake System Settings
dialog, the damage is contained to a throwaway account that can't see your dev
code, your `~/.secrets`, or escalate to admin.

---

## Why one machine = one blast radius

When everyone shares the *same admin account* on a Mac, that single account is
the blast radius for everything:

- Your saved browser logins, session cookies, and crypto wallets.
- Your dev directories, API keys, and `~/.secrets`.
- The ability to type an admin password into a sudo prompt — which is exactly
  what a ClickFix / AMOS-style infostealer needs to install its persistent
  backdoor (e.g. a `com.finder.helper` LaunchDaemon in `/Library/LaunchDaemons`).

A **standard (non-admin)** account for casual/family use cuts that down:

- A standard user **cannot** approve a sudo/admin-password phish, so the
  password-dialog trick can't escalate to a system-wide LaunchDaemon.
- A standard user **cannot** read another user's home directory — macOS sets
  home dirs to `700` by default, so your `~/dev` and `~/.secrets` are invisible
  to the guest account entirely.
- If something does go wrong on that account, you delete the account and the
  mess goes with it. Your primary account is untouched.

### Honest limits — read this, it's the differentiator

This does **not** stop an infostealer. Be clear-eyed:

- ClickFix / AMOS malware runs through already-trusted, Apple-signed binaries
  (Terminal, `osascript`, `bash`) and inherits *their* permissions. A
  **standard** account still gets *its own* browser data, cookies, and
  clipboard scraped if the user pastes-and-runs the payload.
- Gatekeeper, notarization, and XProtect do **not** fire on a `curl … | bash`
  the user pastes themselves — there's no `com.apple.quarantine` attribute and
  no file-launch event, so those checks are structurally bypassed.
- The macOS 26.4 Terminal paste-block is **warn-only** and user-overridable
  ("Paste Anyway").

So the honest framing is: **GuestMode reduces what a phished password can do.**
It is containment, not prevention. Pair it with the other kit layers:

- **ShellGuard** (zsh execute-time gate) does the actual *blocking* of
  `curl|sh` / `eval $(curl)` / `base64 -d | sh`.
- **ClipSentinel** warns at *copy* time.
- **ExposureScan** tells you what credentials are already sitting exposed.

GuestMode is the "if it still goes wrong, keep it small" layer.

---

## What this folder contains

| File | What it does |
|------|--------------|
| `setup-guestmode.sh` | **Dry-run by default.** Reports your private paths' permissions, checks whether a guest account exists, and — only with `--apply` plus a typed `CREATE` confirmation — creates a standard non-admin user via `sysadminctl`, sets a restrictive `umask 077`, and ensures the account is not in the `admin` group. Never deletes users, never demotes existing admins, never touches your primary account. |
| `README.md` | This file. |

---

## Quick start

```bash
cd clickfix-defense-kit/guestmode

# 1) DRY-RUN (default) — prints the plan, changes nothing:
./setup-guestmode.sh

# 2) Apply for real (still asks you to type CREATE, still prompts for sudo):
./setup-guestmode.sh --apply

# Optional: custom name
./setup-guestmode.sh --apply --user movienight --fullname "Movie Night"
```

The script is **side-effect free** until you pass `--apply`. Even with
`--apply`, it:

1. prints the exact `sysadminctl` command it will run,
2. requires you to type the word **`CREATE`** (not a single-key `y/N` — same
   anti-autopilot principle as ShellGuard), and
3. relies on macOS's own admin-password prompt for the privileged step (the
   script never reads, stores, or logs your password).

### Safety guarantees (by design)

- **Dry-run by default.** No flag = no change.
- **Two gates to mutate:** `--apply` *and* a typed `CREATE` (or `--apply --yes`
  for scripted/CI use).
- **Never destructive:** it will not delete a user, will not demote an existing
  admin, and will not modify your primary account. If the target user already
  exists, it reports status and exits.
- **Private-by-default guest:** sets `umask 077` for the new account so anything
  the guest creates is `600`/`700`.
- **No secrets in code:** the temp password is generated at runtime from
  `/dev/urandom`, never printed, and scrubbed from the environment immediately.

---

## The pure manual path (no script required)

If you'd rather click than run a shell script — totally reasonable for a
security tool — here is the exact, supported System Settings path. This is the
*recommended* path for most people.

### Create a standard (non-admin) account

1. Open **System Settings** → **Users & Groups**.
2. Click the **Add Account…** button (you'll be asked for your admin password).
3. Set **New Account** to **Standard** (NOT *Administrator*).
4. Give it a name like `Family Guest` / short name `familyguest`, set a
   password, and click **Create User**.
5. Confirm it shows as **Standard** in the list — *not* "Admin".

That's it. That account now cannot escalate to admin and cannot read your
home directory.

### (Alternative) Turn on the built-in Guest User — best for true movie-night

macOS ships a **Guest User** that requires *no password* and **erases its home
folder on logout** — ideal for a shared/movie-night machine where you want zero
persistence.

1. **System Settings** → **Users & Groups**.
2. Find **Guest User**, click the ⓘ / toggle.
3. Turn on **Allow guests to log in to this computer**.
4. (Optional) restrict it with **Screen Time** / parental controls.

Trade-off: the Guest User can't keep settings between sessions (that's the
point). The `setup-guestmode.sh` script instead makes a *persistent* standard
account, which is better when the same family member uses it regularly.

### Verify your own home dir is locked down

Run these once (they're safe, read-mostly):

```bash
ls -ld ~                 # expect: drwx------  (700) — only you can read it
chmod 700 ~              # enforce it if not
chmod o-rwx ~/dev ~/Documents/Projects ~/.secrets 2>/dev/null  # belt + suspenders
```

---

## Further hardening (intentionally NOT automated)

These are documented but the script does **not** do them for you, because they
change behavior and should be a deliberate choice:

- **Hide the guest from fast-user-switching** if you don't want it in the menu.
- **Disable Terminal for the guest** via parental controls / Screen Time app
  limits (removes the easiest ClickFix paste target on that account).
- **Per-account FileVault** considerations on shared machines.
- **Don't grant the guest sudoers entries** — the whole point is they have none.

---

## Placeholders / privacy

This tool ships with obvious placeholder values (`familyguest`, `Family Guest`,
and example clone paths). No real secrets, tokens, or PII are
included. Change the username/full name to taste via `--user` / `--fullname`.

**Defensive use only.**
