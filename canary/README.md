# Canary — honeytoken tripwire generator

Part of the **ClickFix Defense Kit**. A small, dependency-free Bash tool that
plants **decoy credentials** ("honeytokens") in the places an infostealer or a
ClickFix-pasted payload is most likely to grab them — so that if your Mac is
breached, *you find out*.

> **Defensive use only.** This tool writes obviously-fake bait onto **your own**
> machine. It makes no network calls itself and never touches anything outside
> the decoy paths you choose. Every decoy carries a unique marker so a leaked
> copy is traceable back to the exact file and the day you planted it.

---

## Why honeytokens catch a breach

A honeytoken is a credential that is **worthless to you but irresistible to an
attacker**. You never use it. So the only way it ever gets touched is if someone
who shouldn't be on your machine finds it. Two independent things can then alert
you:

| Layer | What trips it | What you learn | Cost |
|-------|---------------|----------------|------|
| **A — canarytoken (network callback)** | The fake credential is **USED** (e.g. `aws sts get-caller-identity`) or the bait doc is **OPENED & rendered** | Breach happened + timestamp + usually source IP | Free, 2 min |
| **B — local read-watch (eslogger)** | The decoy file is **READ** locally (`cat`, `cp`) — even with no network | Exact process + pid + time that opened it | Heavier: root + Full Disk Access |

These cover different failure modes. canarytokens miss a "read it and walk away"
attacker; the local read-watch catches that but needs elevated permissions. Use
both where you can.

This Canary tool does the part nobody packages turnkey: **bulk-minting-adjacent
placement** — it scatters realistic decoys into the right tempting locations,
tags each with a traceable marker, and tells you honestly what each layer can and
cannot detect.

---

## Quick start

```bash
chmod +x canary-gen.sh

# Interactive: choose where to plant
./canary-gen.sh

# Or non-interactive: plant the standard set into specific dirs
./canary-gen.sh --paths ~/.aws ~/Desktop ~/Documents

# See what you've planted
./canary-gen.sh --list

# Remove everything this tool planted
./canary-gen.sh --revert
```

By default the planted decoys contain **placeholder** values, which means they
are **bait + a traceable marker, but they do NOT alert you on their own**. To
turn them into live tripwires, do one (ideally both) of the following.

---

## Step 1 — make decoys actually alert you (canarytokens.org walkthrough)

Print the in-tool guide any time:

```bash
./canary-gen.sh --canary-walkthrough
```

Short version (AWS-key token, the highest-signal type):

1. Open <https://canarytokens.org> (free, no account).
2. Choose token type **"AWS keys"**.
3. Enter the **email** you want the alert sent to, **or** paste a **Webhook URL**
   (e.g. a private Discord webhook) to get the alert in a channel.
4. In **"Reminder note"** write something you'll recognise, e.g.
   `ClickFix kit decoy — ~/.aws/credentials on <machine-name>`. This note is
   echoed back in the alert so you instantly know *which* decoy fired.
5. Click **Create my Canarytoken**. Copy the `AKIA...` Access Key ID it gives you.
6. Re-plant with your real key so the decoy beacons when used:
   ```bash
   ./canary-gen.sh --token AKIA<your-real-canarytoken-key> --paths ~/.aws
   ```
7. **Test it** from a throwaway shell: `aws sts get-caller-identity`. You should
   get your own alert within seconds. Now you *know* the wiring works.

Other token types: **Fast Redirect / URL** (embed in a fake `backup.sh`), and
**Web bug** (embed in a bait `wallet-seed.pdf` / `passwords.docx`). The generated
`.env` and `passwords.txt` decoys already include a `@@CANARY_URL@@` slot for a
URL/web-bug token.

---

## Step 2 (optional, heavier) — catch a decoy that is merely *read*

```bash
./canary-gen.sh --watch-note
```

This prints two macOS approaches:

- **`log stream`** — lightest to try, but coverage of clean file-open events
  varies by macOS version.
- **`eslogger`** — Apple's Endpoint Security tool. Authoritative one-JSON-event-
  per-open detection of *exactly which process* opened a decoy. **Requires `sudo`
  (root) and Full Disk Access** on the running terminal. Persist it with a
  `LaunchDaemon` if you want it always-on.

This is the only layer that catches an attacker who `cat`s `~/.aws/credentials`
and never touches the network.

---

## What gets planted

| Decoy | Default location(s) | Why there |
|-------|--------------------|-----------|
| `credentials` (fake AWS) | `~/.aws/` | The canonical first thing AMOS/Atomic grab |
| `.env` (bait DB/Stripe/JWT keys) | project roots, `~`, `~/Documents` | Stealers scrape `.env` everywhere |
| `passwords.txt` (bait logins + "wallet seed") | `~/Desktop`, `~/Documents` | The "jackpot" file a smash-and-grab looks for |

Templates live in [`templates/`](./templates) and are clearly marked decoys with
placeholder values. The generator substitutes a unique marker and (optionally)
your real canarytoken at plant time, then `chmod 600`s each file so it looks like
a genuinely guarded secret.

---

## Safety design

- **Never overwrites a real file.** Before writing, the tool refuses any target
  that already exists and does **not** contain a `CANARY-` marker — so it can
  never clobber your real `~/.aws/credentials` or `.env`. Re-running only
  refreshes its own decoys.
- **Ledger + revert.** Every plant is recorded in
  `~/.local/state/clickfix-defense-kit/canary-ledger.tsv`. `--list` shows them
  (and flags any that have gone *missing* — which itself is a signal). `--revert`
  removes only the files this tool planted.
- **No self-exfiltration.** The script makes zero network calls. The only thing
  that ever phones home is a canarytoken *you* minted — to *you*.

---

## Honest limits (read these)

- **This is detection, not prevention.** It tells you *after* a breach. The
  **ShellGuard** layer of this kit (zsh accept-line guard) is what actually
  *blocks* a malicious `curl | sh` paste in the first place. Canary is your
  tripwire if something got past it.
- **A placeholder decoy does not alert on its own.** It's only a live tripwire
  once you (a) re-plant with a real `--token`, and/or (b) enable the local
  read-watch. Out of the box it's bait plus a marker you can later grep for in a
  breach dump.
- **canarytokens fire on USE/OPEN, never on a silent read.** Pair with the
  read-watch for full coverage.
- **AWS canarytokens have a known tell** — a careful attacker who inspects the
  returned identity can spot the Thinkst beacon domain and avoid using the key.
  Most automated stealers don't bother; the local read-watch covers the careful
  case.
- **The read-watch is a real onboarding wall.** Granting root + Full Disk Access
  to a fresh, unsigned tool is itself the trust profile of malware. Only enable
  it on a machine you trust, and prefer a signed/notarized helper if distributing.

---

## Layering with the rest of the kit and the wider stack

- **ShellGuard (this kit)** blocks the dangerous paste at execute time.
- **ClipSentinel (this kit)** warns at copy time.
- **Canary (this tool)** tells you if something *got through* and is now reading
  your secrets.
- **Objective-See LuLu** (separate, free) independently sees the outbound
  canarytoken callback at the network layer.

No single layer is sufficient; that's the point.
