# ClickFix Defense Kit

[![CI](https://github.com/DareDev256/clickfix-defense-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/DareDev256/clickfix-defense-kit/actions/workflows/ci.yml) [![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) ![Platform: macOS](https://img.shields.io/badge/platform-macOS-lightgrey) [![Release](https://img.shields.io/github/v/release/DareDev256/clickfix-defense-kit)](https://github.com/DareDev256/clickfix-defense-kit/releases)

**A small, honest, defensive toolkit for solo developers, freelancers, and families
who use one Mac for everything — built after a single human moment cost me my
whole digital life.**

Defensive use only. No exploits, no offensive tooling. Every tool here runs on
*your own* machine, against *your own* exposure, and never phones home.

---

## Why this exists (the true story)

My fiancée tried to watch a movie on my MacBook while I was half-awake on the
couch. A popup told her to paste a command into Terminal to "fix" the playback /
"verify you're human." She did what the screen told her to do. In under a minute
an infostealer had swept my saved passwords, my API keys, my Notes, and my
screenshots off the disk and out to someone else's server.

I'm an AI engineer. I write security checks into every project I ship. And it
**still** got into my house — not through a zero-day, not through bad code, but
through a normal human moment: a tired person, a trusted laptop, and a popup that
sounded reasonable. The malware didn't break macOS. It asked a human to carry it
past every defense Apple built, and the human said yes.

That's the gap this kit is built around. The attack isn't technical. It's social.
So the defense has to live where the human and the machine actually meet: the
clipboard, the shell prompt, the account boundary, and the question *"if this
already happened, what would they have gotten?"*

---

## The threat: ClickFix + macOS infostealers (AMOS / Atomic / Poseidon)

**ClickFix** (also seen as FakeCAPTCHA, "ClearFake," fake-update, and
fake-error-fix lures) is a social-engineering technique, not a software exploit:

1. A malicious or SEO-poisoned page — often surfaced through a poisoned search
   result or a fake AI-tool/browser "update" — shows a believable prompt: *"Verify
   you are human,"* *"Fix this error,"* *"Complete CAPTCHA in Terminal."*
2. The page **silently copies a shell command to your clipboard** (a `curl … | sh`,
   a `base64 -d | sh` blob, an `eval "$(curl …)"`, or an `osascript` one-liner).
3. It instructs you to open **Terminal** (or the macOS Run dialog), paste, and
   press Enter "to finish."
4. One keystroke later, a macOS infostealer from the **AMOS / Atomic / Poseidon**
   family is downloading, running, and popping a fake password dialog. It then
   scrapes browser logins and cookies, crypto wallets, Keychain prompts, Apple
   Notes, and `.env`/`~/.ssh` files — and 2025-era variants drop a persistence
   `LaunchDaemon` (observed label `com.finder.helper`) via a phished `sudo`
   password.

### Why Gatekeeper, notarization, XProtect, and TCC don't save you here

This is the part most people get wrong, so it's worth stating plainly:

- **Gatekeeper / notarization / XProtect only inspect files that carry the
  `com.apple.quarantine` attribute.** That attribute is attached by
  download-aware apps (Safari, Mail, Messages) when they write a file to disk. A
  command you **paste and type** into Terminal — or a payload `curl` pulls down
  and pipes **straight into a shell** without ever landing as a launched file —
  never gets that attribute and never triggers a file-launch check. Gatekeeper is
  **structurally bypassed, not defeated.** There is nothing for it to scan.
- **The macOS 26.4 Terminal paste-warning does not inspect what you pasted, and
  on a developer's Mac it is usually not running at all.** Per public reversing
  of `xprotectd` (Adam Codega, corroborated by Patrick Wardle), the alert does
  not examine paste *contents* — pasting `hello world` triggers it too. It
  matches the source app's signing identifier against a fixed list. What
  actually matters is that it is **suppressed entirely** when developer tools
  are present, when Terminal has been opened recently, and when SIP is
  disabled. Every one of those describes this kit's audience, so Apple's paste
  protection is effectively **inactive on exactly the machines most likely to be
  attacked through a terminal**.

  > *Correction:* v0.1.0 of this README said the alert "keys off the source app
  > — so it provably misses a `curl | bash` from a browser the user trusts."
  > That was wrong; a browser is precisely what it *does* flag. The real gap is
  > the exemption conditions above, which is a stronger argument, and the kit
  > was leaving it on the table while stating something falsifiable.
- **TCC (Privacy & Security prompts)** gate *file-category* and *automation*
  access — but the malware runs through already-trusted, Apple-signed binaries
  (`Terminal`, `bash`, `osascript`) that inherit the user's own grants, and the
  fake "System Settings" password dialog phishes the one click TCC can't make for
  you.

The only thing standing between the popup and the breach is **a human not
hitting Enter on autopilot** — and autopilot is exactly what the attack is
engineered to exploit. So this kit puts controls at the points where that
autopilot can be interrupted, contained, or at least *noticed*.

---

## The tools

Six small tools, each independent, each installable on its own. They stack into
defense-in-depth across the kill chain: **copy → paste → execute → escalate →
persist → exfiltrate**, plus a self-audit of what's already exposed.

| Tool | Stage it covers | What it actually stops / does | Honest positioning vs. prior art |
|------|-----------------|-------------------------------|----------------------------------|
| **[ShellGuard](./shellguard)** | **Execute** | A zsh guard that tokenizes the command you are about to run, and stops download/decode-and-execute shapes **at the moment you press Enter** — two tiers: a typed confirmation phrase for unambiguous attacks, a single Enter for heuristics. | **The zero-permission control point.** Objective-See's **BlockBlock** added ClickFix protection at Cmd+V in Feb 2026 and inspects real paste content — if you will install a system extension, run it. ShellGuard's remaining honest claim is narrower and still real: it needs **no root, no kext, no system extension and no TCC grant**, it is the only layer that fires on a **typed** (not pasted) command, and it gates at the last authoritative moment: execution. |
| **[ExposureScan](./exposurescan)** | **Self-audit** | A read-only, **names-and-counts-only** scan of four surfaces (browser logins, Apple Notes, `.env` files, `~/.secrets`, plus PII markers) that prints a **blast-radius map ranked by pivot value** — never a single secret value. | **Inverts the trufflehog/gitleaks posture.** Those tools *find and print the value*. ExposureScan answers *"what would a stealer walk away with?"* with the values **architecturally absent from the code path**. That inversion is the product. |
| **[ClipSentinel](./clipsentinel)** | **Copy** | A dependency-free clipboard watchdog. Fires a macOS notification the instant a dangerous command lands on your clipboard — the earliest interception point, before any terminal is involved. | **Use BlockBlock instead if you'll install a system extension** — since Feb 2026 it inspects actual paste content at Cmd+V and does this job better. ClipSentinel is the **zero-permission fallback**: nothing to approve, nothing to trust with root, which is the difference between a family member having *something* and having nothing. It cannot block a paste (macOS exposes no API to); the authoritative block is ShellGuard. |
| **[Canary](./canary)** | **Detect breach** | A honeytoken generator. Plants traceable decoy credentials (fake AWS keys, `.env`, `passwords.txt`) where stealers grab them, with a walkthrough to wire them to **canarytokens.org** (network callback) and/or `eslogger` (local read-watch). | The network-callback half is **Thinkst Canarytokens' / Objective-See's** territory and they win it — this tool is the *turnkey placement + literacy layer* around them. The only additive sliver is the `eslogger` local-read tripwire for a "read-and-walk-away" attacker. |
| **[WatchPost](./watchpost)** | **Persist** | A zero-dependency, cron-scheduled persistence + login-item baseline-diff for **unattended** Macs (e.g. a headless Mac Mini). Flags new/tampered LaunchAgents, LaunchDaemons, cron, and login items with a `codesign` verdict. | **Objective-See's BlockBlock/KnockKnock win the real-time, signing-aware version** — use those on a Mac you sit at. WatchPost's only non-duplicative slice is the **headless, notification-wired** diff for a machine where an interactive prompt can't reach you. |
| **[GuestMode](./guestmode)** | **Contain** | A safe wrapper + manual guide for creating a **standard, non-admin** macOS account for movie night / family / guests, so a phished password can't escalate and the guest can't read your `~/dev` or `~/.secrets`. | A **stock-macOS** blast-radius reducer. No novelty in the mechanism — the value is packaging the right setting with the right honest explanation for the exact victim profile. Containment, not prevention. |

> **A note on honesty (read it):** the kit's real novelty is **not** any single
> monitor. It's three things stacked: (1) **ShellGuard's** execute-time,
> zero-permission grammar gate — no longer an *unoccupied* control point, since
> BlockBlock now covers paste-time, but still the only one that needs no
> system extension and the only one that sees a typed command; (2)
> **ExposureScan's** names-and-counts-only, four-surface, blast-radius-framed
> self-audit, which inverts the entire find-and-print-the-value posture of
> secret scanners into a personal attack-surface map — and physically removing
> value-exposure from the codebase *is* the product; and (3) the integrated
> solo-dev/small-biz framing plus a literacy layer that meets the actual ClickFix
> victim *before* they're an enterprise EDR customer. WatchPost and the Canary
> network-callback half are **not** novel — Objective-See and Thinkst already win
> those, and this kit says so and points you at them. GuestMode is a stock-macOS
> wrapper. **ExposureScan is the differentiated product, ShellGuard is the clever
> load-bearing control, and the rest is glue and education around tools that
> already exist.** That's the whole pitch, stated straight.

---

## If you are in an incident right now

Stop reading the rest of this page.

```sh
./panic.sh            # the checklist, offline, no browser needed
./panic.sh --short    # the ordered summary, fits on a phone screen
./panic.sh --triage   # ...plus live "did anything get root?" probes
./preserve.sh         # capture evidence BEFORE you start cleaning up
```

Or open **[INCIDENT.md](./INCIDENT.md)** on your phone.

The order in that document is the point. The step people get wrong is doing
password resets first: **a stolen session cookie authenticates without your
password and without your 2FA**, so sessions have to be killed first or the
reset protects nothing. Crypto comes before even that, because it is the only
step that cannot be undone.

---

## Quick install

Clone the repo, read the code, then run the top-level menu installer:

```sh
git clone https://github.com/DareDev256/clickfix-defense-kit.git
cd clickfix-defense-kit
./install.sh
```

`install.sh` is an interactive menu — install any tool individually, or run an
uninstall path. It is idempotent: re-running it never double-installs.

**There is deliberately no `curl … | bash` one-line installer.** That delivery
pattern is exactly the attack this kit exists to stop. A security tool should
never train you into the habit it's defending against. Clone it, read the (short,
commented) source, and run it locally.

Each tool also installs standalone — see its folder's `README.md`.

### Recommended order for a solo dev on one Mac

1. **ShellGuard** — the load-bearing block. Install first.
2. **ExposureScan** — run it once to see your current blast radius and fix the P0s.
3. **ClipSentinel** — copy-time early warning.
4. **GuestMode** — make a non-admin account for anyone who isn't you.
5. **Canary** — plant tripwires so you'd *know* if something got through.
6. **WatchPost** — only if you have an unattended/headless Mac.

---

## Permissions: why a security tool asks for what malware asks for

A savvy user should rightly distrust a defensive tool that requests Full Disk
Access or root — those are the same grants malware wants. Here is exactly why
each is requested, and the honest tension:

| Tool | Requests | Why — and the honest tension |
|------|----------|------------------------------|
| **ShellGuard** | nothing | Pure zsh widget. No FDA, no root, no network. Reads only the command line you're about to run. |
| **ClipSentinel** | nothing | Polls `pbpaste` and notifies. No FDA, no root, no network. |
| **ExposureScan** | **Full Disk Access** (to your terminal) | To **read** Apple Notes and browser profile dirs that TCC protects. It only ever reads; it copies SQLite DBs `mode=ro&immutable=1`, never decrypts, never writes outside a temp dir, never touches the network. Without FDA those surfaces are simply skipped. |
| **Canary (read-watch)** | **root + Full Disk Access** (only for the optional `eslogger` layer) | `eslogger` is Apple's Endpoint Security tool; catching a *local read* of a decoy needs it. This is a real onboarding wall — granting root to a fresh, unsigned tool is itself a malware trust profile. **Read the source first; prefer a signed/notarized helper if you distribute it.** The placement half needs nothing. |
| **WatchPost** | **Full Disk Access** (+ Automation→System Events) | To read `~/Library`, `/Library/LaunchDaemons`, and enumerate login items. It hashes plists and lists names; it never reads file *contents*, never decrypts, never phones home. |
| **GuestMode** | macOS admin password (its own prompt) | Only to create the account via `sysadminctl`. The script never reads, stores, or logs your password; macOS prompts for it directly. |

If a tool's rationale here doesn't satisfy you, don't grant it — every tool that
needs an elevated grant degrades gracefully (skips the surface) without it, and
the source is short enough to read in full before you decide.

---

## Defensive-use-only disclaimer

**This kit is for defending machines you own or are explicitly authorized to
defend.** It contains no exploits and no offensive capability:

- Nothing here exfiltrates data, phones home, or transmits your secrets anywhere.
  The only outbound traffic the kit can *cause* is a **canarytoken you minted
  yourself**, beaconing to **your own** alert destination.
- ExposureScan is a self-audit, **not** a secret extractor — it is architecturally
  incapable of emitting a secret value (see its README and CI test).
- Canary plants decoys on **your own** machine only and refuses to overwrite real
  files.
- Do not use any part of this kit to scan, probe, plant, or audit a machine you do
  not own or have written authorization to test. That would be both unethical and,
  in most jurisdictions, illegal.

This is education and self-defense. Treat it that way.

---

## The honest novelty, one more time

If you only remember one thing: the differentiated pieces are **ExposureScan**
(the value-absent, blast-radius-framed self-audit) and **ShellGuard** (the
execute-time grammar gate that costs the user no permission grant at all).
Everything else is careful glue, honest packaging, and a
literacy layer aimed at the real-world ClickFix victim — the tired person on the
couch trying to watch a movie — instead of the enterprise SOC. That victim was me.
This is the kit I wish I'd had installed that night.

---

## License & contributing

- **License:** [Apache License 2.0](./LICENSE). The kit shells out to external
  tools (e.g. Gitleaks) rather than vendoring them, and deliberately does **not**
  copy any AGPL/GPL code (notably it does not vendor TruffleHog) — see
  [SECURITY.md](./SECURITY.md) and [CONTRIBUTING.md](./CONTRIBUTING.md).
- **Reporting issues / responsible disclosure:** see [SECURITY.md](./SECURITY.md).
- **Contributing:** see [CONTRIBUTING.md](./CONTRIBUTING.md).

---

## Credit

Built by **James "DareDev256" Olusoga** — AI Solutions Engineer & Creative
Technologist, Toronto — after the movie-night breach described above. If it saves
one other person that night, it did its job.
