# ExposureScan

**Local secret + PII blast-radius self-audit for macOS — names and counts only, never values.**

Part of the open-source [ClickFix Defense Kit](../).

---

## What it answers

> *If an infostealer (AMOS / Atomic / Poseidon) ran on my Mac right now, what would it walk away with — and what could the attacker pivot into?*

ExposureScan inventories the credential/PII surfaces a macOS infostealer targets and prints a **prioritized blast-radius report** ranked by pivot value (P0 → P3), not raw count. It is the productized version of the manual "what's sitting on my disk" incident scan.

It scans:

| # | Surface | What it reports |
|---|---------|-----------------|
| a | **Chrome / Brave / Edge / Chromium saved logins** (`Login Data` SQLite) | per-domain count of saved logins, whether a username exists, whether a password is present — **never the password**. Plus **cookie row counts** per profile, with the "sessions survive a password reset" ordering warning |
| b | **Apple Notes** (`NoteStore.sqlite` → gzip `ZICNOTEDATA.ZDATA`) | note **primary key**, title **length**, **modification date**, matched **category** (password / seed-phrase / api-key / PIN / SIN…) — **never the title, never the matched text** |
| c | **`.env` files** under a target dir | **KEY NAMES only** (left of `=`), line number, value *shape* (length / entropy class / prefix class) — **never the value** |
| d | **`~/.secrets`** | file **names** + sizes + permissions (the filename *is* the credential name) |
| e | **PII markers** in Desktop / Documents / Downloads | **counts per type** (email, phone, SIN/SSN, Luhn-validated card, DOB) — **never the instance**. Filenames are screened by the same patterns and **withheld** (hash + parent dir + size + mtime) when the filename is itself the PII |
| f | **Developer credentials** (v0.2.0) | `~/.ssh` private keys by **filename + type + ENCRYPTED vs PLAINTEXT**; presence + **file mode** + **key names only** for `~/.aws/credentials`, `~/.npmrc`, `~/.pypirc`, `~/.netrc`, `~/.config/gh/hosts.yml`, `~/.docker/config.json`, `~/.kube/config`, `~/.config/gcloud`, `~/.git-credentials`, `~/.cargo/credentials.toml`, `~/.gem/credentials`; secret-shaped **counts + line numbers** in `~/.zsh_history` / `~/.bash_history` |
| g | **Crypto wallets** (v0.2.0) | wallet **extension LevelDB stores** under each browser profile's `Local Extension Settings`, plus desktop wallet bundles. Always **P0** |
| h | **Keychain / Safari / Firefox** (v0.2.0) | `login.keychain-db` presence + size + lock state; Firefox saved-login and cookie **counts**; Safari stated honestly (see limits) |
| i | **TCC grants** — `--tcc` (v0.2.0) | which binaries hold Full Disk Access / Accessibility / Screen Recording / Input Monitoring, tiered **P0 when the holder is a grant-inheritance vehicle**, plus Secure Keyboard Entry, the remote-access surface and Secure Boot level |

### Why (f)–(i) exist

The v0.1.x surfaces cover what a stealer takes from a *consumer*. They missed the highest-pivot files on a solo developer's Mac. A passphrase-less SSH key plus a GitHub CLI token is push access to every repo you own — **a personal breach becomes a supply-chain breach** — and the report said nothing about any of it. The wallet case is worse: the tool tiered a seed phrase in Notes at P0 and never looked where wallets actually live. Crypto theft is irreversible, uninsured and has no chargeback, so wallet stores are P0 unconditionally.

### `--tcc`: the kit's own argument, finally actioned

The kit's central claim is that **malware inherits the grants of the trusted binary it runs inside** — and then never told you *which* binaries those are.

```bash
./exposurescan.py --tcc
```

reads both `TCC.db` files (`~/Library/Application Support/com.apple.TCC/TCC.db` and `/Library/Application Support/com.apple.TCC/TCC.db`) through the same read-only safe-copy machinery as every other SQLite surface, and tiers **P0** any terminal, shell, SSH wrapper, remote-access tool or bare interpreter binary holding Full Disk Access, Accessibility, Screen Recording, Input Monitoring or Developer Tools. Those are not apps holding a permission; they are permissions attached to a thing that runs other code:

> *Your Terminal has Screen Recording. A pasted payload gets Screen Recording too — it never has to ask.*

An ordinary GUI app holding an ordinary grant (Photos, Camera) is counted in a P3 aggregate, not tiered up. Without Full Disk Access the system database is reported as skipped, not failed.

Bundled into the same flag, because they are ClickFix-relevant and nothing else surfaces them to a consumer:

- **Terminal Secure Keyboard Entry** — off by default. Without it, *any* of the apps holding Accessibility or Input Monitoring can read the admin password you type at a `sudo` prompt, which is the exact step a ClickFix payload wants from you.
- **Remote-access surface** — is `com.openssh.sshd` or `com.apple.screensharing` enabled? An added line in `~/.ssh/authorized_keys` is quieter persistence than a LaunchAgent, survives a password change, and is invisible to WatchPost's persistence diff.
- **Secure Boot level / kext policy** — a Mac sitting at *Reduced Security / Allow All Kernel Extensions* is a real downgrade of the boot chain, and no other tool in this kit would tell you.

**Deliberately excluded from `--tcc`, and not coming later:** FileVault, firewall posture, update settings, sudoers, password policy, the general CIS-style sweep. [mSCP](https://github.com/usnistgov/macos_security) (authoritative via NIST SP 800-219), [CIS](https://www.cisecurity.org/benchmark/apple_os) and [Pareto Security](https://paretosecurity.com/) own that ground and own it better. `--tcc` is only the narrow grant-inheritance slice that is genuinely underserved and directly on-thesis.

---

## The privacy promise (this is the product, not a flag)

**Secret values never leave your machine — they never even enter the program's output.**

This is enforced by architecture, not by a disabled `--show-data` flag:

- **Browser passwords** — we `SELECT origin_url, username_value, length(password_value)` only. We **never** select, read, or decrypt `password_value`. Chrome's macOS passwords are AES-128-CBC under a Keychain key; **this tool refuses to decrypt by design** — decrypting is exactly what a stealer does.
- **`.env` values** — we split on the first `=`, keep the **key name**, measure the value's length/entropy to score risk, then **discard the value immediately**. It is never stored or printed.
- **Apple Notes** — we report the note's **primary key, title LENGTH, modification date and matched category**. **The title is never emitted.** On macOS a note has no user-chosen title: `ZTITLE1` is *derived from the note's first line*. For the exact person this surface exists for — someone who pasted a seed phrase into Notes — the "title" **is** the secret. The modification date is what actually lets you find the note again (sort Notes.app by *Date Edited*).
- **PII filenames** — a filename can be the PII. `visa 4111 1111 1111 1111 exp 0327 cvv 415.csv` is withheld and reported as `<filename withheld - matched credit-card> (#3df3ff2b) in ~/Documents/ (34 bytes, 2026-07-28 18:36 UTC)`.
- **SSH private keys** — we report the **filename, key type and ENCRYPTED vs PLAINTEXT**. For an `OPENSSH PRIVATE KEY` we base64-decode a hard-bounded **112 characters (84 bytes)** of the body: enough for the magic, ciphername, KDF name/options and — for a passphrase-less key — the *public* key type, and it stops **short of the private section in both layouts** (which starts at ~94 bytes plaintext, ~126 bytes encrypted). For an encrypted key the type is read from the `.pub` half instead; the bound is widened for nobody. Private key material is never decoded, so it cannot be held, logged or emitted even by accident. If the header cannot be parsed the key is reported as encrypted — **unknown is never reported as the P0 case**.
- **Developer credential files** — presence, **file mode** and **key names only**. `~/.git-credentials` is the sharp case: every line of it is literally `https://user:token@host`, so no line is ever emitted or parsed for userinfo — we report the entry **count** and the **hostnames**. `.netrc` gets the same treatment: field names and a machine count, never a `login` or `password` value.
- **Shell history** — a **count**, the **line numbers**, and the credential **prefix class** (`GitHub personal access token`, `Bearer auth token`). The matched text is never read into a finding, so the report tells you exactly where to look without ever reading the secret back to you.
- **TCC** — service + client identifier only. There are no values in `TCC.db` to leak.
- **`redact()` chokepoint** — every user-facing string (markdown and JSON) passes through a final funnel that, in order:
  1. replaces control characters with `U+FFFD` (kills ANSI escapes, `NUL`, C1);
  2. collapses the string to **one line** (a `\n` in a title otherwise forges a markdown heading);
  3. strips `scheme://user:password@` URI userinfo;
  4. strips everything right of `=` **to end of line**;
  5. redacts to end of line after a sensitive keyword (`password`, `pin`, `token`, …) followed by `:`/`=`/space — this is what catches short, low-entropy secrets like `PIN 4821`;
  6. replaces any run of ≥6 consecutive **BIP-39 wordlist** tokens with `<redacted seed-phrase>`;
  7. redacts any remaining long high-entropy run.
  Then `markdown_safe()` escapes markdown metacharacters before anything is interpolated into the report.

The BIP-39 English wordlist ships as `bip39.txt` (exactly 2048 lines, sha256 `2f5eed53…`, from the [BIP-39 spec repo](https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt)). It is loaded lazily; if it is missing, seed-phrase redaction is disabled with a warning that names the missing **file** and never echoes the text it would have checked.

**Detection** uses a higher bar than redaction: a P0 "seed-phrase" finding needs ≥11 consecutive wordlist tokens, because a false-positive P0 on a shopping list trains you to ignore the report.

No network. Read-only. Temp copies of credential DBs are created `0600` (`shutil.copyfile` + explicit `os.chmod` — **not** `copy2`, whose `copystat` would replay the source's `0644`) and removed in `__exit__`, on an exception inside `__enter__`, at `atexit`, and on `SIGINT`/`SIGTERM`/`SIGHUP`. Report files written with `--out` / `--json` are created `0600` and moved into place with `os.replace()`.

SQLite DBs are copied and opened `mode=ro`. **`immutable=1` was removed in v0.2.0** — it tells SQLite the file cannot change, so it skips WAL recovery entirely and silently under-counts the most recent logins and cookies. See "What v0.1.0 got wrong" below.

---

## Install & run

No dependencies beyond the Python 3.11+ standard library (`sqlite3`, `gzip`, `re`, `argparse`, `pathlib`). One data file: `bip39.txt`.

```bash
chmod +x exposurescan.py

# Audit home dir, print markdown to stdout
./exposurescan.py

# Scope the .env / project scan to a subtree
./exposurescan.py --target ~/dev

# Also write a values-free JSON sidecar (for week-over-week diffing) and a markdown file
# NOTE: not /tmp. A report is a map of every credential surface on the box.
./exposurescan.py --target ~/dev \
  --json ~/.local/state/exposurescan/exposure.json \
  --out  ~/.local/state/exposurescan/exposure.md

# Add the TCC grant inventory (read-only; needs no new permission)
./exposurescan.py --tcc

# Skip a surface
./exposurescan.py --no-notes --no-browser --no-dev-creds
```

**Exit codes** (useful in launchd / CI): `0` clean-ish, `1` a P1 was found, `3` a P0 was found.

**Optional keychain item count.** By default the tool reports `login.keychain-db` presence, size and lock state and does **not** count its items, because `security dump-keychain` can raise a GUI unlock prompt — this tool will not make your Mac ask you for your keychain password. Set `EXPOSURESCAN_KEYCHAIN_COUNT=1` if you want the count and accept the possible prompt.

---

## Permissions (and why an audit tool asks for them)

Reading `~/Library/Group Containers/group.com.apple.notes/` (Apple Notes) and the browser profile directories requires **Full Disk Access** for the terminal you run this in:

> System Settings → Privacy & Security → Full Disk Access → add your terminal (Terminal / iTerm / Ghostty).

Without it, those surfaces are reported as `skipped (no access)` — the run still completes. The tool only ever **reads**; it never writes to those locations and never touches the network.

> macOS TCC note: reads can succeed at session start and then `EPERM` mid-session if Full Disk Access wasn't granted to the *responsible* binary. If a surface flips to "no access" mid-run, grant FDA and relaunch the terminal.

---

## Run it weekly (optional)

Drop a `launchd` agent that runs the scan and diffs the JSON sidecar week-over-week (count deltas only — no values ever leave the box). Pattern matches the `com.daredev.*` jobs:

```bash
./exposurescan.py --target "$HOME/dev" --json "$HOME/.local/state/exposurescan-$(date +%Y-%m-%d).json"
```

Compare this week's `tier_counts` / finding `id`s against last week's. A new P0/P1 `id` is the signal to alert.

---

## What v0.1.0 got wrong

v0.1.0's README claimed ExposureScan was *"architecturally incapable of emitting a secret value"* and that *"we report a note's title + category only — the matched substring is never emitted."* A red-team pass reproduced **seven** counterexamples against the shipped module. Publishing them is the point: a security tool that hides its own misses is worse than one that never made the claim.

| # | What leaked | Why | Fixed by |
|---|-------------|-----|----------|
| 1 | A 12-word **BIP-39 seed phrase** passed through `redact()` **100% byte-identical** | `_VALUE_SHAPE` needs one unbroken 20+ char run; a mnemonic is short lowercase dictionary words separated by spaces | ship the real 2048-word wordlist; ≥6 consecutive tokens → `<redacted seed-phrase>` |
| 2 | `wifi password = correct horse battery staple` → `wifi password = <redacted> horse battery staple` — three of four words survived, and the literal `<redacted>` made the line *read as sanitized* | `_ASSIGNMENT` was `(=)\s*\S+`, which stops at the first space | `(=)\s*.+$` with `re.M` |
| 3 | `PIN 4821 / password hunter2 / 2FA backup 731-449` passed unchanged | no rule covered short, low-entropy secrets | keyword-proximity rule: redact to end of line |
| 4 | `postgres://admin:hunter2@db.internal:5432/prod` passed unchanged | no `=`, no 20-char run | URI-userinfo rule |
| 5 | **Apple Notes emitted the note title verbatim.** `ZTITLE1` is derived from the note's **first line**, so for the one user this surface exists for the "title" *is* the seed phrase. The `[:60]` slice was formatting, not a security control | the invariant was written for a mental model of Notes that macOS does not implement | emit `Note #pk (title N chars, modified …)` — never the title |
| 6 | A **filename** containing a Luhn-valid card number, expiry and CVV was reproduced verbatim into stdout, the `--out` markdown *and* the `--json` sidecar — annotated `credit-card: 1` | filenames were interpolated straight into `Finding.name` and `Finding.location` | screen filenames through `PII_PATTERNS`; withhold + hash |
| 7 | **ANSI escapes and markdown passed through untouched.** A title containing a newline plus `### P0 - INJECTED FINDING` forged a finding in the rendered report | `redact()` never touched control characters or structure | control-char scrub, single-line collapse, `markdown_safe()` |

Two further defects found while writing the regression suite, not in the original report:

- **Detection was as broken as redaction.** `SENSITIVE_CONTENT_CATEGORIES["seed-phrase"]` only ever matched the *label* (`"seed phrase"`, `"recovery phrase"`, `"mnemonic"`). A note containing **nothing but the twelve words** — the actual catastrophic case — was never flagged at all. Now checked against the wordlist.
- **A file whose *name* was the PII but whose contents were clean was never scanned.** The PII walk only ever looked at file contents.

And four hardening bugs that were not leaks but were real:

- `shutil.copy2`'s `copystat` replayed the source's `0644` onto the temp copy of the browser's `Login Data`, leaving a **world-readable plaintext copy of the credential DB** in `TMPDIR` for the duration of the scan. Now `copyfile` + explicit `chmod 0600`.
- A TCC `PermissionError` (or `Ctrl-C`) mid-copy **orphaned a partial credential DB** in `TMPDIR` with no process left to clean it up. Now cleaned in `__enter__`'s `except`, at `atexit`, and on `SIGINT`/`SIGTERM`/`SIGHUP`.
- The code copied the `-wal` sidecar *and* opened `mode=ro&immutable=1`. `immutable=1` makes SQLite **skip WAL recovery entirely**. Measured on a DB with 50 rows parked in an uncheckpointed WAL: `immutable=1` reported `no such table`; plain `mode=ro` reported the correct 50. The tool was silently **under-counting the most recent logins and cookies in a report whose entire output is a risk score.** `immutable=1` is gone; the `-wal` copy stays. (Cost: SQLite may create a `-shm` and replay the WAL — inside our own temp dir, on our own `0600` copy, never on the user's file.)
- The README's own example wrote the JSON sidecar to `/tmp/exposure.json`. A world-readable map of every credential surface on the machine, in a world-readable directory, demonstrated by the docs. Examples now use `~/.local/state/exposurescan/`, and both output files are written `0600` via `os.open` + `os.replace`.

**The lesson, stated plainly:** v0.1.0 had a *passing* unit test on `redact()` and shipped six leaks anyway, because the leaks lived in the f-strings **between the scanner and the chokepoint**, not in the chokepoint. A unit test on `redact()` proves `redact()` works. Only an **end-to-end** test — real scanner → real renderer → real sidecar → assert the secret is absent from the artifact — proves the invariant. `tests/test_invariant.py` is built around that.

---

## Honest limits

- It tells you your blast radius and raises your literacy. **It cannot stop you** from pasting a `curl … | bash` into Terminal, typing your password into a fake `osascript` dialog, or clicking *Allow* on a TCC prompt. For execute-time blocking pair it with **ShellGuard** (zsh accept-line guard) and **ClipSentinel** (clipboard early-warning) from this kit.
- It is intentionally **not** a value extractor. If you want the values, you already have them (they're your files) — this tool's whole reason for existing is to give you the inventory **without** ever materializing them.
- Regex-based PII detection has false positives; that's why card numbers are Luhn-validated and counts (not instances) are reported. Treat counts as a "how exposed am I" signal, not a forensic ground truth.
- **`redact()` deliberately over-fires.** The keyword-proximity rule truncates a line to `<redacted>` after any sensitive keyword followed by `:`/`=`/space. Sometimes that eats context you wanted. Over-redaction is a readability bug; under-redaction is the bug this tool exists to not have. When the tool's own generated text collides with the rule, the text is reworded — the rule is not weakened.
- **Generated metadata bypasses `redact()` on purpose.** Value *shapes* (`"46 chars, high-entropy, Postgres connection URI"`) are built from integers and a fixed label vocabulary, so they are value-free by construction and travel in `Finding.shape`, filtered through a conservative-alphabet `safe_shape()` instead. That field is the one place a future leak could be introduced, so it has its own tests.
- The seed-phrase rule covers the **English** BIP-39 wordlist only. Other BIP-39 languages, Electrum seeds, and SLIP-39 shares are not detected.
- **Safari saved logins are not counted, and the report says so instead of guessing.** Safari does not keep them in a readable file — they are login-keychain items, and counting them means `security` calls that can raise a prompt. The report names the surface, points at the keychain finding, and refuses to invent a number. Firefox *is* counted, from `logins.json` row counts and `cookies.sqlite`; `key4.db` is never opened and `encryptedUsername` / `encryptedPassword` are never read.
- **A long filename can be over-redacted.** `redact()` collapses any 20+ character run in the token alphabet, so an SSH key named `id_ed25519_example_locked` (25 chars) renders as `<redacted>: encrypted private key` while `id_ed25519_NEW` survives intact. The finding is still findable — location, key type, mode and size are all preserved, and the finding `id` is stable for diffing — but the name is gone. This is the documented tradeoff, not a bug to file: when the tool's own generated text collides with the rule, **the text gets reworded and the rule does not get weakened**, and a filename is exactly the field the v0.1.0 credit-card-filename leak taught us not to trust.
- **`--tcc` reports grants, not code identity.** It does not validate each row's `csreq` code requirement, so a client identifier that has been squatted or a stale row for an uninstalled app is reported as written in the database. The cross-check that matters — the tool's rows against a hand-run `sqlite3` query over both `TCC.db` files — is part of the release checklist and matched exactly (64/64, no invented rows, no missed rows) on the development machine.
- **`--tcc` is not a hardening baseline and will never become one.** See the exclusion note above: FileVault, firewall, updates, sudoers and the CIS sweep belong to mSCP and Pareto Security.

---

## Files

| File | Purpose |
|------|---------|
| `exposurescan.py` | the CLI (executable, stdlib-only) |
| `sample-report.md` | example output with **fake placeholder data only** — generated, not hand-written |
| `bip39.txt` | the 2048-word BIP-39 English wordlist (verbatim, unmodified) |
| `tests/test_redaction.py` | v0.1.0 unit tests on the `redact()` chokepoint + the `.env` surface |
| `tests/test_invariant.py` | v0.2.0 regression suite — one test per verified leak, incl. the **end-to-end** Notes and PII-filename tests |
| `tests/test_dev_credentials.py` | v0.2.0 regression suite for the dev-credential, wallet and TCC surfaces, incl. their leak tests |
| `tests/make-sample-report.py` | regenerates `sample-report.md` by running the **real** scanner against a synthetic `$HOME`; `--check` fails if it is stale |
| `README.md` | this file |

## Tests

```bash
cd exposurescan
python3 -m unittest discover -s tests          # 72 tests
python3 tests/make-sample-report.py --check    # sample-report.md is not stale
```

**A new surface without a leak test does not ship.** Every v0.2.0 surface has a fixture that plants synthetic key material and tokens in a synthetic `$HOME`, runs the real scanner → real renderer → real JSON sidecar, and asserts **zero** occurrences of that material in either artifact. The SSH fixture generates one passphrase-less and one encrypted key with `ssh-keygen` and asserts the plaintext key is P0 and the encrypted one is not. The TCC fixture is a `TCC.db` with a known row set, asserting Terminal-with-Accessibility is P0, an ordinary GUI app with Photos access is not, and a denied row is never reported as a grant.
