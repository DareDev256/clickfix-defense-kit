# ExposureScan

**Local secret + PII blast-radius self-audit for macOS — names and counts only, never values.**

Part of the open-source [ClickFix Defense Kit](../).

---

## What it answers

> *If an infostealer (AMOS / Atomic / Poseidon) ran on my Mac right now, what would it walk away with — and what could the attacker pivot into?*

ExposureScan inventories the four credential/PII surfaces a macOS infostealer targets and prints a **prioritized blast-radius report** ranked by pivot value (P0 → P3), not raw count. It is the productized version of the manual "what's sitting on my disk" incident scan.

It scans:

| # | Surface | What it reports |
|---|---------|-----------------|
| a | **Chrome / Brave / Edge / Chromium saved logins** (`Login Data` SQLite) | per-domain count of saved logins, whether a username exists, whether a password is present — **never the password** |
| b | **Apple Notes** (`NoteStore.sqlite` → gzip `ZICNOTEDATA.ZDATA`) | note **title** + matched **category** (password / seed-phrase / api-key / PIN / SIN…) — **never the matched text** |
| c | **`.env` files** under a target dir | **KEY NAMES only** (left of `=`), line number, value *shape* (length / entropy class) — **never the value** |
| d | **`~/.secrets`** | file **names** + sizes + permissions (the filename *is* the credential name) |
| e | **PII markers** in Desktop / Documents / Downloads | **counts per type** (email, phone, SIN/SSN, Luhn-validated card, DOB) — **never the instance** |

---

## The privacy promise (this is the product, not a flag)

**Secret values never leave your machine — they never even enter the program's output.**

This is enforced by architecture, not by a disabled `--show-data` flag:

- **Browser passwords** — we `SELECT origin_url, username_value, length(password_value)` only. We **never** select, read, or decrypt `password_value`. Chrome's macOS passwords are AES-128-CBC under a Keychain key; **this tool refuses to decrypt by design** — decrypting is exactly what a stealer does.
- **`.env` values** — we split on the first `=`, keep the **key name**, measure the value's length/entropy to score risk, then **discard the value immediately**. It is never stored or printed.
- **Apple Notes** — we report a note's **title + category** only. The matched substring is never emitted.
- **`redact()` chokepoint** — every user-facing string (markdown and JSON) passes through a final `redact()` funnel that strips anything value-shaped (long high-entropy runs, anything right of `=`). Even an accidental leak in a path or title cannot escape. This invariant is covered by `tests/test_redaction.py`.

No network. No writes outside a temp dir that is deleted in a `finally`. SQLite DBs are copied and opened `mode=ro&immutable=1` so a running browser/Notes.app can't trigger `database is locked` and we can never mutate the original.

---

## Install & run

No dependencies beyond the Python 3.11+ standard library (`sqlite3`, `gzip`, `re`, `argparse`, `pathlib`).

```bash
chmod +x exposurescan.py

# Audit home dir, print markdown to stdout
./exposurescan.py

# Scope the .env / project scan to a subtree
./exposurescan.py --target ~/dev

# Also write a values-free JSON sidecar (for week-over-week diffing) and a markdown file
./exposurescan.py --target ~/dev --json /tmp/exposure.json --out /tmp/exposure.md

# Skip a surface
./exposurescan.py --no-notes --no-browser
```

**Exit codes** (useful in launchd / CI): `0` clean-ish, `1` a P1 was found, `3` a P0 was found.

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

## Honest limits

- It tells you your blast radius and raises your literacy. **It cannot stop you** from pasting a `curl … | bash` into Terminal, typing your password into a fake `osascript` dialog, or clicking *Allow* on a TCC prompt. For execute-time blocking pair it with **ShellGuard** (zsh accept-line guard) and **ClipSentinel** (clipboard early-warning) from this kit.
- It is intentionally **not** a value extractor. If you want the values, you already have them (they're your files) — this tool's whole reason for existing is to give you the inventory **without** ever materializing them.
- Regex-based PII detection has false positives; that's why card numbers are Luhn-validated and counts (not instances) are reported. Treat counts as a "how exposed am I" signal, not a forensic ground truth.

---

## Files

| File | Purpose |
|------|---------|
| `exposurescan.py` | the CLI (executable, stdlib-only) |
| `sample-report.md` | example output with **fake placeholder data only** |
| `tests/test_redaction.py` | CI test asserting no value-shaped string escapes |
| `README.md` | this file |
