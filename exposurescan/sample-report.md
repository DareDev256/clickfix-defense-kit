# ExposureScan — Blast-Radius Self-Audit

_Generated 2026-01-01 00:00 UTC · scope: `/Users/PLACEHOLDER/dev`_

> **Names and counts only.** Secret values were never read, decrypted, stored, or printed. This is a defensive self-audit, not an extractor.

<!--
  NOTE: every entry below is FAKE / PLACEHOLDER data for documentation only.
  No real domains, keys, files, or PII. This is what real output LOOKS like.
-->

## Summary

| Tier | Severity | Findings | What it means |
|------|----------|----------|----------------|
| P0 | CRITICAL | 3 | Live keys / wallet seeds in plaintext — disk access = full pivot |
| P1 | HIGH | 4 | Account-takeover credentials (browser logins, secret files) |
| P2 | MEDIUM | 2 | Session cookies / reusable PII clusters |
| P3 | LOW | 2 | Advisory exposure (PII, trusted-host logins) |

## P0 — CRITICAL

_Live keys / wallet seeds in plaintext — disk access = full pivot_

### EXAMPLE_DB_URL (value: 64 chars, high-entropy, Postgres connection URI)
- **Surface:** env-file
- **Category:** env-key
- **Location:** /Users/PLACEHOLDER/dev/example-app/.env
- **Detail:** line 7
- **Attacker pivots into:** an attacker with disk access reads this plaintext key and pivots into the live service it unlocks
- **Remediation:** Move secrets out of plaintext .env into a secrets manager / Keychain / 1Password; rotate this key; ensure .env is gitignored; chmod 600.

### EXAMPLE_AWS_ACCESS_KEY_ID (value: 20 chars, AWS access key id)
- **Surface:** env-file
- **Category:** env-key
- **Location:** /Users/PLACEHOLDER/dev/example-app/.env
- **Detail:** line 12
- **Attacker pivots into:** an attacker with disk access reads this plaintext key and pivots into the live service it unlocks
- **Remediation:** Move secrets out of plaintext .env into a secrets manager / Keychain / 1Password; rotate this key; ensure .env is gitignored; chmod 600.

### Note 'Wallet backup' — seed-phrase
- **Surface:** apple-notes
- **Category:** note-secret
- **Location:** Apple Notes
- **Detail:** matched categories: seed-phrase
- **Attacker pivots into:** wallet drain / irreversible crypto theft
- **Remediation:** Move secrets/seed phrases out of plain Notes into a password manager or a hardware-backed store; lock the note (App-level encryption) at minimum; delete if no longer needed.

## P1 — HIGH

_Account-takeover credentials (browser logins, secret files)_

### example-bank.test — 1 saved login(s)
- **Surface:** browser-login
- **Category:** financial-or-identity-login
- **Location:** Chrome/Default
- **Detail:** profile Chrome/Default; usernames present: yes
- **Attacker pivots into:** account takeover of a financial/identity/registrar account
- **Remediation:** Stop saving passwords in the browser; migrate to a password manager (1Password/Keychain). Enable the OS-level encryption prompt. Remove stale entries you no longer use.

### example-registrar.test — 1 saved login(s)
- **Surface:** browser-login
- **Category:** financial-or-identity-login
- **Location:** Chrome/Default
- **Detail:** profile Chrome/Default; usernames present: yes
- **Attacker pivots into:** account takeover of a financial/identity/registrar account
- **Remediation:** Stop saving passwords in the browser; migrate to a password manager (1Password/Keychain). Enable the OS-level encryption prompt. Remove stale entries you no longer use.

### example-api-key (107 bytes, chmod 644 — GROUP/OTHER READABLE)
- **Surface:** dot-secrets
- **Category:** flat-secret-file
- **Location:** ~/.secrets
- **Detail:** single-value secret file (name = credential)
- **Attacker pivots into:** direct read of a live credential by anyone with disk access
- **Remediation:** chmod 600 each file; consider moving into the macOS Keychain; rotate any secret you suspect was exposed.

### .env: 5/9 sensitive key(s)
- **Surface:** env-file
- **Category:** env-file-summary
- **Location:** /Users/PLACEHOLDER/dev/example-app/.env
- **Detail:** AWS access key id, Postgres connection URI
- **Attacker pivots into:** bulk credential exposure for one project
- **Remediation:** chmod 600; gitignore; migrate to a secrets manager.

## P2 — MEDIUM

_Session cookies / reusable PII clusters_

### 4 high-value session-cookie host(s)
- **Surface:** browser-login
- **Category:** session-cookie
- **Location:** Chrome/Default
- **Detail:** hosts: example-bank.test, example-mail.test, github.com, example-cloud.test
- **Attacker pivots into:** session hijack — bypasses password + MFA while cookie is valid
- **Remediation:** Sign out of sensitive sites when done; clear cookies regularly; never paste a curl|bash that could read this DB.

### tax-export-PLACEHOLDER.csv — sin-ssn: 2, email: 1
- **Surface:** pii
- **Category:** pii-file
- **Location:** Documents
- **Detail:** sin-ssn: 2, email: 1
- **Attacker pivots into:** identity theft / financial fraud
- **Remediation:** Encrypt or delete this file; remove SIN/card data from cleartext.

## P3 — LOW

_Advisory exposure (PII, trusted-host logins)_

### 37 PII marker(s) across Desktop/Documents/Downloads
- **Surface:** pii
- **Category:** pii-aggregate
- **Location:** Desktop/Documents/Downloads
- **Detail:** email: 28, phone-na: 6, dob: 3
- **Attacker pivots into:** identity theft / targeted social engineering (no direct system pivot)
- **Remediation:** Move documents containing SIN/SSN/card numbers into an encrypted disk image or password manager; delete stale exports; empty Downloads of old statements.

### raw.githubusercontent.com — 1 saved login(s)
- **Surface:** browser-login
- **Category:** saved-login
- **Location:** Chrome/Default
- **Detail:** profile Chrome/Default; usernames present: no
- **Attacker pivots into:** credential reuse / lateral account takeover
- **Remediation:** Stop saving passwords in the browser; migrate to a password manager (1Password/Keychain). Enable the OS-level encryption prompt. Remove stale entries you no longer use.

## Scan notes (skips & access)

- Apple Notes: 2 locked/encrypted note(s) skipped (cannot read).
- Browser Edge: no Chromium-family profiles found.

## Remediation checklist (do these in order)

1. **P0 first** — Move every plaintext live key (AWS/Stripe/Anthropic/DB URI), private key, and wallet seed out of `.env`/`~/.secrets`/Notes into the macOS Keychain or a password manager, then **rotate** them. `chmod 700 ~/.secrets`, `chmod 600` each secret file.
2. **P1** — Stop saving passwords in the browser for financial/email/registrar origins; migrate to a password manager; enable OS-level encryption.
3. **P2** — Sign out of sensitive sites to kill session cookies; encrypt or delete documents containing SIN/SSN/card numbers.
4. **P3** — Clear stale PII exports from Downloads; review trusted-host logins.

> This audit shrinks the blast radius. It does **not** stop you from pasting a `curl … | bash` into Terminal or typing your password into a fake dialog. Pair it with ShellGuard (zsh execute-time guard) and ClipSentinel (clipboard early-warning) from this kit.
