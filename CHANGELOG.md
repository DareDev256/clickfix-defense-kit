# Changelog

All notable changes to the ClickFix Defense Kit are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
