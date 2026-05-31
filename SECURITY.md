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
