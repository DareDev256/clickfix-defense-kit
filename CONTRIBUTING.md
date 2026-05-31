# Contributing

Thanks for wanting to help harden the ClickFix Defense Kit. This is a small,
defensive-use-only project — contributions are welcome, with a few firm rules
that exist because this is a *security* repo.

## Ground rules (non-negotiable)

1. **Defensive only.** No exploits, no offensive tooling, no "for educational
   purposes" payloads. If a change makes the kit more useful to an attacker than
   to a defender, it won't be merged.
2. **No real secrets, tokens, keys, PII, or host data — ever.** All fixtures and
   examples must be synthetic placeholders (`PLACEHOLDER` / `EXAMPLE` / `.invalid`
   / `.test`). No real paths (`/Users/<you>`), real `~/.secrets` filenames,
   webhook URLs, IPs, hostnames, or personal/client data. Use `/Users/example`
   and placeholder tokens.
3. **Preserve ExposureScan's value-absent invariant.** Any change touching
   ExposureScan must keep `exposurescan/tests/test_redaction.py` passing: a
   secret value must never appear in any output artifact (markdown or JSON). Add a
   test if you add a surface.
4. **Ship token-MINTING code, never minted tokens.** Canary contributions must not
   include any real canarytoken or live webhook.
5. **No `curl | bash` installers.** Installers stay as readable local scripts.
6. **License hygiene.** Apache 2.0. Do **not** copy AGPL/GPL code into the tree
   (no vendoring TruffleHog). Shelling out to an external tool is fine.

## Before you open a PR

- Run `python3 -m unittest discover -s exposurescan/tests` and make sure it's green.
- For ShellGuard changes, update and verify `shellguard/test-cases.md` (the
  safe-vs-dangerous matrix) so you don't regress false-positive behavior.
- Run a secret scan over your diff (e.g. `gitleaks detect`, `trufflehog
  filesystem .`) and confirm nothing leaked — fixtures and example output are the
  highest-risk surface in a secret-scanner project.
- Keep each tool independent: a change to one tool shouldn't require another.
- Be honest in docs. This kit's credibility comes from *not* overclaiming. If a
  tool defers to prior art (Objective-See, Thinkst), say so.

## Reporting a vulnerability

See [SECURITY.md](./SECURITY.md). Report security issues **privately first** and
never paste real secrets or scan output into a public issue.

## Style

- Shell: POSIX-ish bash/zsh, `set -euo pipefail`, no external deps unless a tool
  already requires them.
- Python: 3.11+ standard library only for ExposureScan.
- Keep it small, commented, and readable — people are being asked to read this
  source before granting it access. Earn that trust.
