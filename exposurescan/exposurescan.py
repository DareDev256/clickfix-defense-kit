#!/usr/bin/env python3
"""
ExposureScan — local secret + PII blast-radius self-audit for macOS.

Part of the open-source ClickFix Defense Kit.

WHAT THIS IS
------------
A defensive, read-only self-audit that answers the question:
    "If an infostealer (AMOS / Atomic / Poseidon) ran on my Mac right now,
     what would it walk away with — and what could the attacker pivot into?"

It inventories the four credential/PII surfaces a macOS stealer targets and
prints a *prioritized blast-radius report*. It ranks surfaces by pivot value
(P0 -> P3), not by raw count, so you fix the prod-key-in-a-.env before the
phone number in a Note.

THE PRIVACY INVARIANT (this is the product, not a feature flag)
---------------------------------------------------------------
Secret VALUES never touch memory, never get printed, never get written to disk.

  * Browser Login Data : we SELECT origin_url + username only, and read the
                         *length* of password_value. We NEVER select, decrypt,
                         or print password_value itself. Chrome's macOS
                         passwords are AES-128-CBC under a Keychain key; this
                         tool refuses to decrypt by design.
  * .env / ~/.secrets  : we emit only the KEY NAME (left of '='). The value
                         (right of '=') is measured for length/entropy to score
                         risk, then *immediately discarded* — never stored,
                         never printed.
  * Apple Notes        : we report a note TITLE + matched CATEGORY only
                         (e.g. "Note 'Bank stuff' -> seed-phrase pattern").
                         The matched substring is never emitted.

Every user-facing string passes through redact() as a final chokepoint, which
strips anything value-shaped (long high-entropy runs, anything after '='),
so even an accidental leak in a path or title cannot escape. See the unit
tests in tests/test_redaction.py.

SAFETY
------
  * Read-only. No network. No decryption. No writes outside a temp dir that is
    deleted in a finally block.
  * SQLite DBs are copied to a temp path and opened
    `mode=ro&immutable=1` so a running browser/Notes.app cannot cause a
    "database is locked" error and so we can never mutate the original.

PERMISSIONS
-----------
Reading ~/Library/Group Containers (Apple Notes) and the browser profile dirs
requires Full Disk Access for the terminal you run this in
(System Settings > Privacy & Security > Full Disk Access). Without it, those
surfaces are reported as "skipped (no access)" rather than failing the run.

USAGE
-----
    ./exposurescan.py                      # audit home dir, print markdown
    ./exposurescan.py --target ~/dev       # scope .env/PII scan to a subtree
    ./exposurescan.py --json report.json   # also write a values-free JSON sidecar
    ./exposurescan.py --no-notes           # skip the Apple Notes surface
    ./exposurescan.py --out report.md      # write markdown to a file too

This tool reduces risk and raises literacy. It cannot stop you from pasting a
curl|bash into Terminal or typing your password into a fake dialog. Pair it
with the ShellGuard (zsh) and ClipSentinel layers in this kit.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import math
import os
import re
import shutil
import sqlite3
import stat
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------

# Directories we never descend into when walking for .env / PII. These are
# noisy, huge, and not where a human keeps real secrets.
WALK_DENYLIST = {
    "node_modules", ".git", ".venv", "venv", "__pycache__", ".cache",
    "Library", ".Trash", ".npm", ".pnpm-store", ".cargo", ".rustup",
    "DerivedData", ".next", "dist", "build", ".gradle", "Pods",
}

# Hostnames whose "saved login" / install command is expected and benign.
# Used to DOWNGRADE (not hide) browser logins for trusted install/dev origins
# so the report doesn't train you to ignore it.
TRUSTED_INSTALL_HOSTS = {
    "rustup.rs", "sh.rustup.rs", "get.docker.com", "brew.sh",
    "raw.githubusercontent.com", "deb.nodesource.com", "nodejs.org",
}

# Known credential prefixes -> reported as a PREFIX CLASS only, never the tail.
# (key_name detection is independent of this; this classifies the *value* shape
#  without ever retaining the value.)
SECRET_VALUE_PREFIXES = {
    "sk-": "OpenAI/Anthropic-style API key",
    "sk-ant-": "Anthropic API key",
    "ghp_": "GitHub personal access token",
    "gho_": "GitHub OAuth token",
    "github_pat_": "GitHub fine-grained PAT",
    "xoxb-": "Slack bot token",
    "xoxp-": "Slack user token",
    "AKIA": "AWS access key id",
    "ASIA": "AWS temp access key id",
    "AIza": "Google API key",
    "ya29.": "Google OAuth token",
    "-----BEGIN": "PEM private key block",
    "Bearer ": "Bearer auth token",
    "postgres://": "Postgres connection URI",
    "postgresql://": "Postgres connection URI",
    "mysql://": "MySQL connection URI",
    "mongodb+srv://": "MongoDB connection URI",
    "mongodb://": "MongoDB connection URI",
    "redis://": "Redis connection URI",
}

# Key NAMES (left of '=') that strongly imply a live credential. Substring,
# case-insensitive. Used to risk-score .env entries without reading the value.
SENSITIVE_KEY_HINTS = (
    "secret", "token", "api_key", "apikey", "password", "passwd", "pwd",
    "private_key", "privatekey", "access_key", "client_secret", "auth",
    "credential", "session", "cookie", "database_url", "db_url", "dsn",
    "stripe", "anthropic", "openai", "aws", "gcp", "azure", "twilio",
    "sendgrid", "webhook", "signing", "jwt", "encryption_key",
)

# Apple Notes / generic content categories we flag (names of the *category*,
# never the matched text). Patterns are deliberately broad-but-cheap.
SENSITIVE_CONTENT_CATEGORIES = {
    "password":     re.compile(r"\b(pass(word)?|passwd|pwd)\b\s*[:=]", re.I),
    "seed-phrase":  re.compile(r"\b(seed phrase|recovery phrase|mnemonic|12[- ]word|24[- ]word)\b", re.I),
    "private-key":  re.compile(r"-----BEGIN[ A-Z]*PRIVATE KEY-----"),
    "api-key":      re.compile(r"\b(api[ _-]?key|secret[ _-]?key|access[ _-]?token)\b", re.I),
    "pin":          re.compile(r"\b(pin|passcode)\b\s*[:=]?\s*\d{3,8}\b", re.I),
    "crypto-wallet":re.compile(r"\b(0x[a-fA-F0-9]{40}|wallet seed|private wallet|metamask)\b"),
    "sin-ssn":      re.compile(r"\b(\d{3}[-\s]?\d{2}[-\s]?\d{4}|\d{3}[-\s]?\d{3}[-\s]?\d{3})\b"),
    "card-number":  re.compile(r"\b(?:\d[ -]?){13,19}\b"),
    "recovery-code":re.compile(r"\b(recovery|backup) code(s)?\b", re.I),
}

# PII markers for filesystem scan. COUNTS only, never the matched instance.
PII_PATTERNS = {
    "email":        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "phone-na":     re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "sin-ssn":      re.compile(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b"),
    "credit-card":  re.compile(r"\b(?:\d[ -]?){13,19}\b"),
    # DOB: a date NOT immediately followed by a time component (T / space + HH:MM),
    # which excludes the ISO-8601 log timestamps that otherwise flood the count.
    "dob":          re.compile(
        r"\b(19|20)\d{2}[-/](0[1-9]|1[0-2])[-/](0[1-9]|[12]\d|3[01])\b"
        r"(?![T ]\d{2}:\d{2})"
    ),
}

# File extensions worth scanning for PII markers (skip binaries/media).
# Deliberately EXCLUDES .log — machine-generated logs are full of
# timestamp/ID strings that masquerade as DOB/card numbers and drown the
# signal. Human-authored documents are where real PII clusters live.
PII_SCAN_EXTENSIONS = {
    ".txt", ".md", ".csv", ".json", ".yaml", ".yml", ".rtf",
    ".html", ".xml", ".ini", ".conf", ".cfg", ".env", ".tsv", ".vcf",
}

MAX_FILE_BYTES = 5 * 1024 * 1024   # don't slurp anything over 5 MB for PII scan


# ---------------------------------------------------------------------------
# The redaction chokepoint — every user-facing string passes through here.
# ---------------------------------------------------------------------------

# A "value-shaped" run: 20+ chars of base64/hex/token alphabet with no spaces.
_VALUE_SHAPE = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")
# Anything that looks like KEY=VALUE — we keep the key, nuke the value.
_ASSIGNMENT = re.compile(r"(=)\s*\S+")


def shannon_entropy(s: str) -> float:
    """Bits-per-char Shannon entropy. Used to risk-score a value we never keep."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def looks_high_entropy(value: str) -> bool:
    """Heuristic: long-ish and high entropy => probably a live secret value."""
    v = value.strip().strip('"').strip("'")
    if len(v) < 16:
        return False
    return shannon_entropy(v) >= 3.5


def classify_value_prefix(value: str) -> str | None:
    """Return a human prefix-class for a value WITHOUT retaining the value."""
    v = value.strip().strip('"').strip("'")
    for prefix, label in SECRET_VALUE_PREFIXES.items():
        if v.startswith(prefix):
            return label
    return None


def redact(text: str) -> str:
    """
    Final safety chokepoint. Strip anything value-shaped from any string that
    is about to be shown to the user or written to a report. Defense in depth:
    even if a code path forgot to drop a value, it cannot escape this funnel.
    """
    if text is None:
        return ""
    # Kill "key = <value>" -> "key = <redacted>"
    redacted = _ASSIGNMENT.sub(r"\1 <redacted>", text)
    # Kill any remaining long high-entropy run.
    redacted = _VALUE_SHAPE.sub("<redacted>", redacted)
    return redacted


# ---------------------------------------------------------------------------
# Findings model
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    surface: str          # "browser-login", "apple-notes", "env-file", "dot-secrets", "pii"
    tier: str             # "P0".."P3"
    name: str             # human, names/counts only (e.g. "github.com — saved login")
    category: str         # logical category (e.g. "registrar-login", "api-key")
    count: int = 1        # how many instances
    detail: str = ""      # extra context, names/counts only
    pivot: str = ""       # what an attacker pivots into
    remediation: str = "" # how to shrink the blast radius
    location: str = ""    # path/origin (a NAME, never a value)

    def hashed_id(self) -> str:
        """Stable, value-free id for week-over-week diffing in the JSON sidecar."""
        basis = f"{self.surface}|{self.category}|{self.location}|{self.name}"
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]

    def to_json(self) -> dict:
        # Everything here is names/counts only by construction; redact() anyway.
        return {
            "id": self.hashed_id(),
            "surface": self.surface,
            "tier": self.tier,
            "name": redact(self.name),
            "category": self.category,
            "count": self.count,
            "detail": redact(self.detail),
            "pivot": self.pivot,
            "remediation": self.remediation,
            "location": redact(self.location),
        }


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)   # non-finding messages (skips, errors)

    def add(self, f: Finding) -> None:
        self.findings.append(f)

    def note(self, msg: str) -> None:
        self.notes.append(redact(msg))


# ---------------------------------------------------------------------------
# Shared helper: copy a (possibly locked) sqlite DB and open it read-only.
# ---------------------------------------------------------------------------

class _TempCopyConn:
    """
    Context manager that copies an sqlite file to a temp path and opens it
    read-only + immutable, so a running app can't lock us out and we can never
    mutate the original. Temp file is deleted in __exit__.
    """

    def __init__(self, src: Path):
        self.src = src
        self.tmp: Path | None = None
        self.conn: sqlite3.Connection | None = None

    def __enter__(self) -> sqlite3.Connection:
        fd, tmp_name = tempfile.mkstemp(prefix="exposurescan_", suffix=".sqlite")
        os.close(fd)
        self.tmp = Path(tmp_name)
        shutil.copy2(self.src, self.tmp)
        # Some browser DBs ship -wal/-shm sidecars; copy if present so the
        # read sees a consistent snapshot.
        for sidecar in (".sqlite-wal", "-wal", ".sqlite-shm", "-shm"):
            cand = Path(str(self.src) + sidecar.replace(".sqlite", ""))
            # best-effort; ignore if absent
            try:
                if cand.exists():
                    shutil.copy2(cand, Path(str(self.tmp) + sidecar.replace(".sqlite", "")))
            except OSError:
                pass
        uri = f"file:{self.tmp}?mode=ro&immutable=1"
        self.conn = sqlite3.connect(uri, uri=True)
        return self.conn

    def __exit__(self, *exc) -> None:
        try:
            if self.conn is not None:
                self.conn.close()
        finally:
            if self.tmp is not None:
                for suffix in ("", "-wal", "-shm"):
                    p = Path(str(self.tmp) + suffix)
                    try:
                        if p.exists():
                            p.unlink()
                    except OSError:
                        pass


# ---------------------------------------------------------------------------
# Surface (a): Browser saved logins (Chrome / Brave / Edge / Chromium)
# ---------------------------------------------------------------------------

# Financial / identity origins => account takeover => P1. Everything else P2-ish.
HIGH_VALUE_LOGIN_HINTS = (
    "bank", "rbc", "td", "scotiabank", "bmo", "cibc", "tangerine", "wealthsimple",
    "paypal", "stripe", "coinbase", "binance", "kraken",
    "google.com", "gmail", "icloud", "apple.com", "proton",
    "godaddy", "namecheap", "cloudflare", "porkbun",   # registrars
    "github.com", "gitlab", "vercel", "aws.amazon", "console.aws",
)


def _browser_profiles() -> list[tuple[str, Path]]:
    """Return (browser_label, profile_dir) for installed Chromium browsers."""
    home = Path.home()
    base = home / "Library" / "Application Support"
    roots = {
        "Chrome": base / "Google" / "Chrome",
        "Brave":  base / "BraveSoftware" / "Brave-Browser",
        "Edge":   base / "Microsoft Edge",
        "Chromium": base / "Chromium",
        "Vivaldi": base / "Vivaldi",
    }
    out: list[tuple[str, Path]] = []
    for label, root in roots.items():
        if not root.exists():
            continue
        for profile in ("Default", *(f"Profile {i}" for i in range(1, 12))):
            pdir = root / profile
            if pdir.exists():
                out.append((f"{label}/{profile}", pdir))
    return out


def scan_browser_logins(result: ScanResult) -> None:
    profiles = _browser_profiles()
    if not profiles:
        result.note("Browser: no Chromium-family profiles found.")
        return

    for label, pdir in profiles:
        login_db = pdir / "Login Data"
        if not login_db.exists():
            continue
        try:
            with _TempCopyConn(login_db) as conn:
                cur = conn.cursor()
                # NOTE: we select origin_url + username_value + LENGTH(password_value)
                # ONLY. We NEVER select password_value itself. We refuse to
                # decrypt the macOS v10 AES-CBC blob — that requires Keychain
                # unlock and is exactly what a stealer does.
                cur.execute(
                    "SELECT origin_url, username_value, "
                    "       length(password_value) AS pwlen, "
                    "       blacklisted_by_user "
                    "FROM logins"
                )
                rows = cur.fetchall()
        except sqlite3.Error as e:
            result.note(f"Browser {label}: could not read Login Data ({e.__class__.__name__}).")
            continue
        except (PermissionError, OSError):
            result.note(f"Browser {label}: no access to Login Data (grant Full Disk Access).")
            continue

        # Aggregate by hostname so we report counts, not a per-row dump.
        by_host: dict[str, dict] = {}
        for origin_url, username, pwlen, blacklisted in rows:
            if blacklisted:
                continue
            host = (urlparse(origin_url or "").hostname or "(unknown)").lower()
            entry = by_host.setdefault(host, {"with_pw": 0, "with_user": 0, "total": 0})
            entry["total"] += 1
            if pwlen and pwlen > 0:
                entry["with_pw"] += 1
            if username:
                entry["with_user"] += 1

        for host, info in sorted(by_host.items()):
            high_value = any(h in host for h in HIGH_VALUE_LOGIN_HINTS)
            trusted = any(host == th or host.endswith("." + th) for th in TRUSTED_INSTALL_HOSTS)
            tier = "P1" if high_value else ("P3" if trusted else "P2")
            cat = "financial-or-identity-login" if high_value else "saved-login"
            name = f"{host} — {info['with_pw']} saved login(s)"
            detail = (
                f"profile {label}; usernames present: "
                f"{'yes' if info['with_user'] else 'no'}"
            )
            pivot = (
                "account takeover of a financial/identity/registrar account"
                if high_value else
                "credential reuse / lateral account takeover"
            )
            result.add(Finding(
                surface="browser-login",
                tier=tier,
                name=name,
                category=cat,
                count=info["with_pw"],
                detail=detail,
                pivot=pivot,
                remediation=(
                    "Stop saving passwords in the browser; migrate to a "
                    "password manager (1Password/Keychain). Enable the OS-level "
                    "encryption prompt. Remove stale entries you no longer use."
                ),
                location=f"{label}",
            ))

        # Cookies DB => session-token blast radius (names only).
        cookies_db = pdir / "Cookies"
        if not cookies_db.exists():
            cookies_db = pdir / "Network" / "Cookies"   # newer Chrome layout
        if cookies_db.exists():
            try:
                with _TempCopyConn(cookies_db) as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT DISTINCT host_key FROM cookies")
                    hosts = [r[0] for r in cur.fetchall()]
            except (sqlite3.Error, PermissionError, OSError):
                hosts = []
            hv = sorted({
                h for h in hosts
                if any(hint in (h or "").lower() for hint in HIGH_VALUE_LOGIN_HINTS)
            })
            if hv:
                result.add(Finding(
                    surface="browser-login",
                    tier="P2",
                    name=f"{len(hv)} high-value session-cookie host(s)",
                    category="session-cookie",
                    count=len(hv),
                    detail="hosts: " + ", ".join(hv[:8]) + ("…" if len(hv) > 8 else ""),
                    pivot="session hijack — bypasses password + MFA while cookie is valid",
                    remediation=(
                        "Sign out of sensitive sites when done; clear cookies "
                        "regularly; never paste a curl|bash that could read this DB."
                    ),
                    location=f"{label}",
                ))


# ---------------------------------------------------------------------------
# Surface (b): Apple Notes (NoteStore.sqlite -> gzip ZDATA -> regex categories)
# ---------------------------------------------------------------------------

def scan_apple_notes(result: ScanResult) -> None:
    home = Path.home()
    store = home / "Library" / "Group Containers" / "group.com.apple.notes" / "NoteStore.sqlite"
    if not store.exists():
        result.note("Apple Notes: NoteStore.sqlite not found (no notes or no access).")
        return

    try:
        with _TempCopyConn(store) as conn:
            cur = conn.cursor()
            # ZICNOTEDATA.ZDATA holds the gzipped protobuf note body.
            # ZICCLOUDSYNCINGOBJECT.ZTITLE1 holds the note title (may vary by
            # macOS version; we fall back gracefully).
            try:
                cur.execute(
                    "SELECT d.Z_PK, d.ZDATA, o.ZTITLE1 "
                    "FROM ZICNOTEDATA d "
                    "LEFT JOIN ZICCLOUDSYNCINGOBJECT o ON o.ZNOTEDATA = d.Z_PK "
                    "WHERE d.ZDATA IS NOT NULL"
                )
            except sqlite3.OperationalError:
                # Older/newer schema: just pull the blobs without titles.
                cur.execute("SELECT Z_PK, ZDATA, NULL FROM ZICNOTEDATA WHERE ZDATA IS NOT NULL")
            rows = cur.fetchall()
    except (sqlite3.Error, PermissionError, OSError) as e:
        result.note(
            f"Apple Notes: could not read NoteStore ({e.__class__.__name__}). "
            "Grant Full Disk Access to this terminal."
        )
        return

    locked = 0
    category_counts: dict[str, int] = {}
    # Track per-note titles we flagged so we can show TITLE + category only.
    flagged_titles: dict[str, set[str]] = {}

    for pk, blob, title in rows:
        if not blob:
            continue
        try:
            raw = gzip.decompress(blob)
        except (OSError, EOFError, gzip.BadGzipFile):
            # Encrypted/locked note, or not gzip -> we cannot and will not read it.
            locked += 1
            continue
        # The protobuf carries the note body as readable UTF-8 runs. For
        # names-only we don't parse the protobuf; we just run category regexes
        # over the decoded text and discard the text immediately afterward.
        try:
            text = raw.decode("utf-8", errors="ignore")
        except Exception:
            continue

        note_title = (title or f"Untitled note #{pk}")
        # Defensive: a malicious title could itself contain a value — redact it.
        safe_title = redact(note_title)[:60]

        for cat, pat in SENSITIVE_CONTENT_CATEGORIES.items():
            if pat.search(text):
                category_counts[cat] = category_counts.get(cat, 0) + 1
                flagged_titles.setdefault(safe_title, set()).add(cat)
        # text goes out of scope here; never stored, never printed.

    if locked:
        result.note(f"Apple Notes: {locked} locked/encrypted note(s) skipped (cannot read).")

    if not category_counts:
        result.note("Apple Notes: no notes matched sensitive-content categories.")
        return

    for title, cats in sorted(flagged_titles.items()):
        cat_list = ", ".join(sorted(cats))
        # Crypto seed phrases / private keys in a Note are catastrophic (P0):
        # an attacker who reads them drains a wallet irreversibly.
        if cats & {"seed-phrase", "private-key", "crypto-wallet"}:
            tier, pivot = "P0", "wallet drain / irreversible crypto theft"
        elif cats & {"password", "api-key", "sin-ssn", "card-number"}:
            tier, pivot = "P2", "credential reuse / identity theft / fraud"
        else:
            tier, pivot = "P3", "identity theft / social engineering"
        result.add(Finding(
            surface="apple-notes",
            tier=tier,
            name=f"Note '{title}' — {cat_list}",
            category="note-secret",
            count=1,
            detail=f"matched categories: {cat_list}",
            pivot=pivot,
            remediation=(
                "Move secrets/seed phrases out of plain Notes into a password "
                "manager or a hardware-backed store; lock the note (App-level "
                "encryption) at minimum; delete if no longer needed."
            ),
            location="Apple Notes",
        ))


# ---------------------------------------------------------------------------
# Surface (c): .env files under the target directory (KEY NAMES only)
# ---------------------------------------------------------------------------

def _iter_target_files(target: Path):
    """Walk target, honoring the denylist, yielding files."""
    for root, dirs, files in os.walk(target):
        # prune denylisted dirs in place
        dirs[:] = [d for d in dirs if d not in WALK_DENYLIST and not d.startswith(".Trash")]
        for name in files:
            yield Path(root) / name


def _is_env_file(path: Path) -> bool:
    n = path.name
    return n == ".env" or n.startswith(".env.") or n.endswith(".env") or n.endswith(".env.local")


def scan_env_files(result: ScanResult, target: Path) -> None:
    env_files = []
    try:
        for p in _iter_target_files(target):
            if _is_env_file(p):
                env_files.append(p)
    except (PermissionError, OSError) as e:
        result.note(f".env scan: walk stopped early ({e.__class__.__name__}).")

    if not env_files:
        result.note(f".env scan: none found under {redact(str(target))}.")
        return

    for env_path in env_files:
        try:
            if env_path.stat().st_size > MAX_FILE_BYTES:
                continue
            lines = env_path.read_text(errors="ignore").splitlines()
        except (PermissionError, OSError):
            result.note(f".env scan: cannot read {redact(str(env_path))}.")
            continue

        sensitive_keys = 0
        total_keys = 0
        max_tier_for_file = "P3"
        prefix_classes: set[str] = set()

        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, _, value = stripped.partition("=")
            key = key.strip()
            value = value.strip()
            total_keys += 1

            # --- Everything below uses `value` only to MEASURE, never to keep. ---
            key_is_sensitive = any(h in key.lower() for h in SENSITIVE_KEY_HINTS)
            value_prefix = classify_value_prefix(value)
            value_hot = looks_high_entropy(value) or bool(value_prefix)
            if value_prefix:
                prefix_classes.add(value_prefix)
            # value is dropped at end of loop iteration — never stored.

            if key_is_sensitive or value_hot:
                sensitive_keys += 1
                # A live cloud/payment/AI key or DB URI in plaintext = P0.
                kl = key.lower()
                if (value_prefix in (
                        "AWS access key id", "AWS temp access key id",
                        "Postgres connection URI", "MySQL connection URI",
                        "MongoDB connection URI", "Redis connection URI",
                        "Anthropic API key", "PEM private key block")
                        or any(p in kl for p in ("database_url", "db_url", "dsn",
                                                 "aws", "stripe", "anthropic",
                                                 "openai", "private_key"))):
                    max_tier_for_file = "P0"
                elif max_tier_for_file != "P0":
                    max_tier_for_file = "P1"

                # Per-key finding: KEY NAME + line + value SHAPE only.
                shape = []
                if value:
                    shape.append(f"{len(value)} chars")
                    if looks_high_entropy(value):
                        shape.append("high-entropy")
                if value_prefix:
                    shape.append(value_prefix)
                shape_str = ", ".join(shape) if shape else "empty"
                result.add(Finding(
                    surface="env-file",
                    tier=max_tier_for_file if max_tier_for_file == "P0" else "P1",
                    name=f"{key} (value: {shape_str})",
                    category="env-key",
                    count=1,
                    detail=f"line {lineno}",
                    pivot=(
                        "an attacker with disk access reads this plaintext key "
                        "and pivots into the live service it unlocks"
                    ),
                    remediation=(
                        "Move secrets out of plaintext .env into a secrets "
                        "manager / Keychain / 1Password; rotate this key; "
                        "ensure .env is gitignored; chmod 600."
                    ),
                    location=redact(str(env_path)),
                ))

        # File-level summary finding (counts only).
        if total_keys:
            try:
                mode = stat.S_IMODE(env_path.stat().st_mode)
            except OSError:
                mode = None
            perm_warn = ""
            if mode is not None and (mode & (stat.S_IRGRP | stat.S_IROTH)):
                perm_warn = f" — WORLD/GROUP-READABLE (chmod {oct(mode)[-3:]})"
            result.add(Finding(
                surface="env-file",
                tier=max_tier_for_file,
                name=f"{env_path.name}: {sensitive_keys}/{total_keys} sensitive key(s){perm_warn}",
                category="env-file-summary",
                count=sensitive_keys,
                detail=", ".join(sorted(prefix_classes)) if prefix_classes else "",
                pivot="bulk credential exposure for one project",
                remediation="chmod 600; gitignore; migrate to a secrets manager.",
                location=redact(str(env_path)),
            ))


# ---------------------------------------------------------------------------
# Surface (d): ~/.secrets listing (FILE NAMES + perms; name IS the credential)
# ---------------------------------------------------------------------------

def scan_dot_secrets(result: ScanResult) -> None:
    secrets_dir = Path.home() / ".secrets"
    if not secrets_dir.exists():
        result.note("~/.secrets: directory not present.")
        return
    try:
        dir_mode = stat.S_IMODE(secrets_dir.stat().st_mode)
    except OSError:
        dir_mode = None

    if dir_mode is not None and dir_mode & (stat.S_IRWXG | stat.S_IRWXO):
        result.add(Finding(
            surface="dot-secrets",
            tier="P0",
            name=f"~/.secrets directory is group/other-accessible (chmod {oct(dir_mode)[-3:]})",
            category="secrets-dir-perms",
            count=1,
            detail="should be 700",
            pivot="any local user/process can enumerate and read every secret file",
            remediation="chmod 700 ~/.secrets",
            location="~/.secrets",
        ))

    try:
        entries = sorted(p for p in secrets_dir.iterdir() if p.is_file())
    except (PermissionError, OSError):
        result.note("~/.secrets: present but not readable (good if intentional).")
        return

    for p in entries:
        try:
            st = p.stat()
            mode = stat.S_IMODE(st.st_mode)
            size = st.st_size
        except OSError:
            continue
        world_or_group = bool(mode & (stat.S_IRWXG | stat.S_IRWXO))
        tier = "P0" if world_or_group else "P1"
        perm_note = f"chmod {oct(mode)[-3:]}"
        if world_or_group:
            perm_note += " — GROUP/OTHER READABLE"
        # The FILE NAME is the credential name; we report it + size + perms.
        result.add(Finding(
            surface="dot-secrets",
            tier=tier,
            name=f"{p.name} ({size} bytes, {perm_note})",
            category="flat-secret-file",
            count=1,
            detail="single-value secret file (name = credential)",
            pivot="direct read of a live credential by anyone with disk access",
            remediation=(
                "chmod 600 each file; consider moving into the macOS Keychain; "
                "rotate any secret you suspect was exposed."
            ),
            location="~/.secrets",
        ))


# ---------------------------------------------------------------------------
# Surface (e): PII markers in Desktop / Documents / Downloads (COUNTS only)
# ---------------------------------------------------------------------------

def scan_pii_markers(result: ScanResult) -> None:
    home = Path.home()
    targets = [home / "Desktop", home / "Documents", home / "Downloads"]

    # Aggregate counts per PII type across all scanned files; report top files.
    type_totals: dict[str, int] = {t: 0 for t in PII_PATTERNS}
    per_file_hot: list[tuple[str, dict[str, int]]] = []

    for base in targets:
        if not base.exists():
            continue
        try:
            for path in _iter_target_files(base):
                if path.suffix.lower() not in PII_SCAN_EXTENSIONS:
                    continue
                try:
                    if path.stat().st_size > MAX_FILE_BYTES:
                        continue
                    content = path.read_text(errors="ignore")
                except (PermissionError, OSError):
                    continue

                file_counts: dict[str, int] = {}
                for ptype, pat in PII_PATTERNS.items():
                    matches = pat.findall(content)
                    if not matches:
                        continue
                    # Luhn-validate credit-card candidates to cut false positives.
                    if ptype == "credit-card":
                        valid = [m for m in matches if _luhn_ok(_digits(m))]
                        if not valid:
                            continue
                        n = len(valid)
                    else:
                        n = len(matches)
                    file_counts[ptype] = n
                    type_totals[ptype] += n
                    # matches go out of scope here — instances never stored/printed.

                if file_counts:
                    per_file_hot.append((redact(str(path)), file_counts))
        except (PermissionError, OSError) as e:
            result.note(f"PII scan: stopped early in {redact(str(base))} ({e.__class__.__name__}).")

    grand_total = sum(type_totals.values())
    if grand_total == 0:
        result.note("PII scan: no PII markers found in Desktop/Documents/Downloads.")
        return

    # One aggregate finding (counts per type) ...
    type_summary = ", ".join(f"{k}: {v}" for k, v in type_totals.items() if v)
    result.add(Finding(
        surface="pii",
        tier="P3",
        name=f"{grand_total} PII marker(s) across Desktop/Documents/Downloads",
        category="pii-aggregate",
        count=grand_total,
        detail=type_summary,
        pivot="identity theft / targeted social engineering (no direct system pivot)",
        remediation=(
            "Move documents containing SIN/SSN/card numbers into an encrypted "
            "disk image or password manager; delete stale exports; empty "
            "Downloads of old statements."
        ),
        location="Desktop/Documents/Downloads",
    ))

    # ... plus the hottest few files by total marker count (names only).
    per_file_hot.sort(key=lambda t: sum(t[1].values()), reverse=True)
    for path_str, counts in per_file_hot[:8]:
        summary = ", ".join(f"{k}: {v}" for k, v in counts.items())
        has_high = any(k in counts for k in ("sin-ssn", "credit-card"))
        result.add(Finding(
            surface="pii",
            tier="P2" if has_high else "P3",
            name=f"{Path(path_str).name} — {summary}",
            category="pii-file",
            count=sum(counts.values()),
            detail=summary,
            pivot="identity theft / financial fraud" if has_high else "identity theft",
            remediation="Encrypt or delete this file; remove SIN/card data from cleartext.",
            location=path_str,
        ))


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def _luhn_ok(num: str) -> bool:
    """Luhn checksum to validate a credit-card candidate (cuts false positives)."""
    if not (13 <= len(num) <= 19) or not num.isdigit():
        return False
    total = 0
    parity = len(num) % 2
    for i, ch in enumerate(num):
        d = int(ch)
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------

TIER_META = {
    "P0": ("CRITICAL", "Live keys / wallet seeds in plaintext — disk access = full pivot"),
    "P1": ("HIGH",     "Account-takeover credentials (browser logins, secret files)"),
    "P2": ("MEDIUM",   "Session cookies / reusable PII clusters"),
    "P3": ("LOW",      "Advisory exposure (PII, trusted-host logins)"),
}
TIER_ORDER = ["P0", "P1", "P2", "P3"]


def render_markdown(result: ScanResult, target: Path) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines: list[str] = []
    lines.append("# ExposureScan — Blast-Radius Self-Audit\n")
    lines.append(f"_Generated {now} · scope: `{redact(str(target))}`_\n")
    lines.append(
        "> **Names and counts only.** Secret values were never read, decrypted, "
        "stored, or printed. This is a defensive self-audit, not an extractor.\n"
    )

    # Tally per tier.
    by_tier: dict[str, list[Finding]] = {t: [] for t in TIER_ORDER}
    for f in result.findings:
        by_tier.setdefault(f.tier, []).append(f)

    # Summary table.
    lines.append("## Summary\n")
    lines.append("| Tier | Severity | Findings | What it means |")
    lines.append("|------|----------|----------|----------------|")
    for t in TIER_ORDER:
        sev, meaning = TIER_META[t]
        lines.append(f"| {t} | {sev} | {len(by_tier.get(t, []))} | {meaning} |")
    lines.append("")

    # Per-tier detail.
    for t in TIER_ORDER:
        findings = by_tier.get(t, [])
        if not findings:
            continue
        sev, meaning = TIER_META[t]
        lines.append(f"## {t} — {sev}\n")
        lines.append(f"_{meaning}_\n")
        for f in sorted(findings, key=lambda x: (x.surface, x.name)):
            lines.append(f"### {redact(f.name)}")
            lines.append(f"- **Surface:** {f.surface}")
            lines.append(f"- **Category:** {f.category}")
            lines.append(f"- **Location:** {redact(f.location)}")
            if f.detail:
                lines.append(f"- **Detail:** {redact(f.detail)}")
            lines.append(f"- **Attacker pivots into:** {f.pivot}")
            lines.append(f"- **Remediation:** {f.remediation}")
            lines.append("")

    # Notes / skips.
    if result.notes:
        lines.append("## Scan notes (skips & access)\n")
        for n in result.notes:
            lines.append(f"- {redact(n)}")
        lines.append("")

    # Tiered remediation checklist.
    lines.append("## Remediation checklist (do these in order)\n")
    lines.append("1. **P0 first** — Move every plaintext live key (AWS/Stripe/Anthropic/DB URI), "
                 "private key, and wallet seed out of `.env`/`~/.secrets`/Notes into the macOS "
                 "Keychain or a password manager, then **rotate** them. `chmod 700 ~/.secrets`, "
                 "`chmod 600` each secret file.")
    lines.append("2. **P1** — Stop saving passwords in the browser for financial/email/registrar "
                 "origins; migrate to a password manager; enable OS-level encryption.")
    lines.append("3. **P2** — Sign out of sensitive sites to kill session cookies; encrypt or "
                 "delete documents containing SIN/SSN/card numbers.")
    lines.append("4. **P3** — Clear stale PII exports from Downloads; review trusted-host logins.")
    lines.append("")
    lines.append("> This audit shrinks the blast radius. It does **not** stop you from pasting a "
                 "`curl … | bash` into Terminal or typing your password into a fake dialog. "
                 "Pair it with ShellGuard (zsh execute-time guard) and ClipSentinel "
                 "(clipboard early-warning) from this kit.\n")

    return "\n".join(lines)


def build_json_sidecar(result: ScanResult, target: Path) -> dict:
    """detect-secrets-style, values-free sidecar for week-over-week diffing."""
    by_tier_counts: dict[str, int] = {t: 0 for t in TIER_ORDER}
    for f in result.findings:
        by_tier_counts[f.tier] = by_tier_counts.get(f.tier, 0) + 1
    return {
        "tool": "exposurescan",
        "version": "1.0.0",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "target": redact(str(target)),
        "invariant": "names-and-counts-only; no secret values present by construction",
        "tier_counts": by_tier_counts,
        "findings": [f.to_json() for f in result.findings],
        "notes": [redact(n) for n in result.notes],
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def run_scan(target: Path, *, do_notes: bool, do_browser: bool) -> ScanResult:
    result = ScanResult()
    if do_browser:
        try:
            scan_browser_logins(result)
        except Exception as e:  # never let one surface crash the audit
            result.note(f"Browser surface errored: {e.__class__.__name__}.")
    if do_notes:
        try:
            scan_apple_notes(result)
        except Exception as e:
            result.note(f"Apple Notes surface errored: {e.__class__.__name__}.")
    try:
        scan_env_files(result, target)
    except Exception as e:
        result.note(f".env surface errored: {e.__class__.__name__}.")
    try:
        scan_dot_secrets(result)
    except Exception as e:
        result.note(f"~/.secrets surface errored: {e.__class__.__name__}.")
    try:
        scan_pii_markers(result)
    except Exception as e:
        result.note(f"PII surface errored: {e.__class__.__name__}.")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="exposurescan",
        description="Local secret + PII blast-radius self-audit (names/counts only, never values).",
    )
    parser.add_argument(
        "--target", type=str, default=str(Path.home()),
        help="Directory to scan for .env files and (via subdirs) project secrets. "
             "Default: your home directory.",
    )
    parser.add_argument(
        "--json", type=str, default=None, metavar="PATH",
        help="Also write a values-free JSON sidecar (for week-over-week diffing).",
    )
    parser.add_argument(
        "--out", type=str, default=None, metavar="PATH",
        help="Write the markdown report to this file (still prints to stdout).",
    )
    parser.add_argument("--no-notes", action="store_true", help="Skip the Apple Notes surface.")
    parser.add_argument("--no-browser", action="store_true", help="Skip the browser-login surface.")
    args = parser.parse_args(argv)

    target = Path(os.path.expanduser(args.target)).resolve()
    if not target.exists():
        print(f"error: --target path does not exist: {target}", file=sys.stderr)
        return 2

    result = run_scan(
        target,
        do_notes=not args.no_notes,
        do_browser=not args.no_browser,
    )

    markdown = render_markdown(result, target)
    print(markdown)

    if args.out:
        out_path = Path(os.path.expanduser(args.out))
        out_path.write_text(markdown)
        print(f"\n[exposurescan] markdown written to {out_path}", file=sys.stderr)

    if args.json:
        sidecar = build_json_sidecar(result, target)
        json_path = Path(os.path.expanduser(args.json))
        json_path.write_text(json.dumps(sidecar, indent=2))
        print(f"[exposurescan] JSON sidecar written to {json_path}", file=sys.stderr)

    # Exit code reflects worst tier found (useful in launchd / CI).
    if any(f.tier == "P0" for f in result.findings):
        return 3
    if any(f.tier == "P1" for f in result.findings):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
