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
  * Apple Notes        : we report a note's PRIMARY KEY, title LENGTH,
                         modification date and matched CATEGORY. The title
                         itself is NEVER emitted — on macOS a Note has no
                         user-chosen title; ZTITLE1 is derived from the note's
                         FIRST LINE, so for the exact user this surface exists
                         for (someone who pasted a seed phrase into Notes) the
                         "title" IS the secret.
  * PII filenames      : a filename can itself be the PII ("visa 4111 ... .csv").
                         Filenames are run through the PII patterns before
                         emission and withheld (hash + parent dir + size +
                         mtime) when they match.

Every user-facing string passes through redact() as a final chokepoint. redact()
scrubs control characters, collapses the string to a single line, strips URI
userinfo, everything after '=', anything inside a sensitive-keyword proximity
window, BIP-39 seed-phrase runs, and long high-entropy runs — so even an
accidental leak in a path or title cannot escape. See tests/.

SAFETY
------
  * Read-only. No network. No decryption. No writes outside a temp file that is
    deleted in __exit__, in an atexit handler, and on SIGINT/SIGTERM.
  * SQLite DBs are copied to a 0600 temp path and opened `mode=ro`.
    See the comment on _TempCopyConn for why `immutable=1` was REMOVED.
  * Report files (--out / --json) are created 0600 and moved into place with
    os.replace(), so a partially written credential map is never observable.

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
    ./exposurescan.py --json ~/.local/state/exposurescan/report.json
                                           # values-free JSON sidecar (mode 0600)
    ./exposurescan.py --no-notes           # skip the Apple Notes surface
    ./exposurescan.py --out report.md      # write markdown to a file too

This tool reduces risk and raises literacy. It cannot stop you from pasting a
curl|bash into Terminal or typing your password into a fake dialog. Pair it
with the ShellGuard (zsh) and ClipSentinel layers in this kit.
"""

from __future__ import annotations

import argparse
import atexit
import gzip
import hashlib
import json
import math
import os
import re
import shutil
import signal
import sqlite3
import stat
import sys
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
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
#
# '/' is deliberately NOT in this class. With it, the run crosses path
# separators and `/Users/me/dev/some-project/.env` collapses to
# `<redacted>.env` — which destroys the one thing a Location line is for.
# Slash-bearing base64 blobs are still caught by _VALUE_SHAPE_LONG below, at a
# length no filesystem path realistically reaches without a '.' or a space.
_VALUE_SHAPE = re.compile(r"[A-Za-z0-9+=_\-]{20,}")
_VALUE_SHAPE_LONG = re.compile(r"[A-Za-z0-9+/=_\-]{40,}")

# One narrow exemption from the shape rules: an UPPER_SNAKE_CASE identifier.
# `.env` KEY NAMES are the tool's primary output and routinely run past 20 chars
# (NEXT_PUBLIC_SUPABASE_ANON_KEY is 29), so without this the report degrades to
# a list of "<redacted>". The shape is deliberately unambiguous — every segment
# uppercase/digits, separated by underscores, no lowercase, capped at 64 chars.
# A credential in that shape does not occur in the wild; anything with a
# lowercase char, a hyphen, '+', '/' or '=' is NOT exempt and still dies.
_KEY_NAME_SHAPE = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$")


def _shape_sub(match: re.Match) -> str:
    run = match.group(0)
    if len(run) <= 64 and _KEY_NAME_SHAPE.match(run):
        return run
    return "<redacted>"

# Anything that looks like KEY=VALUE — we keep the key, nuke the value.
#
# v0.1.0 BUG (fixed): this was `(=)\s*\S+`, which stops at the first space, so
# `wifi password = correct horse battery staple` became
# `wifi password = <redacted> horse battery staple` — three of the four words
# survived AND the literal "<redacted>" made the line read as sanitized. The
# value runs to end of line, so the pattern must too.
_ASSIGNMENT = re.compile(r"(=)\s*.+$", re.M)

# Control characters (C0 minus \t\n, DEL, C1). ANSI escape sequences start with
# \x1b, which lives in this class — a title containing "\x1b[31m" would
# otherwise be replayed straight into the user's terminal.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")

# scheme://user:password@host — the userinfo segment is a credential and holds
# no spaces, so neither the assignment rule nor the entropy rule catches it.
# `postgres://admin:hunter2@db.internal:5432/prod` passed through untouched.
_URI_CREDS = re.compile(r"(\b[A-Za-z][A-Za-z0-9+.\-]*://)[^\s/@]*@")

# --- Proximity rule -------------------------------------------------------
# A short, low-entropy secret next to a keyword ("PIN 4821", "password hunter2")
# is invisible to every shape-based rule. So: when a sensitive keyword appears
# as a whole word and is followed within PROXIMITY_WINDOW chars by a separator
# (':', '=' or whitespace) plus content, the rest of the LINE is redacted.
#
# The separator set deliberately excludes '-' and '_' so the tool's own
# vocabulary ("session-cookie host(s)", "seed-phrase", "STRIPE_SECRET_KEY")
# does not self-redact.
PROXIMITY_WINDOW = 64
_PROXIMITY_RE: re.Pattern | None = None


def _proximity_re() -> re.Pattern:
    global _PROXIMITY_RE
    if _PROXIMITY_RE is None:
        words = sorted(
            {w.lower() for w in SENSITIVE_KEY_HINTS}
            | {c.lower() for c in SENSITIVE_CONTENT_CATEGORIES},
            key=len, reverse=True,
        )
        _PROXIMITY_RE = re.compile(
            r"\b(?:" + "|".join(re.escape(w) for w in words) + r")\b(?=[:=\s])",
            re.I,
        )
    return _PROXIMITY_RE


# --- BIP-39 seed phrases --------------------------------------------------
# A 12/24-word mnemonic is the single highest-value secret this tool can meet,
# and it is 100% invisible to shape-based redaction: every token is a short
# lowercase dictionary word and the longest unbroken run is ~8 chars.
# v0.1.0 emitted such a title BYTE-IDENTICAL.
#
# Wordlist source (verified 2048 lines,
# sha256 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda):
#   https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt
BIP39_PATH = Path(__file__).resolve().parent / "bip39.txt"
SEED_RUN_MIN = 6           # >= 6 consecutive wordlist tokens => REDACT as a seed
# Detection (raising a P0 finding) uses a much higher bar than redaction.
# Redaction should over-fire; a false-positive P0 on an ordinary shopping list
# trains the user to ignore the report. Real mnemonics are 12/18/24 words.
SEED_DETECT_MIN = 11
_BIP39_WORDS: frozenset[str] | None = None
_BIP39_WARNED = False
_WORD_TOKEN = re.compile(r"[A-Za-z]+")


def _bip39_words() -> frozenset[str]:
    """Lazily load the BIP-39 English wordlist. Degrades to empty on failure."""
    global _BIP39_WORDS, _BIP39_WARNED
    if _BIP39_WORDS is None:
        try:
            raw = BIP39_PATH.read_text(encoding="utf-8")
            words = {
                ln.strip().lower() for ln in raw.splitlines()
                if ln.strip() and not ln.lstrip().startswith("#")
            }
            _BIP39_WORDS = frozenset(words)
        except OSError:
            _BIP39_WORDS = frozenset()
        if not _BIP39_WORDS and not _BIP39_WARNED:
            _BIP39_WARNED = True
            # Names the missing FILE only. Never echoes the text that would
            # have been checked against it.
            print(
                f"[exposurescan] warning: {BIP39_PATH.name} missing or empty; "
                "seed-phrase redaction is DISABLED for this run.",
                file=sys.stderr,
            )
    return _BIP39_WORDS


def _redact_seed_phrases(text: str) -> str:
    words = _bip39_words()
    if not words:
        return text
    toks = list(_WORD_TOKEN.finditer(text))
    if len(toks) < SEED_RUN_MIN:
        return text
    out: list[str] = []
    cursor = 0
    run_start = 0
    i = 0
    n = len(toks)
    while i < n:
        if toks[i].group(0).lower() in words:
            run_start = i
            j = i
            while j + 1 < n and toks[j + 1].group(0).lower() in words:
                j += 1
            if (j - run_start + 1) >= SEED_RUN_MIN:
                out.append(text[cursor:toks[run_start].start()])
                out.append("<redacted seed-phrase>")
                cursor = toks[j].end()
            i = j + 1
        else:
            i += 1
    out.append(text[cursor:])
    return "".join(out)


def looks_like_mnemonic(text: str, min_run: int = SEED_DETECT_MIN) -> bool:
    """
    True if `text` contains a long run of consecutive BIP-39 wordlist tokens.

    Found while writing the regression suite: SENSITIVE_CONTENT_CATEGORIES
    only ever matched the LABEL ("seed phrase", "recovery phrase", "mnemonic").
    A note containing nothing but the twelve words — the actual catastrophic
    case — was not detected at all. Detection was as broken as redaction.
    """
    words = _bip39_words()
    if not words:
        return False
    run = 0
    for tok in _WORD_TOKEN.findall(text):
        if tok.lower() in words:
            run += 1
            if run >= min_run:
                return True
        else:
            run = 0
    return False


def _apply_proximity(line: str) -> str:
    pat = _proximity_re()
    m = pat.search(line)
    if not m:
        return line
    tail = line[m.end():]
    lead = len(tail) - len(tail.lstrip(" \t:="))
    if lead > PROXIMITY_WINDOW:
        return line
    if not tail[lead:].strip():
        return line          # keyword ends the line; nothing to hide
    return line[:m.end()] + " <redacted>"


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
    Final safety chokepoint. Every string that is about to be shown to the user
    or written to a report passes through here. Defense in depth: even if a code
    path forgot to drop a value, it cannot escape this funnel.

    Order matters. Structural neutralisation first (control chars, newlines),
    then the rules that key off structure (URI userinfo, '=', keyword
    proximity), then dictionary/shape rules that scan whatever is left.
    """
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)

    # 1. Control characters -> U+FFFD. Kills ANSI escapes (\x1b), NUL, and the
    #    C1 range before anything else can act on them or reach a terminal.
    out = _CONTROL_CHARS.sub("�", text)
    # 2. Collapse to ONE line. A newline in a note title or filename otherwise
    #    forges markdown structure ("\n### P0 — INJECTED FINDING").
    out = out.replace("\r", " ").replace("\n", " ")
    # 3. scheme://user:pass@host
    out = _URI_CREDS.sub(r"\1<redacted>@", out)
    # 4. key = value  (to end of line)
    out = _ASSIGNMENT.sub(r"\1 <redacted>", out)
    # 5. sensitive keyword + separator -> redact to end of line
    out = _apply_proximity(out)
    # 6. BIP-39 mnemonics
    out = _redact_seed_phrases(out)
    # 7. Any remaining long high-entropy run. Long/slash-bearing first, so a
    #    base64 blob is not chopped into per-segment "<redacted>" confetti.
    out = _VALUE_SHAPE_LONG.sub(_shape_sub, out)
    out = _VALUE_SHAPE.sub(_shape_sub, out)
    return out


# Characters that let an interpolated string forge markdown structure. Escaped
# at the LEADING position (headings, blockquotes, lists), plus '|' and '`'
# anywhere (tables and code spans).
_MD_LEADING = "#>-|`+*=_"


def markdown_safe(text: str) -> str:
    """redact(), then neutralise markdown metacharacters. One line, always."""
    s = redact(text)
    s = s.split("\n")[0]
    s = s.replace("`", "\\`").replace("|", "\\|")
    if s[:1] in _MD_LEADING:
        s = "\\" + s
    return s


# Generated metadata (value SHAPES, counts, permission bits) is built entirely
# from ints and a fixed label vocabulary, so it never contains a secret and must
# not be fed to redact() — the proximity rule would eat labels like
# "AWS access key id". This validator is the belt to that suspenders: anything
# outside a conservative alphabet is dropped.
_SHAPE_ALLOWED = re.compile(r"[^A-Za-z0-9 ,.:;/+()\-]")


def safe_shape(text: str) -> str:
    return _SHAPE_ALLOWED.sub("", text or "")[:120]


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
    # Generated metadata about a value's SHAPE (lengths, entropy flag, prefix
    # class). Built from ints + a fixed label vocabulary, so it is value-free by
    # construction and is filtered through safe_shape() instead of redact() —
    # redact()'s proximity rule would otherwise eat labels like
    # "AWS access key id" and "Postgres connection URI".
    shape: str = ""

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
            "value_shape": safe_shape(self.shape),
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

_TEMP_SIDECARS = ("", "-wal", "-shm", "-journal")
_TEMP_PATHS: set[str] = set()
_TEMP_LOCK = threading.Lock()


def _register_temp(p: Path) -> None:
    with _TEMP_LOCK:
        _TEMP_PATHS.add(str(p))


def _purge_temp(base: str) -> None:
    for suffix in _TEMP_SIDECARS:
        try:
            os.unlink(base + suffix)
        except OSError:
            pass


def _cleanup_temps() -> None:
    """Unlink every temp credential-DB copy we know about. Idempotent."""
    with _TEMP_LOCK:
        bases = list(_TEMP_PATHS)
        _TEMP_PATHS.clear()
    for base in bases:
        _purge_temp(base)


atexit.register(_cleanup_temps)


def _install_signal_handlers() -> None:
    """
    A SIGTERM/SIGINT mid-copy would otherwise orphan a plaintext copy of the
    browser's Login Data in TMPDIR, with no process left to clean it up.
    atexit alone does not run on a signal.
    """
    if threading.current_thread() is not threading.main_thread():
        return

    def _handler(signum, _frame):
        _cleanup_temps()
        raise SystemExit(128 + signum)

    for sig in (signal.SIGTERM, signal.SIGINT, getattr(signal, "SIGHUP", None)):
        if sig is None:
            continue
        try:
            signal.signal(sig, _handler)
        except (ValueError, OSError, RuntimeError):
            pass


class _TempCopyConn:
    """
    Context manager that copies an sqlite file to a private 0600 temp path and
    opens it read-only, so a running app can't lock us out and we can never
    mutate the original. Temp file is deleted in __exit__, on an exception
    inside __enter__, at process exit, and on SIGINT/SIGTERM/SIGHUP.

    WAL / immutable tradeoff (v0.1.0 bug, decided in v0.1.1)
    -------------------------------------------------------
    v0.1.0 copied the -wal sidecar AND opened with `mode=ro&immutable=1`.
    `immutable=1` tells SQLite the file cannot change, so it skips WAL recovery
    entirely and reads only the main database. Measured: a DB with 50 rows
    parked in an uncheckpointed WAL reported "no such table" under
    `immutable=1` and the correct 50 rows under plain `mode=ro`. In other
    words the tool silently UNDER-COUNTED the most recent logins and cookies —
    in a report whose entire output is a risk score.

    Decision: keep the -wal copy, DROP `immutable=1`.
      * Cost of dropping it: SQLite needs to create a -shm next to the copy and
        may replay the WAL. Both happen inside our own temp dir, on our own
        0600 copy — never on the user's file, which we only ever read via
        shutil.copyfile. The -shm is registered for cleanup like the rest.
      * Cost of the alternative (dropping the -wal copy): the report keeps
        lying about recency, which is the failure mode that matters. Rejected.
    """

    def __init__(self, src: Path):
        self.src = src
        self.tmp: Path | None = None
        self.conn: sqlite3.Connection | None = None

    def __enter__(self) -> sqlite3.Connection:
        fd, tmp_name = tempfile.mkstemp(prefix="exposurescan_", suffix=".sqlite")
        os.close(fd)
        self.tmp = Path(tmp_name)
        _register_temp(self.tmp)
        try:
            # copyfile, NOT copy2. copy2 runs copystat, which replays the
            # SOURCE's mode onto the destination — widening mkstemp's 0600 back
            # to Login Data's 0644 and leaving a world-readable plaintext copy
            # of the credential DB in TMPDIR for the life of the scan.
            shutil.copyfile(self.src, self.tmp)
            os.chmod(self.tmp, 0o600)
            for suffix in ("-wal", "-shm"):
                cand = Path(str(self.src) + suffix)
                try:
                    if cand.exists():
                        dst = Path(str(self.tmp) + suffix)
                        shutil.copyfile(cand, dst)
                        os.chmod(dst, 0o600)
                except OSError:
                    pass
            uri = f"file:{self.tmp}?mode=ro"
            self.conn = sqlite3.connect(uri, uri=True)
        except BaseException:
            # A TCC PermissionError (or Ctrl-C) mid-copy must not orphan a
            # partial credential DB in TMPDIR.
            self._cleanup()
            raise
        return self.conn

    def _cleanup(self) -> None:
        try:
            if self.conn is not None:
                self.conn.close()
        except sqlite3.Error:
            pass
        finally:
            self.conn = None
            if self.tmp is not None:
                base = str(self.tmp)
                _purge_temp(base)
                with _TEMP_LOCK:
                    _TEMP_PATHS.discard(base)

    def __exit__(self, *exc) -> None:
        self._cleanup()


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
                    # Worded so the proximity rule has nothing to truncate:
                    # "cookie"/"session" are themselves sensitive keywords, so
                    # they must not be followed by content on this line.
                    name=f"{len(hv)} high-value host(s) with saved session-cookies",
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

# Core Data stores dates as seconds since 2001-01-01 UTC.
_CORE_DATA_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)


def _core_data_date(value) -> str:
    """Format a Core Data timestamp as an ISO-ish date. Value-free by nature."""
    try:
        ts = float(value)
    except (TypeError, ValueError):
        return "unknown"
    try:
        return (_CORE_DATA_EPOCH + timedelta(seconds=ts)).strftime("%Y-%m-%d %H:%M UTC")
    except (OverflowError, OSError, ValueError):
        return "unknown"


def _match_categories(text: str) -> set[str]:
    """Return the set of sensitive-content category NAMES that matched."""
    cats = {cat for cat, pat in SENSITIVE_CONTENT_CATEGORIES.items() if pat.search(text)}
    # The regexes above only match the LABEL of a seed phrase. A bare mnemonic
    # carries no label — check the wordlist directly.
    if looks_like_mnemonic(text):
        cats.add("seed-phrase")
    return cats


def scan_apple_notes(result: ScanResult) -> None:
    home = Path.home()
    store = home / "Library" / "Group Containers" / "group.com.apple.notes" / "NoteStore.sqlite"
    if not store.exists():
        result.note("Apple Notes: NoteStore.sqlite not found (no notes or no access).")
        return
    _scan_notestore(result, store)


def _scan_notestore(result: ScanResult, store: Path) -> None:
    """Split out from scan_apple_notes so tests can drive a synthetic store."""
    try:
        with _TempCopyConn(store) as conn:
            cur = conn.cursor()
            # ZICNOTEDATA.ZDATA holds the gzipped protobuf note body.
            # ZICCLOUDSYNCINGOBJECT.ZTITLE1 is the note "title" — which Notes
            # DERIVES FROM THE FIRST LINE OF THE BODY. It is not user-chosen and
            # must never be emitted. ZMODIFICATIONDATE1 is what actually lets a
            # user find the note again.
            try:
                cur.execute(
                    "SELECT d.Z_PK, d.ZDATA, o.ZTITLE1, o.ZMODIFICATIONDATE1 "
                    "FROM ZICNOTEDATA d "
                    "LEFT JOIN ZICCLOUDSYNCINGOBJECT o ON o.ZNOTEDATA = d.Z_PK "
                    "WHERE d.ZDATA IS NOT NULL"
                )
            except sqlite3.OperationalError:
                # Older/newer schema: just pull the blobs without titles.
                cur.execute(
                    "SELECT Z_PK, ZDATA, NULL, NULL FROM ZICNOTEDATA WHERE ZDATA IS NOT NULL"
                )
            rows = cur.fetchall()
    except (sqlite3.Error, PermissionError, OSError) as e:
        result.note(
            f"Apple Notes: could not read NoteStore ({e.__class__.__name__}). "
            "Grant Full Disk Access to this terminal."
        )
        return

    locked = 0
    flagged: list[tuple[int, int, str, set[str], set[str]]] = []

    for pk, blob, title, mdate in rows:
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

        cats = _match_categories(text)
        if not cats:
            continue
        title_str = title if isinstance(title, str) else ""
        # We test the TITLE too — but only to decide how loudly to withhold it.
        title_cats = _match_categories(title_str) if title_str else set()
        flagged.append((
            int(pk) if pk is not None else -1,
            len(title_str),
            _core_data_date(mdate),
            cats,
            title_cats,
        ))
        # text and title_str go out of scope here; never stored, never printed.

    if locked:
        result.note(f"Apple Notes: {locked} locked/encrypted note(s) skipped (cannot read).")

    if not flagged:
        result.note("Apple Notes: no notes matched sensitive-content categories.")
        return

    for pk, title_len, mtime, cats, title_cats in sorted(flagged):
        cat_list = ", ".join(sorted(cats))
        # Crypto seed phrases / private keys in a Note are catastrophic (P0):
        # an attacker who reads them drains a wallet irreversibly.
        if cats & {"seed-phrase", "private-key", "crypto-wallet"}:
            tier, pivot = "P0", "wallet drain / irreversible crypto theft"
        elif cats & {"password", "api-key", "sin-ssn", "card-number"}:
            tier, pivot = "P2", "credential reuse / identity theft / fraud"
        else:
            tier, pivot = "P3", "identity theft / social engineering"
        # Ordering matters: a category name is itself a proximity keyword, so
        # the category list has to be LAST on the line or the withheld-title
        # notice gets truncated by our own redaction rule.
        detail = ""
        if title_cats:
            detail = "<title withheld - matched " + ", ".join(sorted(title_cats)) + "> ; "
        detail += f"matched categories: {cat_list}"
        result.add(Finding(
            surface="apple-notes",
            tier=tier,
            # NO TITLE. pk + length + mtime is enough to find the note in
            # Notes.app (sort by Date Edited) and leaks nothing.
            name=f"Note #{pk} (title {title_len} chars, modified {mtime}) - {cat_list}",
            category="note-secret",
            count=1,
            detail=detail,
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
                    # The KEY NAME is untrusted text and goes through redact()
                    # downstream. The value SHAPE is generated metadata and
                    # travels in its own value-free field.
                    name=f"{key}",
                    category="env-key",
                    count=1,
                    detail=f"line {lineno}",
                    shape=shape_str,
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
                detail="",
                shape=", ".join(sorted(prefix_classes)) if prefix_classes else "",
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
            perm_note += " - GROUP/OTHER READABLE"
        # The FILE NAME is the credential name; we report it + size + perms.
        result.add(Finding(
            surface="dot-secrets",
            tier=tier,
            name=f"{p.name}",
            category="flat-secret-file",
            count=1,
            # Worded so the proximity rule has nothing to truncate: "secret"
            # and "credential" are themselves sensitive keywords.
            detail="flat file whose name identifies the credential",
            shape=f"{size} bytes, {perm_note}",
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
    per_file_hot: list[tuple[Path, dict[str, int]]] = []

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

                # The FILENAME is PII too. v0.1.0 only ever scanned contents, so
                # "visa 4111 1111 1111 1111 exp 0327 cvv 415.csv" with a benign
                # body was invisible to the scan AND, once any other file put it
                # in the report, printed verbatim.
                for ptype in _pii_matches_in(path.name):
                    file_counts[ptype] = file_counts.get(ptype, 0) + 1
                    type_totals[ptype] += 1

                if file_counts:
                    # Keep the real Path: the filename itself has to be
                    # PII-screened before it can be emitted (see _pii_file_label).
                    per_file_hot.append((path, file_counts))
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
        # Counts, not instances -> value-free generated metadata. It also has to
        # live here because "sin-ssn: 2" would trip redact()'s own proximity
        # rule ("sin-ssn" is a sensitive-category keyword).
        detail="",
        shape=type_summary,
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
    for path, counts in per_file_hot[:8]:
        summary = ", ".join(f"{k}: {v}" for k, v in counts.items())
        has_high = any(k in counts for k in ("sin-ssn", "credit-card"))
        label, location, shape = _pii_file_label(path)
        result.add(Finding(
            surface="pii",
            tier="P2" if has_high else "P3",
            name=label,
            category="pii-file",
            count=sum(counts.values()),
            detail="",
            shape=f"{summary}{'; ' + shape if shape else ''}",
            pivot="identity theft / financial fraud" if has_high else "identity theft",
            remediation="Encrypt or delete this file; remove SIN/card data from cleartext.",
            location=location,
        ))


def _pii_matches_in(text: str) -> list[str]:
    """Which PII categories does this string itself contain? (Luhn-checked.)"""
    hits: list[str] = []
    for ptype, pat in PII_PATTERNS.items():
        # finditer, not findall: several patterns have capturing groups and
        # findall would hand back group tuples instead of the matched text.
        found = [m.group(0) for m in pat.finditer(text)]
        if not found:
            continue
        if ptype == "credit-card" and not any(_luhn_ok(_digits(m)) for m in found):
            continue
        hits.append(ptype)
    return sorted(hits)


def _pii_file_label(path: Path) -> tuple[str, str, str]:
    """
    Return (name, location, shape) for a PII-hot file.

    v0.1.0 emitted `f"{Path(path_str).name} - {summary}"`, so a file called
    "visa 4111 1111 1111 1111 exp 0327 cvv 415.csv" was reproduced verbatim into
    stdout, the --out markdown AND the --json sidecar — helpfully annotated
    "credit-card: 1". The FILENAME is one of the places PII actually lives, so
    it has to be screened by the same patterns as the contents.
    """
    fname = path.name
    cats = _pii_matches_in(fname)
    try:
        st = path.stat()
        size = f"{st.st_size} bytes"
        mtime = datetime.fromtimestamp(st.st_mtime, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except OSError:
        size, mtime = "unknown size", "unknown"
    if not cats:
        return fname, str(path), f"{size}, modified {mtime}"
    digest = hashlib.sha256(fname.encode("utf-8", "surrogatepass")).hexdigest()[:8]
    parent = str(path.parent)
    # The parent dir is emitted so the file is still findable; the basename is
    # replaced by a stable hash so week-over-week diffing still works.
    label = (
        f"<filename withheld - matched {', '.join(cats)}> (#{digest}) "
        f"in {parent}/ ({size}, {mtime})"
    )
    return label, f"{parent}/<withheld #{digest}>", ""


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
    lines.append(f"_Generated {now} · scope: {markdown_safe(str(target))}_\n")
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
            # markdown_safe = redact() + single line + escaped metacharacters.
            # Without it a note title containing "\n### P0 - INJECTED FINDING"
            # forges a finding in the rendered report.
            lines.append(f"### {markdown_safe(f.name)}")
            lines.append(f"- **Surface:** {f.surface}")
            lines.append(f"- **Category:** {f.category}")
            lines.append(f"- **Location:** {markdown_safe(f.location)}")
            if f.detail:
                lines.append(f"- **Detail:** {markdown_safe(f.detail)}")
            if f.shape:
                lines.append(f"- **Value shape:** {safe_shape(f.shape)}")
            lines.append(f"- **Attacker pivots into:** {f.pivot}")
            lines.append(f"- **Remediation:** {f.remediation}")
            lines.append("")

    # Notes / skips.
    if result.notes:
        lines.append("## Scan notes (skips & access)\n")
        for n in result.notes:
            lines.append(f"- {markdown_safe(n)}")
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
        "version": "0.2.0",
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

def write_private(path: Path, data: str) -> Path:
    """
    Write `data` to `path` with mode 0600, atomically.

    A report file is a map of every credential surface on the machine. Written
    with a plain write_text() it lands at the umask default (usually 0644) and
    is observable, partially written, for the duration of the write. os.open
    with an explicit 0600 + os.replace() closes both.
    """
    path = Path(os.path.expanduser(str(path)))
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f".{path.name}.exposurescan-{os.getpid()}.tmp"
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(data)
        os.chmod(tmp, 0o600)     # explicit: do not inherit umask relaxation
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


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

    _install_signal_handlers()

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
        out_path = write_private(Path(args.out), markdown)
        print(f"\n[exposurescan] markdown written to {out_path} (mode 0600)", file=sys.stderr)

    if args.json:
        sidecar = build_json_sidecar(result, target)
        json_path = write_private(Path(args.json), json.dumps(sidecar, indent=2))
        print(f"[exposurescan] JSON sidecar written to {json_path} (mode 0600)", file=sys.stderr)

    # Exit code reflects worst tier found (useful in launchd / CI).
    if any(f.tier == "P0" for f in result.findings):
        return 3
    if any(f.tier == "P1" for f in result.findings):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
