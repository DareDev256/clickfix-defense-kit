#!/usr/bin/env python3
# CONFIRMED-SECRET-OK: every literal below is a synthetic, non-functional
# placeholder. The BIP-39 words are the first twelve entries of the PUBLIC
# BIP-39 English wordlist (the canonical "abandon ability able ..." test
# vector); they are not, and never have been, anybody's wallet. "hunter2" is
# the internet's oldest joke password. No literal here authenticates anywhere.
"""
The privacy-invariant regression suite for ExposureScan.

Every test in this file corresponds to a leak that was VERIFIED against the
real module in v0.1.0, while the README claimed the tool was "architecturally
incapable of emitting a secret value". Each one reproduced byte-identically.

The load-bearing tests are the END-TO-END ones. v0.1.0 had a passing unit test
on redact() and shipped six leaks anyway, because the leaks lived in the
f-strings BETWEEN the scanner and the chokepoint, not in the chokepoint itself.
A unit test on redact() proves redact() works. Only an end-to-end test proves
the ARTIFACT is clean.

Run:
    python3 -m unittest discover -s tests -v
"""

import gzip
import json
import re
import os
import shutil
import sqlite3
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import exposurescan as es  # noqa: E402


# The canonical public BIP-39 test vector. Twelve real wordlist entries.
SEED_WORDS = [
    "abandon", "ability", "able", "about", "above", "absent",
    "absorb", "abstract", "absurd", "abuse", "access", "accident",
]
SEED_PHRASE = " ".join(SEED_WORDS)

# Public Visa test PAN (Luhn-valid, not a real card).
TEST_PAN = "4111 1111 1111 1111"
PII_FILENAME = f"visa {TEST_PAN} exp 0327 cvv 415.csv"


# ---------------------------------------------------------------------------
# 1. redact() unit-level regressions
# ---------------------------------------------------------------------------

class TestRedactRegressions(unittest.TestCase):

    def test_assignment_runs_to_end_of_line(self):
        """v0.1.0: `(=)\\s*\\S+` stopped at the first space."""
        out = es.redact("PASSPHRASE = correct horse battery staple")
        for word in ("correct", "horse", "battery", "staple"):
            self.assertNotIn(word, out, f"LEAKED {word!r} -> {out!r}")

    def test_assignment_lowercase_hint_line(self):
        out = es.redact("wifi password = correct horse battery staple")
        for word in ("correct", "horse", "battery", "staple"):
            self.assertNotIn(word, out, f"LEAKED {word!r} -> {out!r}")

    def test_bip39_seed_phrase_is_destroyed(self):
        """v0.1.0: a 12-word mnemonic passed through 100% byte-identical."""
        out = es.redact(f"Note '{SEED_PHRASE}'")
        for word in SEED_WORDS:
            self.assertNotIn(word, out, f"SEED WORD LEAKED: {word!r} -> {out!r}")
        self.assertIn("<redacted seed-phrase>", out)

    def test_bip39_wordlist_is_the_real_2048(self):
        words = es._bip39_words()
        self.assertEqual(len(words), 2048, "bip39.txt must be the full wordlist")
        self.assertIn("abandon", words)
        self.assertIn("zoo", words)

    def test_bip39_missing_file_degrades_without_leaking(self):
        """Missing wordlist must not crash and must not echo the scanned text."""
        saved_words, saved_warned = es._BIP39_WORDS, es._BIP39_WARNED
        saved_path = es.BIP39_PATH
        try:
            es._BIP39_WORDS = None
            es._BIP39_WARNED = True          # suppress the stderr line in CI
            es.BIP39_PATH = Path(tempfile.gettempdir()) / "exposurescan-no-such-bip39.txt"
            out = es.redact("hello world")   # must not raise
            self.assertEqual(out, "hello world")
            self.assertEqual(es._bip39_words(), frozenset())
        finally:
            es._BIP39_WORDS, es._BIP39_WARNED = saved_words, saved_warned
            es.BIP39_PATH = saved_path

    def test_short_secrets_near_keywords(self):
        """v0.1.0: 'PIN 4821 / password hunter2 / ...' passed unchanged."""
        out = es.redact("PIN 4821 / password hunter2 / 2FA backup 731-449")
        for leak in ("hunter2", "4821", "731-449"):
            self.assertNotIn(leak, out, f"LEAKED {leak!r} -> {out!r}")

    def test_uri_userinfo(self):
        """v0.1.0: 'postgres://admin:hunter2@db.internal/prod' passed unchanged."""
        out = es.redact("postgres://admin:hunter2@db.internal:5432/prod")
        self.assertNotIn("hunter2", out)
        self.assertNotIn("admin", out)
        self.assertIn("db.internal", out, "the HOST is the finding; keep it")

    def test_ansi_escapes_are_neutralised(self):
        out = es.redact("shopping\x1b[31mRED")
        self.assertNotIn("\x1b", out)

    def test_newlines_collapse_to_one_line(self):
        out = es.redact("shopping\n### P0 - INJECTED FINDING")
        self.assertNotIn("\n", out)
        self.assertNotIn("\r", out)

    def test_control_characters_scrubbed(self):
        out = es.redact("a\x00b\x07c\x7fd\x9fe")
        for ch in ("\x00", "\x07", "\x7f", "\x9f"):
            self.assertNotIn(ch, out)

    def test_non_string_input(self):
        self.assertEqual(es.redact(None), "")
        self.assertEqual(es.redact(Path("/tmp/x")), "/tmp/x")

    def test_benign_text_survives(self):
        """Over-redaction that eats the report is its own failure mode."""
        self.assertIn("github.com", es.redact("github.com - saved login present"))
        self.assertIn("STRIPE_SECRET_KEY", es.redact("STRIPE_SECRET_KEY"))
        self.assertIn("DATABASE_URL", es.redact("DATABASE_URL"))
        self.assertIn("anthropic-key", es.redact("anthropic-key"))
        # A Location line that collapses to "<redacted>.env" is useless.
        self.assertEqual(
            es.redact("/Users/me/dev/some-project/.env"),
            "/Users/me/dev/some-project/.env",
        )

    def test_slash_bearing_base64_still_dies(self):
        blob = "abcdefghij0123456789ABCDEFGHIJ+/klmnopqrst=="
        out = es.redact(f"token {blob}")
        self.assertNotIn(blob, out)
        self.assertNotIn("klmnopqrst", out)


class TestMarkdownSafety(unittest.TestCase):

    def test_leading_metacharacters_escaped(self):
        self.assertTrue(es.markdown_safe("### heading").startswith("\\#"))
        self.assertTrue(es.markdown_safe("> quote").startswith("\\>"))
        self.assertTrue(es.markdown_safe("| a | b |").startswith("\\"))

    def test_backticks_and_pipes_escaped(self):
        out = es.markdown_safe("a `code` b | c")
        self.assertNotIn("`c", out.replace("\\`", ""))
        self.assertIn("\\|", out)

    def test_always_one_line(self):
        self.assertNotIn("\n", es.markdown_safe("a\nb\nc"))

    def test_safe_shape_alphabet(self):
        self.assertEqual(es.safe_shape("52 chars, high-entropy"), "52 chars, high-entropy")
        self.assertNotIn("<", es.safe_shape("<script>"))
        self.assertNotIn("\n", es.safe_shape("a\nb"))


# ---------------------------------------------------------------------------
# 2. END-TO-END: Apple Notes -> markdown + JSON
# ---------------------------------------------------------------------------

def _build_notestore(path: Path, first_line: str, body_extra: str = "") -> None:
    """
    Build a synthetic NoteStore.sqlite on the real Apple Notes schema shape:
    ZICNOTEDATA(Z_PK, ZDATA gzip blob) LEFT JOIN
    ZICCLOUDSYNCINGOBJECT(ZNOTEDATA, ZTITLE1, ZMODIFICATIONDATE1).

    ZTITLE1 is DERIVED FROM THE FIRST LINE of the note — that is the whole
    point of this test. If the user's first line is a seed phrase, the "title"
    IS the seed phrase.
    """
    conn = sqlite3.connect(str(path))
    conn.execute("CREATE TABLE ZICNOTEDATA (Z_PK INTEGER PRIMARY KEY, ZDATA BLOB)")
    conn.execute(
        "CREATE TABLE ZICCLOUDSYNCINGOBJECT ("
        "  Z_PK INTEGER PRIMARY KEY,"
        "  ZNOTEDATA INTEGER,"
        "  ZTITLE1 TEXT,"
        "  ZMODIFICATIONDATE1 REAL)"
    )
    body = first_line + ("\n" + body_extra if body_extra else "")
    conn.execute(
        "INSERT INTO ZICNOTEDATA (Z_PK, ZDATA) VALUES (?, ?)",
        (7, gzip.compress(body.encode("utf-8"))),
    )
    conn.execute(
        "INSERT INTO ZICCLOUDSYNCINGOBJECT (Z_PK, ZNOTEDATA, ZTITLE1, ZMODIFICATIONDATE1) "
        "VALUES (?, ?, ?, ?)",
        (1, 7, first_line, 775_000_000.0),
    )
    conn.commit()
    conn.close()


class TestAppleNotesEndToEnd(unittest.TestCase):
    """The load-bearing test. Real scanner -> real renderer -> real sidecar."""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp(prefix="exposurescan_notes_"))
        self.store = self.tmpdir / "NoteStore.sqlite"

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _run(self, first_line, body_extra=""):
        _build_notestore(self.store, first_line, body_extra)
        result = es.ScanResult()
        es._scan_notestore(result, self.store)
        markdown = es.render_markdown(result, self.tmpdir)
        sidecar = json.dumps(es.build_json_sidecar(result, self.tmpdir))
        return result, markdown, sidecar

    def test_seed_phrase_title_never_reaches_any_artifact(self):
        result, markdown, sidecar = self._run(
            SEED_PHRASE, body_extra="recovery phrase for my hardware wallet"
        )
        self.assertTrue(result.findings, "the note should have been flagged at all")
        # Baseline: the same renderer with NO findings. Several BIP-39 words
        # ("able", "access", "absent") are substrings or words of the report's
        # own fixed boilerplate ("reusable", "disk access = full pivot"), so the
        # honest assertion is that the note contributed ZERO new occurrences.
        # The baseline carries one inert P0 finding so the same tier sections
        # (and therefore the same boilerplate) render in both reports.
        empty = es.ScanResult()
        empty.add(es.Finding(
            surface="apple-notes", tier="P0", name="placeholder",
            category="note-secret", detail="placeholder",
            pivot="wallet drain / irreversible crypto theft",
            location="Apple Notes",
        ))
        base_md = es.render_markdown(empty, self.tmpdir)
        base_js = json.dumps(es.build_json_sidecar(empty, self.tmpdir))
        for word in SEED_WORDS:
            pat = re.compile(rf"\b{re.escape(word)}\b", re.I)
            self.assertEqual(
                len(pat.findall(markdown)), len(pat.findall(base_md)),
                f"SEED WORD IN MARKDOWN: {word!r}")
            self.assertEqual(
                len(pat.findall(sidecar)), len(pat.findall(base_js)),
                f"SEED WORD IN JSON: {word!r}")
        # And the phrase itself, in any 3-word window, must be absent.
        for i in range(len(SEED_WORDS) - 2):
            window = " ".join(SEED_WORDS[i:i + 3])
            self.assertNotIn(window, markdown)
            self.assertNotIn(window, sidecar)

    def test_finding_is_still_actionable(self):
        result, markdown, _ = self._run(
            SEED_PHRASE, body_extra="recovery phrase for my hardware wallet"
        )
        f = result.findings[0]
        self.assertEqual(f.tier, "P0")
        self.assertIn("Note #7", f.name)
        self.assertIn("chars", f.name)          # title LENGTH, not title
        self.assertIn("modified", f.name)       # how the user finds it again
        self.assertIn("seed-phrase", f.name)
        self.assertIn("title withheld", f.detail)
        self.assertIn("Note #7", markdown)

    def test_markdown_injection_via_title(self):
        _, markdown, _ = self._run(
            "\n### P0 - INJECTED FINDING\npassword: hunter2",
        )
        self.assertEqual(markdown.count("###"), 1,
                         "a note title forged an extra finding heading")
        self.assertNotIn("INJECTED FINDING", markdown)

    def test_ansi_never_reaches_the_report(self):
        _, markdown, sidecar = self._run("shopping\x1b[31mRED password: hunter2")
        self.assertNotIn("\x1b", markdown)
        self.assertNotIn("\x1b", sidecar)
        self.assertNotIn("hunter2", markdown)
        self.assertNotIn("hunter2", sidecar)


# ---------------------------------------------------------------------------
# 3. END-TO-END: PII filenames
# ---------------------------------------------------------------------------

class TestPiiFilenameEndToEnd(unittest.TestCase):

    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="exposurescan_home_"))
        (self.home / "Documents").mkdir()
        self.target = self.home / "Documents" / PII_FILENAME
        self.target.write_text("statement for account ending 1111\n")
        self._real_home = Path.home
        Path.home = staticmethod(lambda: self.home)   # type: ignore[assignment]

    def tearDown(self):
        Path.home = self._real_home                    # type: ignore[assignment]
        shutil.rmtree(self.home, ignore_errors=True)

    def test_card_number_in_filename_never_emitted(self):
        result = es.ScanResult()
        es.scan_pii_markers(result)
        markdown = es.render_markdown(result, self.home)
        sidecar = json.dumps(es.build_json_sidecar(result, self.home))
        self.assertNotIn("4111", markdown, "CARD NUMBER LEAKED INTO MARKDOWN")
        self.assertNotIn("4111", sidecar, "CARD NUMBER LEAKED INTO JSON")

    def test_withheld_filename_is_still_findable(self):
        result = es.ScanResult()
        es.scan_pii_markers(result)
        files = [f for f in result.findings if f.category == "pii-file"]
        self.assertTrue(files)
        f = files[0]
        self.assertIn("filename withheld", f.name)
        self.assertIn("credit-card", f.name)
        self.assertIn("Documents", f.name)       # parent dir survives
        self.assertIn("UTC", f.name)             # mtime survives
        self.assertNotIn("4111", f.location)

    def test_benign_filename_is_kept(self):
        benign = self.home / "Documents" / "contacts.csv"
        benign.write_text("someone@example.test\n")
        self.target.unlink()
        result = es.ScanResult()
        es.scan_pii_markers(result)
        names = " ".join(f.name for f in result.findings)
        self.assertIn("contacts.csv", names)


# ---------------------------------------------------------------------------
# 4. Temp-file hygiene around the credential DB copy
# ---------------------------------------------------------------------------

class TestTempCopyHygiene(unittest.TestCase):

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp(prefix="exposurescan_tmpc_"))
        self.src = self.tmpdir / "Login Data"
        conn = sqlite3.connect(str(self.src))
        conn.execute("CREATE TABLE logins (origin_url TEXT)")
        conn.commit()
        conn.close()
        # Reproduce the real-world case: source is 0644, as Chrome leaves it.
        os.chmod(self.src, 0o644)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_temp_copy_is_0600(self):
        """v0.1.0 used shutil.copy2, whose copystat widened 0600 back to 0644."""
        with es._TempCopyConn(self.src) as conn:
            tmp = None
            for base in list(es._TEMP_PATHS):
                if os.path.exists(base):
                    tmp = base
            self.assertIsNotNone(tmp, "temp copy was not registered for cleanup")
            mode = stat.S_IMODE(os.stat(tmp).st_mode)
            self.assertEqual(
                mode, 0o600,
                f"temp copy of a credential DB is mode {oct(mode)}, expected 0600",
            )
            conn.execute("SELECT count(*) FROM logins").fetchone()
        self.assertFalse(os.path.exists(tmp), "temp copy survived __exit__")

    def test_temp_removed_on_exception_inside_enter(self):
        """A TCC PermissionError mid-copy must not orphan a partial DB."""
        before = set(es._TEMP_PATHS)
        missing = self.tmpdir / "does-not-exist.sqlite"
        with self.assertRaises(OSError):
            with es._TempCopyConn(missing):
                pass                                     # pragma: no cover
        leaked = [p for p in es._TEMP_PATHS - before if os.path.exists(p)]
        self.assertEqual(leaked, [], f"orphaned temp files: {leaked}")

    def test_temp_removed_on_exception_inside_body(self):
        before = set(es._TEMP_PATHS)
        with self.assertRaises(RuntimeError):
            with es._TempCopyConn(self.src):
                raise RuntimeError("boom")
        leaked = [p for p in es._TEMP_PATHS - before if os.path.exists(p)]
        self.assertEqual(leaked, [], f"orphaned temp files: {leaked}")

    def test_wal_contents_are_not_ignored(self):
        """
        v0.1.0 copied the -wal sidecar but opened `immutable=1`, which makes
        SQLite skip WAL recovery entirely — silently under-counting the most
        recent logins in a report whose only output is a risk score.
        """
        src = self.tmpdir / "wal.sqlite"
        conn = sqlite3.connect(str(src))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA wal_autocheckpoint=0")
        conn.execute("CREATE TABLE logins (origin_url TEXT)")
        conn.commit()
        for i in range(50):
            conn.execute("INSERT INTO logins VALUES (?)", (f"https://h{i}.test/",))
        conn.commit()
        self.assertGreater(os.path.getsize(str(src) + "-wal"), 0, "no WAL to test")
        try:
            with es._TempCopyConn(src) as c:
                n = c.execute("SELECT count(*) FROM logins").fetchone()[0]
            self.assertEqual(n, 50, "rows parked in the WAL were dropped")
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# 5. Report files are private and atomic
# ---------------------------------------------------------------------------

class TestPrivateWrites(unittest.TestCase):

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp(prefix="exposurescan_out_"))
        # scan_dot_secrets / scan_pii_markers key off Path.home(); point them at
        # an empty fake home so the CLI test never touches the real machine.
        self.fake_home = Path(tempfile.mkdtemp(prefix="exposurescan_fakehome_"))
        self._real_home = Path.home
        Path.home = staticmethod(lambda: self.fake_home)   # type: ignore[assignment]

    def tearDown(self):
        Path.home = self._real_home                        # type: ignore[assignment]
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        shutil.rmtree(self.fake_home, ignore_errors=True)

    def test_report_is_0600(self):
        out = self.tmpdir / "nested" / "report.md"
        es.write_private(out, "# hello\n")
        self.assertEqual(stat.S_IMODE(os.stat(out).st_mode), 0o600)
        self.assertEqual(out.read_text(), "# hello\n")

    def test_no_temp_left_behind(self):
        out = self.tmpdir / "report.json"
        es.write_private(out, "{}")
        leftovers = [p.name for p in self.tmpdir.iterdir() if p.name != "report.json"]
        self.assertEqual(leftovers, [])

    def test_cli_end_to_end_writes_0600(self):
        target = self.tmpdir / "scope"
        target.mkdir()
        (target / ".env").write_text("PUBLIC_APP_NAME=demo\n")
        md = self.tmpdir / "r.md"
        js = self.tmpdir / "r.json"
        stdout, sys.stdout = sys.stdout, open(os.devnull, "w")
        stderr, sys.stderr = sys.stderr, open(os.devnull, "w")
        try:
            es.main([
                "--target", str(target), "--out", str(md), "--json", str(js),
                "--no-notes", "--no-browser",
            ])
        finally:
            sys.stdout.close(); sys.stdout = stdout
            sys.stderr.close(); sys.stderr = stderr
        self.assertEqual(stat.S_IMODE(os.stat(md).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(js).st_mode), 0o600)


# ---------------------------------------------------------------------------
# 6. The value-shape side channel
# ---------------------------------------------------------------------------

class TestValueShapeChannel(unittest.TestCase):
    """
    v0.2.0 moved generated metadata out of `name` into `Finding.shape`, which
    bypasses redact() on purpose. That makes `shape` the one field that could
    become a new leak, so it gets its own tests.
    """

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp(prefix="exposurescan_shape_"))
        (self.tmpdir / ".env").write_text(
            "STRIPE_SECRET_KEY=PLACEHOLDER-high-entropy-token-0123456789-XYZ\n"
            "DATABASE_URL=postgres://u:PLACEHOLDERpw@db.example.test:5432/app\n"
        )

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_shape_is_useful_and_value_free(self):
        result = es.ScanResult()
        es.scan_env_files(result, self.tmpdir)
        markdown = es.render_markdown(result, self.tmpdir)
        sidecar = json.dumps(es.build_json_sidecar(result, self.tmpdir))
        self.assertIn("Value shape:", markdown)
        self.assertIn("high-entropy", markdown)
        self.assertIn("Postgres connection URI", markdown)
        for forbidden in ("PLACEHOLDER-high-entropy-token", "PLACEHOLDERpw"):
            self.assertNotIn(forbidden, markdown)
            self.assertNotIn(forbidden, sidecar)

    def test_key_names_still_survive_redaction(self):
        result = es.ScanResult()
        es.scan_env_files(result, self.tmpdir)
        names = " ".join(es.redact(f.name) for f in result.findings)
        self.assertIn("STRIPE_SECRET_KEY", names)
        self.assertIn("DATABASE_URL", names)


class TestMnemonicDetection(unittest.TestCase):
    """Detection was as broken as redaction: only the LABEL was ever matched."""

    def test_bare_mnemonic_is_detected(self):
        self.assertTrue(es.looks_like_mnemonic(SEED_PHRASE))
        self.assertIn("seed-phrase", es._match_categories(SEED_PHRASE))

    def test_ordinary_prose_is_not(self):
        prose = (
            "Remember to pick up milk, call the plumber about the leak in the "
            "kitchen, and email Dana the revised quote before Friday afternoon."
        )
        self.assertFalse(es.looks_like_mnemonic(prose))
        self.assertEqual(es._match_categories(prose), set())


if __name__ == "__main__":
    unittest.main(verbosity=2)
