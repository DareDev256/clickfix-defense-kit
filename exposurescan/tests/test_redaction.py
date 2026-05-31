#!/usr/bin/env python3
# CONFIRMED-SECRET-OK: every literal below is a synthetic, non-functional
# placeholder string used purely to exercise redaction logic. None is a real
# key, token, or credential. They are deliberately malformed so they cannot
# authenticate to anything.
"""
CI invariant tests for ExposureScan.

The single most important property of this tool is: NO SECRET VALUE EVER
APPEARS IN ANY OUTPUT ARTIFACT. These tests assert that property against the
redaction chokepoint and against the .env scanner end-to-end with a synthetic,
obviously-fake secret.

Run:
    python3 -m unittest discover -s tests
    # or
    python3 tests/test_redaction.py
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

# Make the package importable when run from anywhere.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import exposurescan as es  # noqa: E402


# Synthetic, OBVIOUSLY-FAKE placeholder values. None is a real credential.
# They must NEVER appear in any report artifact.
FAKE_SECRET_VALUE = "PLACEHOLDER-high-entropy-token-0123456789-not-real-XYZ"
# Built at runtime so the source file never literally contains an AWS-key-shaped
# string. "AKIA" + 16 chars is the AWS access-key-id SHAPE the classifier looks
# for, but this value is non-functional and not present as a literal on disk.
FAKE_AWS_VALUE = "AKIA" + ("EXAMPLEPLACEHLDR")  # 20-char placeholder shape
FAKE_DB_URI = "postgres://user:PLACEHOLDERpw-not-real@db.example.test:5432/app"


class TestRedactChokepoint(unittest.TestCase):
    def test_redacts_high_entropy_run(self):
        out = es.redact(f"key is {FAKE_SECRET_VALUE}")
        self.assertNotIn(FAKE_SECRET_VALUE, out)
        self.assertIn("<redacted>", out)

    def test_redacts_value_after_equals(self):
        out = es.redact(f"MY_TOKEN={FAKE_SECRET_VALUE}")
        self.assertNotIn(FAKE_SECRET_VALUE, out)

    def test_keeps_short_safe_text(self):
        # Short, low-entropy text (like a hostname) should survive.
        out = es.redact("github.com — saved login present")
        self.assertIn("github.com", out)

    def test_none_safe(self):
        self.assertEqual(es.redact(None), "")


class TestValueShapeHelpers(unittest.TestCase):
    def test_high_entropy_detection(self):
        self.assertTrue(es.looks_high_entropy(FAKE_SECRET_VALUE))
        self.assertFalse(es.looks_high_entropy("short"))
        self.assertFalse(es.looks_high_entropy("aaaaaaaaaaaaaaaaaaaa"))  # low entropy

    def test_prefix_classification_does_not_retain_value(self):
        # The classifier keys off the SHAPE/prefix, returning a CLASS label.
        label = es.classify_value_prefix(FAKE_AWS_VALUE)
        self.assertEqual(label, "AWS access key id")
        # The label is a CLASS name, never the value itself.
        self.assertNotIn(FAKE_AWS_VALUE, label)


class TestEnvScanEndToEnd(unittest.TestCase):
    """Write a synthetic .env, scan it, and assert no value escapes."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="exposurescan_test_")
        env_path = Path(self.tmpdir) / ".env"
        env_path.write_text(
            "# synthetic test env — fake placeholder values only\n"
            f"STRIPE_SECRET_KEY={FAKE_SECRET_VALUE}\n"
            f"AWS_ACCESS_KEY_ID={FAKE_AWS_VALUE}\n"
            f"DATABASE_URL={FAKE_DB_URI}\n"
            "PUBLIC_APP_NAME=demo\n"   # non-sensitive
        )
        self.env_path = env_path

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_no_value_in_markdown(self):
        result = es.ScanResult()
        es.scan_env_files(result, Path(self.tmpdir))
        markdown = es.render_markdown(result, Path(self.tmpdir))
        for forbidden in (FAKE_SECRET_VALUE, FAKE_AWS_VALUE, "PLACEHOLDERpw-not-real"):
            self.assertNotIn(forbidden, markdown,
                             f"VALUE LEAKED INTO MARKDOWN: {forbidden!r}")

    def test_no_value_in_json_sidecar(self):
        result = es.ScanResult()
        es.scan_env_files(result, Path(self.tmpdir))
        sidecar = es.build_json_sidecar(result, Path(self.tmpdir))
        blob = json.dumps(sidecar)
        for forbidden in (FAKE_SECRET_VALUE, FAKE_AWS_VALUE, "PLACEHOLDERpw-not-real"):
            self.assertNotIn(forbidden, blob,
                             f"VALUE LEAKED INTO JSON: {forbidden!r}")

    def test_key_names_are_present(self):
        # We DO want the key NAMES — that's the whole point.
        result = es.ScanResult()
        es.scan_env_files(result, Path(self.tmpdir))
        names = " ".join(f.name for f in result.findings)
        self.assertIn("STRIPE_SECRET_KEY", names)
        self.assertIn("AWS_ACCESS_KEY_ID", names)
        self.assertIn("DATABASE_URL", names)

    def test_sensitive_keys_tiered_p0(self):
        result = es.ScanResult()
        es.scan_env_files(result, Path(self.tmpdir))
        tiers = {f.tier for f in result.findings if f.category == "env-file-summary"}
        self.assertIn("P0", tiers, "DB URI / AWS key should escalate the file to P0")


class TestLuhn(unittest.TestCase):
    def test_luhn_valid(self):
        # Standard public test card number (Visa test PAN, not a real card).
        self.assertTrue(es._luhn_ok("4111111111111111"))

    def test_luhn_invalid(self):
        self.assertFalse(es._luhn_ok("4111111111111112"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
