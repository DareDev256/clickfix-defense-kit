#!/usr/bin/env python3
# CONFIRMED-SECRET-OK: every credential literal in this file is synthetic and
# non-functional. The SSH keys are generated fresh into a temp dir at test time
# and deleted in tearDown. The "tokens" are fixed placeholder strings that
# authenticate nowhere. Nothing here is, or ever was, a live credential.
"""
Regression suite for the v0.2.0 ExposureScan surfaces:

  * scan_dev_credentials  — SSH keys, cloud/registry credential files,
                            shell history            (plan item P1-4)
  * scan_wallets          — browser + desktop crypto wallets
  * scan_tcc              — the TCC grant-inheritance inventory (plan item P1-5)

The load-bearing tests are the LEAK tests. A new surface without one does not
ship: for every fixture we grep the rendered markdown AND the JSON sidecar for
the fixture's key material and token strings and assert ZERO hits. v0.1.0
shipped six leaks behind a passing unit test on redact(), because the leaks
lived in the f-strings between the scanner and the chokepoint.

Run:
    python3 -m unittest discover -s tests -v
"""

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import exposurescan as es  # noqa: E402


# Synthetic, non-functional placeholder credentials. Shaped like the real thing
# so the scanner's prefix classifier fires; valid nowhere.
FAKE_NPM_TOKEN = "npm_PLACEHOLDER0000000000000000000000000000"
FAKE_GH_TOKEN = "gho_PLACEHOLDER0000000000000000000000000000"
FAKE_HISTORY_TOKEN = "sk-PLACEHOLDERnotarealkey000000000000000000"
FAKE_AWS_ID = "AKIAPLACEHOLDER00000"

SSH_PASSPHRASE = "not-a-real-passphrase"


def _ssh_keygen_available() -> bool:
    return shutil.which("ssh-keygen") is not None


def _gen_key(path: Path, passphrase: str) -> None:
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", passphrase, "-C", "fixture",
         "-f", str(path), "-q"],
        check=True, capture_output=True,
    )


def _b64_body(key_path: Path) -> list[str]:
    """The base64 body lines of a private key file — i.e. the key MATERIAL."""
    lines = key_path.read_text().splitlines()
    return [ln for ln in lines if ln and not ln.startswith("-----")]


class _FakeHome(unittest.TestCase):
    """Base: a synthetic HOME that Path.home() resolves to for the test."""

    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="exposurescan_devcred_"))
        self._real_home = Path.home
        Path.home = staticmethod(lambda: self.home)   # type: ignore[assignment]
        # Never let a unit test shell out to `security`, `launchctl` or
        # `system_profiler` — it would make the suite report the developer's
        # machine instead of the fixture.
        self._real_run = es._safe_run
        es._safe_run = lambda cmd, timeout=8.0: ""    # type: ignore[assignment]

    def tearDown(self):
        Path.home = self._real_home                   # type: ignore[assignment]
        es._safe_run = self._real_run                 # type: ignore[assignment]
        shutil.rmtree(self.home, ignore_errors=True)

    def artifacts(self, result: es.ScanResult) -> tuple[str, str]:
        md = es.render_markdown(result, self.home)
        js = json.dumps(es.build_json_sidecar(result, self.home))
        return md, js


# ---------------------------------------------------------------------------
# 1. SSH keys: encrypted vs plaintext
# ---------------------------------------------------------------------------

@unittest.skipUnless(_ssh_keygen_available(), "ssh-keygen not available")
class TestSshKeys(_FakeHome):

    def setUp(self):
        super().setUp()
        self.ssh = self.home / ".ssh"
        self.ssh.mkdir(mode=0o700)
        self.plain = self.ssh / "id_ed25519_plain"
        self.enc = self.ssh / "id_ed25519_encrypted"
        _gen_key(self.plain, "")
        _gen_key(self.enc, SSH_PASSPHRASE)
        (self.ssh / "known_hosts").write_text("example.test ssh-ed25519 AAAA\n")

    def _findings(self):
        result = es.ScanResult()
        es.scan_ssh_keys(result)
        return {f.name.split(":")[0]: f for f in result.findings}, result

    def test_plaintext_key_is_p0_and_encrypted_key_is_not(self):
        by_name, _ = self._findings()
        self.assertIn("id_ed25519_plain", by_name)
        self.assertIn("id_ed25519_encrypted", by_name)
        self.assertEqual(by_name["id_ed25519_plain"].tier, "P0",
                         "a passphrase-less private key must be P0")
        self.assertNotEqual(by_name["id_ed25519_encrypted"].tier, "P0",
                            "an encrypted key must NOT be tiered P0")

    def test_classification_is_correct(self):
        self.assertEqual(es.classify_ssh_key(self.plain), ("ssh-ed25519", False))
        self.assertEqual(es.classify_ssh_key(self.enc), ("ssh-ed25519", True))

    def test_public_key_and_known_hosts_are_not_private_keys(self):
        self.assertIsNone(es.classify_ssh_key(self.ssh / "known_hosts"))
        self.assertIsNone(es.classify_ssh_key(Path(str(self.plain) + ".pub")))

    def test_key_material_never_reaches_any_artifact(self):
        result = es.ScanResult()
        es.scan_ssh_keys(result)
        md, js = self.artifacts(result)
        for key in (self.plain, self.enc):
            for line in _b64_body(key):
                for chunk in (line, line[:24], line[-24:]):
                    if len(chunk) < 16:
                        continue
                    self.assertNotIn(chunk, md, f"KEY MATERIAL IN MARKDOWN ({key.name})")
                    self.assertNotIn(chunk, js, f"KEY MATERIAL IN JSON ({key.name})")

    def test_pem_encrypted_header_is_detected(self):
        pem = self.ssh / "id_rsa_legacy"
        pem.write_text(
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "Proc-Type: 4,ENCRYPTED\n"
            "DEK-Info: AES-128-CBC,0000\n"
            "\nAAAAB3NzaC1lZDI1NTE5\n"
            "-----END RSA PRIVATE KEY-----\n"
        )
        self.assertEqual(es.classify_ssh_key(pem), ("rsa-pem", True))

    def test_unparseable_openssh_header_is_not_called_plaintext(self):
        """Unknown encryption state must never be reported as the P0 case."""
        broken = self.ssh / "id_broken"
        broken.write_text(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "bm90LWEtcmVhbC1rZXk=\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
        )
        info = es.classify_ssh_key(broken)
        self.assertIsNotNone(info)
        self.assertTrue(info[1], "an unparseable header must not be tiered P0")


# ---------------------------------------------------------------------------
# 2. Credential files, shell history, wallets — end to end through the CLI
# ---------------------------------------------------------------------------

class TestDevCredentialFixture(_FakeHome):

    WALLET_EXT = "nkbihfbeogaeaoehlefnkodbefgpgknn"      # MetaMask

    def setUp(self):
        super().setUp()
        (self.home / ".npmrc").write_text(
            f"//registry.npmjs.org/:_authToken={FAKE_NPM_TOKEN}\n"
            "cache=/tmp/npm\n"
        )
        gh = self.home / ".config" / "gh"
        gh.mkdir(parents=True)
        (gh / "hosts.yml").write_text(
            "github.com:\n"
            f"    oauth_token: {FAKE_GH_TOKEN}\n"
            "    user: fixture-user\n"
            "    git_protocol: ssh\n"
        )
        aws = self.home / ".aws"
        aws.mkdir()
        (aws / "credentials").write_text(
            "[default]\n"
            f"aws_access_key_id = {FAKE_AWS_ID}\n"
            "aws_secret_access_key = PLACEHOLDERsecret0000000000000000000000\n"
        )
        os.chmod(aws / "credentials", 0o644)     # deliberately world-readable
        (self.home / ".zsh_history").write_text(
            "cd ~/dev\n"
            "ls -la\n"
            f"export ANTHROPIC_API_KEY={FAKE_HISTORY_TOKEN}\n"
            "git status\n"
        )
        wallet = (self.home / "Library" / "Application Support" / "Google" /
                  "Chrome" / "Default" / "Local Extension Settings" / self.WALLET_EXT)
        wallet.mkdir(parents=True)
        (wallet / "000003.log").write_bytes(b"\x00leveldb")
        (wallet / "CURRENT").write_bytes(b"MANIFEST-000001\n")

    def _run(self):
        result = es.run_scan(
            self.home, do_notes=False, do_browser=False,
            do_dev_creds=True, do_tcc=False,
        )
        md, js = self.artifacts(result)
        return result, md, js

    def test_no_token_reaches_any_artifact(self):
        """The load-bearing assertion for this surface."""
        _, md, js = self._run()
        for secret in (FAKE_NPM_TOKEN, FAKE_GH_TOKEN, FAKE_HISTORY_TOKEN,
                       FAKE_AWS_ID, "PLACEHOLDERsecret"):
            self.assertNotIn(secret, md, f"TOKEN LEAKED INTO MARKDOWN: {secret[:12]}…")
            self.assertNotIn(secret, js, f"TOKEN LEAKED INTO JSON: {secret[:12]}…")
            # And the distinctive tail on its own, in case a prefix was stripped.
            self.assertNotIn(secret[8:24], md)
            self.assertNotIn(secret[8:24], js)

    def test_credential_files_are_reported_by_name_and_mode(self):
        result, md, _ = self._run()
        files = {f.location: f for f in result.findings
                 if f.category == "dev-credential-file"}
        self.assertIn("~/.npmrc", files)
        self.assertIn("~/.config/gh/hosts.yml", files)
        self.assertIn("~/.aws/credentials", files)
        # KEY NAMES survive; values do not.
        self.assertIn("_authToken", files["~/.npmrc"].detail)
        self.assertIn("oauth_token", files["~/.config/gh/hosts.yml"].detail)
        self.assertIn("aws_access_key_id", files["~/.aws/credentials"].detail)
        # A world-readable credential file is called out explicitly and escalated.
        self.assertEqual(files["~/.aws/credentials"].tier, "P0")
        self.assertIn("GROUP/OTHER READABLE", files["~/.aws/credentials"].shape)
        self.assertIn("WORLD/GROUP-READABLE", md)

    def test_shell_history_reports_counts_and_line_numbers_only(self):
        result, md, js = self._run()
        hist = [f for f in result.findings if f.category == "shell-history"]
        self.assertEqual(len(hist), 1)
        f = hist[0]
        self.assertEqual(f.tier, "P0")           # a known credential prefix class
        self.assertEqual(f.count, 1)
        self.assertIn("line(s) 3", f.name)       # the actionable part
        self.assertIn("API key", f.shape)        # the prefix CLASS, not the value
        self.assertNotIn(FAKE_HISTORY_TOKEN, md)
        self.assertNotIn(FAKE_HISTORY_TOKEN, js)

    def test_benign_history_produces_no_finding(self):
        (self.home / ".bash_history").write_text(
            "ls\ncd /Users/fixture/dev/some-project\ngit commit -m 'wip'\n"
            "brew upgrade\npython3 -m pytest\n"
        )
        result, _, _ = self._run()
        bash = [f for f in result.findings
                if f.category == "shell-history" and ".bash_history" in f.name]
        self.assertEqual(bash, [], "ordinary shell history must not fire")

    def test_wallet_extension_is_p0(self):
        result, md, _ = self._run()
        wallets = [f for f in result.findings if f.surface == "crypto-wallet"]
        self.assertTrue(wallets, "the wallet extension store was not found")
        self.assertEqual(wallets[0].tier, "P0")
        self.assertIn("MetaMask", wallets[0].name)
        self.assertIn("irreversible", wallets[0].pivot)
        self.assertIn("MetaMask", md)

    def test_cli_exit_code_is_3_on_the_fixture(self):
        out = self.home / "report.md"
        js = self.home / "report.json"
        stdout, sys.stdout = sys.stdout, open(os.devnull, "w")
        stderr, sys.stderr = sys.stderr, open(os.devnull, "w")
        try:
            rc = es.main([
                "--target", str(self.home), "--no-notes", "--no-browser",
                "--out", str(out), "--json", str(js),
            ])
        finally:
            sys.stdout.close(); sys.stdout = stdout
            sys.stderr.close(); sys.stderr = stderr
        self.assertEqual(rc, 3, "a P0 fixture must exit 3")
        # Same leak assertion, against the files actually written to disk.
        for text in (out.read_text(), js.read_text()):
            for secret in (FAKE_NPM_TOKEN, FAKE_GH_TOKEN, FAKE_HISTORY_TOKEN):
                self.assertNotIn(secret, text)


# ---------------------------------------------------------------------------
# 3. TCC grant inventory
# ---------------------------------------------------------------------------

def _build_tcc_db(path: Path, rows, legacy: bool = False) -> None:
    """A fixture TCC.db on the real `access` schema shape (modern or legacy)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    col = "allowed" if legacy else "auth_value"
    conn.execute(
        f"CREATE TABLE access (service TEXT NOT NULL, client TEXT NOT NULL, "
        f"client_type INTEGER NOT NULL, {col} INTEGER NOT NULL)"
    )
    conn.executemany(f"INSERT INTO access VALUES (?,?,?,{'?'})", rows)
    conn.commit()
    conn.close()


class TestTccInventory(_FakeHome):

    ROWS = [
        # (service, client, client_type, auth)
        ("kTCCServiceAccessibility", "com.apple.Terminal", 0, 2),
        ("kTCCServiceScreenCapture", "com.apple.Terminal", 0, 2),
        ("kTCCServiceSystemPolicyAllFiles", "/usr/libexec/sshd-keygen-wrapper", 1, 2),
        ("kTCCServiceAccessibility", "/opt/homebrew/bin/python3.12", 1, 2),
        ("kTCCServicePhotos", "com.example.OrdinaryPhotoApp", 0, 2),
        ("kTCCServiceCamera", "com.example.OrdinaryPhotoApp", 0, 2),
        # An app that holds Accessibility but does not run other code.
        ("kTCCServiceAccessibility", "com.example.WindowManager", 0, 2),
        # DENIED — must never be reported as a grant.
        ("kTCCServiceScreenCapture", "com.example.DeniedApp", 0, 0),
    ]

    def setUp(self):
        super().setUp()
        self.db = self.home / es.TCC_USER_DB
        _build_tcc_db(self.db, self.ROWS)
        self._real_system_db = es.TCC_SYSTEM_DB
        # Point the system DB at a path that does not exist, so the test reads
        # the fixture and nothing else.
        es.TCC_SYSTEM_DB = str(self.home / "no-such-system-TCC.db")

    def tearDown(self):
        es.TCC_SYSTEM_DB = self._real_system_db
        super().tearDown()

    def _scan(self):
        result = es.ScanResult()
        es.scan_tcc(result)
        return result, {f.name: f for f in result.findings}

    def test_terminal_with_accessibility_is_p0(self):
        _, by_name = self._scan()
        f = by_name.get("Terminal holds Accessibility (drive any app, read any window)")
        self.assertIsNotNone(f, "Terminal/Accessibility was not reported")
        self.assertEqual(f.tier, "P0")
        self.assertEqual(f.category, "tcc-grant-inheritance")
        # Plain language, per the plan: say what inheritance MEANS.
        self.assertIn("inherits", f.pivot)

    def test_ordinary_gui_app_with_photos_is_not_p0(self):
        result, _ = self._scan()
        photo = [f for f in result.findings
                 if "OrdinaryPhotoApp" in f.name or "OrdinaryPhotoApp" in f.detail]
        for f in photo:
            self.assertNotEqual(f.tier, "P0",
                                "an ordinary GUI app with Photos access is not P0")
        agg = [f for f in result.findings if f.category == "tcc-other"]
        self.assertTrue(agg, "low-risk grants should still be counted")
        self.assertEqual(agg[0].tier, "P3")
        self.assertIn("Photos", agg[0].shape)

    def test_non_vehicle_app_with_accessibility_is_reported_but_not_p0(self):
        _, by_name = self._scan()
        f = by_name.get("WindowManager holds Accessibility (drive any app, read any window)")
        self.assertIsNotNone(f)
        self.assertEqual(f.tier, "P2")
        self.assertEqual(f.category, "tcc-grant")

    def test_ssh_wrapper_and_bare_interpreter_are_p0(self):
        _, by_name = self._scan()
        self.assertEqual(by_name["sshd-keygen-wrapper holds Full Disk Access"].tier, "P0")
        self.assertEqual(
            by_name["python3.12 holds Accessibility (drive any app, read any window)"].tier,
            "P0",
        )

    def test_denied_rows_are_never_reported(self):
        result, _ = self._scan()
        blob = " ".join(f.name + f.detail for f in result.findings)
        self.assertNotIn("DeniedApp", blob)

    def test_legacy_allowed_schema_is_read(self):
        legacy = self.home / "legacy-TCC.db"
        _build_tcc_db(
            legacy,
            [("kTCCServiceAccessibility", "com.apple.Terminal", 0, 1)],
            legacy=True,
        )
        rows = es.read_tcc_grants(legacy)
        self.assertEqual(rows, [("kTCCServiceAccessibility", "com.apple.Terminal", 1)])

    def test_missing_db_degrades_to_a_note(self):
        self.db.unlink()
        result, _ = self._scan()
        self.assertEqual(
            [f for f in result.findings if f.surface == "tcc"], [],
            "no TCC findings should be invented without a DB",
        )
        self.assertTrue(any("TCC" in n for n in result.notes))

    def test_unreadable_db_degrades_to_a_note_not_a_crash(self):
        self.db.write_bytes(b"this is not a database")
        result, _ = self._scan()
        self.assertTrue(any("TCC" in n for n in result.notes))

    def test_vehicle_classifier(self):
        for client in ("com.apple.Terminal", "com.googlecode.iterm2",
                       "/usr/libexec/sshd-keygen-wrapper", "/bin/zsh",
                       "/opt/homebrew/bin/node", "com.teamviewer.TeamViewer",
                       "/usr/bin/osascript"):
            self.assertTrue(es.is_grant_inheritance_vehicle(client), client)
        for client in ("com.apple.Photos", "com.example.OrdinaryPhotoApp",
                       "/Applications/Numbers.app/Contents/MacOS/Numbers", ""):
            self.assertFalse(es.is_grant_inheritance_vehicle(client), client)


class TestClickfixPosture(_FakeHome):
    """The three adjacent one-liners bundled into --tcc."""

    def _with_output(self, mapping):
        def fake(cmd, timeout=8.0):
            for key, out in mapping.items():
                if key in " ".join(cmd):
                    return out
            return ""
        es._safe_run = fake                       # type: ignore[assignment]

    def test_secure_keyboard_entry_off_is_reported(self):
        self._with_output({"SecureKeyboardEntry": "0\n"})
        result = es.ScanResult()
        es.scan_clickfix_posture(result)
        names = [f.name for f in result.findings]
        self.assertIn("Terminal: Secure Keyboard Entry is OFF", names)

    def test_secure_keyboard_entry_on_is_silent(self):
        self._with_output({"SecureKeyboardEntry": "1\n"})
        result = es.ScanResult()
        es.scan_clickfix_posture(result)
        self.assertEqual(
            [f for f in result.findings if f.category == "secure-keyboard-entry"], [])

    def test_remote_access_surface(self):
        self._with_output({"print-disabled": (
            'disabled services = {\n'
            '\t"com.openssh.sshd" => false\n'
            '\t"com.apple.screensharing" => true\n'
            '}\n'
        )})
        result = es.ScanResult()
        es.scan_clickfix_posture(result)
        cats = [f.name for f in result.findings if f.category == "remote-access"]
        self.assertEqual(len(cats), 1, cats)
        self.assertIn("Remote Login (SSH)", cats[0])

    def test_secure_boot_reduced_is_reported_full_is_not(self):
        self._with_output({"SPiBridgeDataType":
                           "        Secure Boot: Reduced Security\n"
                           "        Allow All Kernel Extensions: Yes\n"})
        result = es.ScanResult()
        es.scan_clickfix_posture(result)
        sb = [f for f in result.findings if f.category == "secure-boot"]
        self.assertEqual(len(sb), 1)
        self.assertIn("Reduced Security", sb[0].name)

        self._with_output({"SPiBridgeDataType": "        Secure Boot: Full Security\n"})
        result = es.ScanResult()
        es.scan_clickfix_posture(result)
        self.assertEqual([f for f in result.findings if f.category == "secure-boot"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
