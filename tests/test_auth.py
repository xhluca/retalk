"""`retalk auth USER [PASSPHRASE]` selects a user for the shell session: it
verifies the credentials unlock the identity, then prints eval-able export
lines (a child process cannot modify its parent shell). Omitting the
passphrase errors clearly on a protected identity and is fine on a
--no-passphrase one; flags (-u/-p) win over the positionals.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PASS = "s3cret pass'word"          # embedded quote: quoting must survive eval


class TestAuth(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cli("init", "-u", "alice", "-p", PASS, "--no-register")
        self.cli("init", "-u", "bot", "--no-passphrase", "--no-register")

    def cli(self, *cmd, expect=0):
        home = os.path.join(self.tmp, "store")
        os.makedirs(home, exist_ok=True)
        cfg = os.path.join(home, "config.json")
        if not os.path.exists(cfg):
            Path(cfg).write_text("{}")          # hermetic: no default relay
        env = dict(os.environ, RETALK_HOME=home)
        for k in ("RETALK_USER", "RETALK_PASSPHRASE", "RETALK_RELAY",
                  "RETALK_SAVE_MESSAGE"):
            env.pop(k, None)
        r = subprocess.run([sys.executable, "-m", "retalk.cli", *cmd],
                           capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, expect,
                         f"{cmd}: rc={r.returncode}\n{r.stderr}")
        return r

    def test_exports_and_eval_roundtrip(self):
        r = self.cli("auth", "alice", PASS)
        self.assertIn("export RETALK_USER='alice'", r.stdout)
        self.assertIn("export RETALK_PASSPHRASE=", r.stdout)
        self.assertIn("authenticated as alice", r.stderr)
        # the printed lines survive a real shell eval, quote and all
        probe = subprocess.run(
            ["bash", "-c", r.stdout + 'echo "u=$RETALK_USER p=$RETALK_PASSPHRASE"'],
            capture_output=True, text=True)
        self.assertEqual(probe.stdout.strip(), f"u=alice p={PASS}")
        print("PASS: auth prints eval-able exports (quote-safe)")

    def test_no_passphrase_identity(self):
        r = self.cli("auth", "bot")
        self.assertIn("export RETALK_USER='bot'", r.stdout)
        self.assertNotIn("RETALK_PASSPHRASE", r.stdout)
        self.assertIn("no passphrase needed", r.stderr)
        print("PASS: auth on a --no-passphrase identity needs no passphrase")

    def test_omitted_passphrase_errors_clearly(self):
        r = self.cli("auth", "alice", expect=2)
        self.assertIn("passphrase is required", r.stderr)
        self.assertEqual(r.stdout, "")           # exports only on success
        print("PASS: omitted passphrase on a protected identity errors")

    def test_wrong_passphrase_and_unknown_user(self):
        r = self.cli("auth", "alice", "nope", expect=2)
        self.assertIn("could not unlock", r.stderr)
        r = self.cli("auth", "nobody", "x", expect=2)
        self.assertIn("no identity", r.stderr)
        print("PASS: wrong passphrase / unknown user refused")

    def test_flags_win_over_positionals(self):
        r = self.cli("auth", "alice", "nope", "-p", PASS)
        self.assertIn("authenticated as alice", r.stderr)
        print("PASS: -p beats the positional passphrase")


if __name__ == "__main__":
    unittest.main()
