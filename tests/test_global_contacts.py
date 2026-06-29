"""A global contact list (~/.retalk/contacts.db) is shared by every identity the
owner creates; `retalk add` writes there with no identity selected (or
--global). A per-identity list overrides the global one on the same fingerprint
or local name. `--global` and an explicit --user/--dir conflict."""
from __future__ import annotations
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

FP1 = "f1041c25c87351d8550b31cc6b13ab04"
FP2 = "00e7fb3c717b284a304c031207511ee7"


class TestGlobalContacts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cli("init", "-u", "alice", "--no-passphrase", "--no-register")
        self.cli("init", "-u", "bob", "--no-passphrase", "--no-register")

    def cli(self, *cmd, expect=0):
        home = os.path.join(self.tmp, "store")
        os.makedirs(home, exist_ok=True)
        cfg = os.path.join(home, "config.json")
        if not os.path.exists(cfg):
            Path(cfg).write_text("{}")          # hermetic: no default relay
        env = dict(os.environ, RETALK_PASSPHRASE="x", RETALK_HOME=home)
        env.pop("RETALK_USER", None)
        env.pop("RETALK_RELAY", None)
        r = subprocess.run([sys.executable, "-m", "retalk.cli", *cmd],
                           capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, expect,
                         f"{cmd}: rc={r.returncode}\n{r.stderr}")
        return r

    def test_global_shared_user_scoped(self):
        self.cli("add", FP1, "--name", "shared")              # -> global (no user)
        self.cli("add", FP2, "--name", "mine", "-u", "alice")  # -> alice only
        # every identity sees the global contact
        self.assertIn(FP1, self.cli("contacts", "-u", "alice").stdout)
        self.assertIn(FP1, self.cli("contacts", "-u", "bob").stdout)
        # the global list with no identity selected
        gl = self.cli("contacts").stdout
        self.assertIn(FP1, gl)
        self.assertNotIn(FP2, gl)
        # user-specific stays scoped to that identity
        self.assertIn(FP2, self.cli("contacts", "-u", "alice").stdout)
        self.assertNotIn(FP2, self.cli("contacts", "-u", "bob").stdout)
        print("PASS: global contacts shared; user-specific scoped")

    def test_user_overrides_global_by_name(self):
        self.cli("add", FP1, "--name", "shared")                          # global
        self.cli("add", FP2, "--name", "shared", "-u", "alice", "--override")
        # alice's 'shared' resolves to her fingerprint; the global to the other
        self.assertEqual(self.cli("contacts", "--show", "shared", "-u", "alice")
                         .stdout.split("\t")[1], FP2)
        self.assertEqual(self.cli("contacts", "--show", "shared")
                         .stdout.split("\t")[1], FP1)
        # bob (no override) still sees the global one
        self.assertEqual(self.cli("contacts", "--show", "shared", "-u", "bob")
                         .stdout.split("\t")[1], FP1)
        print("PASS: user-specific contact overrides global by name")

    def test_global_and_user_conflict(self):
        r = self.cli("add", FP1, "--global", "-u", "alice", expect=2)
        self.assertIn("pick one", r.stderr.lower())
        print("PASS: --global with an explicit --user errors")


if __name__ == "__main__":
    unittest.main()
