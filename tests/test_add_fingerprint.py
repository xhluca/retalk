"""`retalk add <fingerprint>` saves a peer by fingerprint; --peer is optional.
A name already taken by another contact errors (suggesting a free name) unless
--override reassigns it. Old name-keyed peer tables migrate to the new
fingerprint-keyed schema."""
from __future__ import annotations
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

FP1 = "f1041c25c87351d8550b31cc6b13ab04"
FP2 = "00e7fb3c717b284a304c031207511ee7"


class TestAddByFingerprint(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.a = os.path.join(self.tmp, "me")
        self.cli("init", "--dir", self.a, "--no-passphrase", "--no-register")

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

    def contacts(self):
        return {o["fingerprint"]: o for o in (json.loads(l) for l in
                self.cli("contacts", "--json", "--dir", self.a).stdout.splitlines())}

    def test_add_unnamed_and_named(self):
        self.cli("add", FP1, "--dir", self.a)                  # no name
        self.cli("add", FP2, "--peer", "bob", "--dir", self.a)
        c = self.contacts()
        self.assertEqual(c[FP1]["name"], "")                   # unnamed
        self.assertEqual(c[FP2]["name"], "bob")
        # an unnamed peer is still addressable by fingerprint
        row = self.cli("contacts", "--show", FP1, "--dir", self.a).stdout
        self.assertEqual(row.split("\t")[1], FP1)
        print("PASS: add by fingerprint — named + unnamed")

    def test_name_collision_and_override(self):
        self.cli("add", FP1, "--peer", "bob", "--dir", self.a)
        # a different fingerprint claiming the same name -> error + suggestion
        r = self.cli("add", FP2, "--peer", "bob", "--dir", self.a, expect=2)
        self.assertIn("already exists", r.stderr)
        self.assertIn("bob-1", r.stderr)
        # --override reassigns the name; the old holder is left unnamed
        self.cli("add", FP2, "--peer", "bob", "--override", "--dir", self.a)
        c = self.contacts()
        self.assertEqual(c[FP2]["name"], "bob")
        self.assertEqual(c[FP1]["name"], "")
        print("PASS: name collision errors; --override reassigns")

    def test_migrates_name_keyed_store(self):
        from retalk.cli import _saved_peers
        db = os.path.join(self.tmp, "old.db")
        con = sqlite3.connect(db)
        con.execute("CREATE TABLE peers(name TEXT PRIMARY KEY, fingerprint TEXT, "
                    "identity_key TEXT, signing_key TEXT)")
        con.execute("INSERT INTO peers VALUES('bob', ?, NULL, NULL)", (FP1,))
        con.commit()
        con.close()
        peers = _saved_peers(Path(db))                         # triggers migration
        self.assertEqual(peers, {FP1: ("bob", None, None)})
        pk = [r[1] for r in sqlite3.connect(db)
              .execute("PRAGMA table_info(peers)").fetchall() if r[5]]
        self.assertEqual(pk, ["fingerprint"])
        print("PASS: old name-keyed peers table migrates to fingerprint-keyed")


if __name__ == "__main__":
    unittest.main()
