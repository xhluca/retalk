"""`retalk contacts` lists a user's saved peers (offline; no server needed).

Asserts:
  1. With no saved peers, `contacts` prints nothing (zero lines), in both
     plain and --json form.
  2. After `add`, `contacts` lists each peer as NAME<tab>FINGERPRINT, sorted
     by name.
  3. `contacts --json` emits one Contact object per peer with exactly
     {"name", "fingerprint", "identity_key"} (see docs/STANDARD.md); the
     identity_key carries a pinned key, or "" when none was pinned.
  4. Selecting no identity is a loud refusal (nothing is guessed or created).

Needs no server: init, add, and contacts never contact the relay.
Run from the repo root: uv run python -m unittest discover -s tests
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest


class TestContacts(unittest.TestCase):
    def cli(self, *cmd, secret="cli-secret", expect=0):
        env = dict(os.environ,
                   RETALK_PASSPHRASE=secret,
                   XDG_DATA_HOME=os.path.join(self.tmp, "xdg"))
        env.pop("RETALK_USER", None)
        env.pop("RETALK_RELAY", None)
        res = subprocess.run([sys.executable, "-m", "retalk.cli", *cmd],
                             capture_output=True, text=True, env=env)
        self.assertEqual(res.returncode, expect,
                         f"{cmd}: rc={res.returncode}\n{res.stderr}")
        return res

    def test_contacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.tmp = tmp
            a = os.path.join(tmp, "alice")
            self.cli("init", "--dir", a, "--display-name", "alice")

            # 1. no peers yet -> empty output (plain and JSON)
            self.assertEqual(self.cli("contacts", "--dir", a).stdout, "")
            self.assertEqual(
                self.cli("contacts", "--json", "--dir", a).stdout, "")

            # save two peers; carol also gets a pinned identity key
            bid = "f1041c25c87351d8550b31cc6b13ab04"
            cid = "0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d"
            pin = "vGY3SomeBase64IdentityKey="
            self.cli("add", "bob", bid, "--dir", a)
            self.cli("add", "carol", cid, "--identity-key", pin, "--dir", a)

            # 2. plain output: NAME<tab>FINGERPRINT, sorted by name
            lines = self.cli("contacts", "--dir", a).stdout.splitlines()
            self.assertEqual(lines, [f"bob\t{bid}", f"carol\t{cid}"])

            # 3. --json: exact keys + values; identity_key "" when unpinned
            objs = [json.loads(l) for l in
                    self.cli("contacts", "--json", "--dir", a).stdout.splitlines()]
            self.assertEqual([set(o) for o in objs],
                             [{"name", "fingerprint", "identity_key"}] * 2)
            by_name = {o["name"]: o for o in objs}
            self.assertEqual(by_name["bob"]["fingerprint"], bid)
            self.assertEqual(by_name["bob"]["identity_key"], "")
            self.assertEqual(by_name["carol"]["fingerprint"], cid)
            self.assertEqual(by_name["carol"]["identity_key"], pin)

            # 4. no identity selected -> loud refusal, nothing created
            res = self.cli("contacts", expect=2)
            self.assertIn("no user selected", res.stderr)
            print("PASS: contacts lists saved peers (empty, plain, and JSON)")


if __name__ == "__main__":
    unittest.main()
