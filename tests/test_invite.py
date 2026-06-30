"""`retalk id --json` emits your OWN Contact card (incl. the relay you use);
`retalk id --invite-message` renders it as a copy-paste onboarding message. The
self-card is a valid Contact card, so a peer can `retalk import` it."""
import json
import os
import subprocess
import sys
import tempfile
import unittest


class TestInvite(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def cli(self, *cmd, stdin=None, expect=0):
        env = dict(os.environ, RETALK_PASSPHRASE="cli-secret",
                   RETALK_HOME=os.path.join(self.tmp, "store"))
        env.pop("RETALK_USER", None)
        _h = os.path.join(self.tmp, "store"); os.makedirs(_h, exist_ok=True)
        _c = os.path.join(_h, "config.json")
        if not os.path.exists(_c): open(_c, "w").write("{}")  # hermetic: no default relay
        env.pop("RETALK_RELAY", None)
        r = subprocess.run([sys.executable, "-m", "retalk.cli", *cmd],
                           capture_output=True, text=True, env=env, input=stdin)
        self.assertEqual(r.returncode, expect, f"{cmd}: rc={r.returncode}\n{r.stderr}")
        return r.stdout

    def test_self_card_invite_and_import(self):
        alice = os.path.join(self.tmp, "alice")
        self.cli("init", "--dir", alice, "--relay", "https://relay.example.com",
                 "--display-name", "alice")
        # --json: your own Contact card as JSON, including the relay
        card = json.loads(self.cli("id", "--dir", alice, "--json"))
        self.assertEqual(card["name"], "alice")
        self.assertTrue(card["verified"])
        self.assertEqual(card["relay"], "https://relay.example.com")
        self.assertEqual(len(card["fingerprint"]), 32)
        self.assertTrue(card["identity_key"] and card["signing_key"])
        # --invite-message: carries the key facts + honors --as
        msg = self.cli("id", "--dir", alice, "--invite-message", "--as", "ali")
        self.assertIn(card["fingerprint"], msg)
        self.assertIn("https://relay.example.com", msg)
        self.assertIn("--peer ali", msg)
        # the self-card is a valid Contact card: import it into another identity
        bob = os.path.join(self.tmp, "bob")
        self.cli("init", "--dir", bob, "--relay", "https://relay.example.com",
                 "--display-name", "bob")
        self.cli("import", "--dir", bob, stdin=json.dumps(card))
        con = json.loads(self.cli("contacts", "--dir", bob, "--json").splitlines()[0])
        self.assertEqual(con["fingerprint"], card["fingerprint"])
        self.assertTrue(con["verified"])


if __name__ == "__main__":
    unittest.main()
