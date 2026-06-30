"""`retalk contacts` lists saved peers; `retalk verify` records their keys.

A peer added with `retalk add` is "incomplete" (name + fingerprint only).
`retalk verify` makes the first-contact key exchange explicit: it fetches the
peer's keys from the relay (or takes them manually), checks they hash to the
saved fingerprint, and records them — after which `contacts` shows them and the
peer reads as verified.

Asserts:
  1. `add` saves an unverified contact: `contacts` shows it with empty keys and
     verified=false; `add` no longer accepts `--identity-key`.
  2. Manual `verify --identity-key/--signing-key` with keys that hash to the
     fingerprint records them (verified=true); wrong keys are refused with PIN
     MISMATCH and leave the contact unverified; one key alone is rejected.
  3. `verify` on an unknown contact, and any command with no identity selected,
     fail loudly.
  4. `verify <peer>` (no keys) fetches them from the relay and records the
     peer's real keys (server-backed, port 8772).

Run from the repo root: uv run python -m unittest discover -s tests
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest

PORT = 8772


def wait_for_port(port: int, timeout: float = 15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"server did not start on port {port}")


def start_server(db: str, port: int) -> subprocess.Popen:
    env = dict(os.environ, RETALK_SERVER_DB=db, RETALK_SERVER_HOST="127.0.0.1",
               RETALK_SERVER_PORT=str(port),
               RETALK_SERVER_AUDIENCE=f"http://127.0.0.1:{port}")
    proc = subprocess.Popen(
        [sys.executable, "-m", "retalk.server"],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    wait_for_port(port)
    return proc


class TestContacts(unittest.TestCase):
    def cli(self, *cmd, secret="cli-secret", expect=0):
        env = dict(os.environ,
                   RETALK_PASSPHRASE=secret,
                   RETALK_HOME=os.path.join(self.tmp, "store"))
        env.pop("RETALK_USER", None)
        _h = os.path.join(self.tmp, "store"); os.makedirs(_h, exist_ok=True)
        _c = os.path.join(_h, "config.json")
        if not os.path.exists(_c): open(_c, "w").write("{}")  # hermetic: no default relay
        if getattr(self, "relay", None):
            env["RETALK_RELAY"] = self.relay
        else:
            env.pop("RETALK_RELAY", None)
        res = subprocess.run([sys.executable, "-m", "retalk.cli", *cmd],
                             capture_output=True, text=True, env=env)
        self.assertEqual(res.returncode, expect,
                         f"{cmd}: rc={res.returncode}\n{res.stderr}")
        return res

    def contacts(self, a):
        return {o["name"]: o for o in (json.loads(l) for l in
                self.cli("contacts", "--json", "--dir", a).stdout.splitlines())}

    def test_listing_and_manual_verify(self):
        from retalk import User  # for a consistent (fingerprint, ik, sk) triple

        with tempfile.TemporaryDirectory() as tmp:
            self.tmp = tmp
            a = os.path.join(tmp, "alice")
            self.cli("init", "--dir", a, "--display-name", "alice")

            # bob's real keys, generated locally (no server needed)
            b = User("http://127.0.0.1:1", "bsecret",
                     store=os.path.join(tmp, "bsrc.db"))
            bid, b_ik = b.fingerprint(), b.identity_key()
            b_sk = b._load_account().ed25519_key.to_base64()

            # 1. add saves an unverified contact; --identity-key is gone
            self.assertEqual(self.cli("contacts", "--dir", a).stdout, "")
            self.cli("add", bid, "--name", "bob", "--dir", a)
            self.cli("add", bid, "--name", "bob", "--identity-key", b_ik, "--dir", a,
                     expect=2)  # flag removed
            line = self.cli("contacts", "--dir", a).stdout.strip()
            self.assertEqual(line, f"bob\t{bid}\tunverified")
            bob = self.contacts(a)["bob"]
            self.assertEqual(set(bob),
                             {"name", "fingerprint", "identity_key",
                              "signing_key", "verified"})
            self.assertEqual((bob["identity_key"], bob["signing_key"],
                              bob["verified"]), ("", "", False))

            # 2a. one key alone is rejected
            self.cli("verify", "bob", "--identity-key", b_ik, "--dir", a,
                     expect=2)
            # 2b. wrong keys -> PIN MISMATCH, contact stays unverified
            res = self.cli("verify", "bob", "--identity-key", b_ik,
                           "--signing-key", "AAAAwrongkeyAAAA=", "--dir", a,
                           expect=2)
            self.assertIn("PIN MISMATCH", res.stderr)
            self.assertFalse(self.contacts(a)["bob"]["verified"])
            # 2c. correct keys -> recorded, verified
            self.cli("verify", "bob", "--identity-key", b_ik,
                     "--signing-key", b_sk, "--dir", a)
            bob = self.contacts(a)["bob"]
            self.assertEqual((bob["identity_key"], bob["signing_key"],
                              bob["verified"]), (b_ik, b_sk, True))
            self.assertEqual(self.cli("contacts", "--dir", a).stdout.strip(),
                             f"bob\t{bid}\tverified")

            # 3. verifying an unknown contact fails loudly
            res = self.cli("verify", "nobody", "--dir", a, expect=2)
            self.assertIn("no saved contact", res.stderr)
            # with no identity selected, `contacts` shows the (empty) global list
            self.assertEqual(self.cli("contacts").stdout, "")
            print("PASS: contacts listing + manual verify (incl. PIN MISMATCH)")

    def test_verify_fetches_from_relay(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.tmp = tmp
            self.relay = f"http://127.0.0.1:{PORT}"
            server = start_server(os.path.join(tmp, "server.db"), PORT)
            try:
                a = os.path.join(tmp, "alice")
                b = os.path.join(tmp, "bob")
                self.cli("init", "--dir", a, "--display-name", "alice")
                bid = self.cli("init", "--dir", b,
                               "--display-name", "bob").stdout.strip()
                b_ik = json.loads(
                    self.cli("id", "--json", "--dir", b).stdout)["identity_key"]
                self.cli("receive", "--all", "--dir", b)  # bob publishes keys

                # alice adds bob, then fetches+records his keys from the relay
                self.cli("add", bid, "--name", "bob", "--dir", a)
                self.assertFalse(self.contacts(a)["bob"]["verified"])
                res = self.cli("verify", "bob", "--dir", a)
                self.assertIn("from the relay", res.stderr)
                bob = self.contacts(a)["bob"]
                self.assertTrue(bob["verified"])
                self.assertEqual(bob["identity_key"], b_ik)
                self.assertNotEqual(bob["signing_key"], "")
                print("PASS: verify fetches and records a peer's keys from relay")
            finally:
                server.terminate()
                server.wait(timeout=10)


if __name__ == "__main__":
    unittest.main()
