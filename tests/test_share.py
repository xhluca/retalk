"""`retalk contacts --show C --json` emits a contact as a card; `retalk share`
sends it to a peer; `retalk import` saves a received card.

A "contact card" is the Contact object of docs/STANDARD.md: a peer's
fingerprint + a recommended nickname, plus its keys when verified. `contacts
--show C --json` prints one for a saved peer (the out-of-band, copy/paste form);
`share` encrypts the same card and sends it to a recipient over the relay, who
sees it in `receive` as a contact record and saves it with `import`. A card is
not a secret -- `import` re-checks any keys against the fingerprint, so a
tampered card is refused with PIN MISMATCH, never trusted.

Asserts:
  1. `contacts --show <peer> --json` prints the saved peer's card; a verified
     peer carries keys (verified=true), an unverified one has empty keys; `--as`
     overrides the recommended nickname; an unknown contact fails loudly; and
     `--show` without `--json` prints just the status row.
  2. Relay round-trip: alice `share`s bob with carol; carol `receive`s a contact
     record ({"kind":"contact","card":{...}}) carrying bob's recommended
     nickname and keys, and `import`s it -> carol now has bob as a verified
     contact. A chat message in the same mailbox still reads as {id,from,name,
     text}, so the two record kinds are distinguishable.
  3. `share --as` changes the recommended nickname the recipient sees.
  4. `import` of a card whose keys do not hash to its fingerprint is refused
     with PIN MISMATCH; `--as` overrides the saved nickname on import.

Run from the repo root: uv run python -m unittest discover -s tests
"""

import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

PORT = 8773


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


class TestShare(unittest.TestCase):
    def cli(self, *cmd, secret="cli-secret", expect=0):
        env = dict(os.environ,
                   RETALK_PASSPHRASE=secret,
                   RETALK_RELAY=f"http://127.0.0.1:{PORT}",
                   RETALK_HOME=os.path.join(self.tmp, "store"))
        env.pop("RETALK_USER", None)
        _h = os.path.join(self.tmp, "store"); os.makedirs(_h, exist_ok=True)
        _c = os.path.join(_h, "config.json")
        if not os.path.exists(_c): open(_c, "w").write("{}")  # hermetic: no default relay
        res = subprocess.run([sys.executable, "-m", "retalk.cli", *cmd],
                             capture_output=True, text=True, env=env,
                             input=getattr(self, "_stdin", None))
        self.assertEqual(res.returncode, expect,
                         f"{cmd}: rc={res.returncode}\n{res.stderr}")
        return res

    def cli_in(self, stdin, *cmd, **kw):
        self._stdin = stdin
        try:
            return self.cli(*cmd, **kw)
        finally:
            self._stdin = None

    def contacts(self, d):
        return {o["name"]: o for o in (json.loads(l) for l in
                self.cli("contacts", "--json", "--dir", d).stdout.splitlines())}

    def test_show_share_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.tmp = tmp
            server = start_server(os.path.join(tmp, "server.db"), PORT)
            try:
                a = os.path.join(tmp, "alice")
                b = os.path.join(tmp, "bob")
                c = os.path.join(tmp, "carol")
                aid = self.cli("init", "--dir", a,
                               "--display-name", "alice").stdout.strip()
                bid = self.cli("init", "--dir", b,
                               "--display-name", "bob").stdout.strip()
                cid = self.cli("init", "--dir", c,
                               "--display-name", "carol").stdout.strip()
                # bob and carol publish their keys so others can reach them
                self.cli("receive", "--all", "--dir", b)
                self.cli("receive", "--all", "--dir", c)

                # alice saves bob and records his keys from the relay
                self.cli("add", bid, "--name", "bob", "--dir", a)
                self.cli("verify", "bob", "--dir", a)
                b_ik = self.contacts(a)["bob"]["identity_key"]
                b_sk = self.contacts(a)["bob"]["signing_key"]
                self.assertTrue(b_ik and b_sk)

                # 1. contacts --show --json: a verified peer's card carries keys;
                #    --as renames; a raw fingerprint resolves to the saved peer;
                #    unknown fails; without --json it is just the status row
                card = json.loads(self.cli("contacts", "--show", "bob", "--json",
                                           "--dir", a).stdout)
                self.assertEqual(set(card), {"fingerprint", "name",
                                             "identity_key", "signing_key",
                                             "verified"})
                self.assertEqual((card["fingerprint"], card["name"],
                                  card["identity_key"], card["signing_key"],
                                  card["verified"]),
                                 (bid, "bob", b_ik, b_sk, True))
                self.assertEqual(
                    json.loads(self.cli("contacts", "--show", "bob", "--json",
                                        "--as", "bobby",
                                        "--dir", a).stdout)["name"], "bobby")
                self.assertEqual(
                    json.loads(self.cli("contacts", "--show", bid, "--json",
                                        "--dir", a).stdout)["name"],
                    "bob")  # raw id resolves to the saved contact
                self.cli("contacts", "--show", "nobody", "--dir", a, expect=2)
                # without --json, --show prints the single status row
                self.assertEqual(
                    self.cli("contacts", "--show", "bob", "--dir", a).stdout,
                    f"bob\t{bid}\tverified\n")

                # 2. share bob with carol over the relay; carol also gets a chat
                #    message, so the two record kinds must stay distinguishable
                self.cli("add", cid, "--name", "carol", "--dir", a)
                receipt = json.loads(
                    self.cli("share", "--peer", "carol", "bob", "--dir", a).stdout)
                self.assertEqual(set(receipt), {"id", "to", "shared"})
                self.assertEqual((receipt["to"], receipt["shared"]), (cid, bid))
                self.cli("send", "--peer", cid, "hi carol", "--dir", a)

                recs = [json.loads(l) for l in
                        self.cli("receive", "--all", "--dir", c).stdout.splitlines()]
                cards = [r for r in recs if r.get("kind") == "contact"]
                msgs = [r for r in recs if "text" in r]
                self.assertEqual(len(cards), 1, recs)
                self.assertEqual(len(msgs), 1, recs)
                self.assertEqual(msgs[0]["text"], "hi carol")  # chat unchanged
                self.assertEqual(set(msgs[0]), {"id", "from", "name", "text"})
                got = cards[0]
                self.assertEqual(set(got),
                                 {"id", "from", "name", "kind", "card"})
                self.assertEqual(got["from"], aid)
                self.assertEqual(got["name"], "~alice")  # carol never added alice
                self.assertEqual((got["card"]["fingerprint"], got["card"]["name"],
                                  got["card"]["identity_key"],
                                  got["card"]["signing_key"]),
                                 (bid, "bob", b_ik, b_sk))

                # carol imports the received card -> bob is a verified contact
                self.cli_in(json.dumps(got["card"]), "import", "--dir", c)
                cbob = self.contacts(c)["bob"]
                self.assertEqual((cbob["fingerprint"], cbob["identity_key"],
                                  cbob["signing_key"], cbob["verified"]),
                                 (bid, b_ik, b_sk, True))

                # 3. share --as: the recipient sees the chosen nickname
                self.cli("share", "--peer", "carol", "bob", "--as", "bobby",
                         "--dir", a)
                rec2 = [json.loads(l) for l in
                        self.cli("receive", "--all", "--dir", c).stdout.splitlines()]
                self.assertEqual([r["card"]["name"] for r in rec2
                                  if r.get("kind") == "contact"], ["bobby"])

                # 4. a tampered card (keys that don't hash to fp) is refused;
                #    --as overrides the saved nickname on import
                tampered = {"fingerprint": bid, "name": "mallory",
                            "identity_key": b_ik, "signing_key": "AAAAwrong="}
                res = self.cli_in(json.dumps(tampered), "import", "--dir", c,
                                  expect=2)
                self.assertIn("PIN MISMATCH", res.stderr)
                self.assertNotIn("mallory", self.contacts(c))
                good = {"fingerprint": bid, "name": "bob",
                        "identity_key": b_ik, "signing_key": b_sk}
                self.cli_in(json.dumps(good), "import", "--as", "bobby",
                            "--dir", c)
                self.assertIn("bobby", self.contacts(c))
                self.assertTrue(self.contacts(c)["bobby"]["verified"])
                print("PASS: contacts --show emits a card; share+receive+import "
                      "round-trips; tampered cards refused")
            finally:
                server.terminate()
                server.wait(timeout=10)

    def test_contacts_remove(self):
        """contacts --remove deletes a saved peer by name or fingerprint (the
        inverse of add); unknown fails; --show and --remove are exclusive.
        All offline -- no relay needed."""
        with tempfile.TemporaryDirectory() as tmp:
            self.tmp = tmp
            a = os.path.join(tmp, "alice")
            self.cli("init", "--dir", a, "--display-name", "alice")
            bid, cid = "b" * 32, "c" * 32
            self.cli("add", bid, "--name", "bob", "--dir", a)
            self.cli("add", cid, "--name", "carol", "--dir", a)
            self.assertEqual(set(self.contacts(a)), {"bob", "carol"})

            # remove by name, then by fingerprint
            self.cli("contacts", "--remove", "bob", "--dir", a)
            self.assertEqual(set(self.contacts(a)), {"carol"})
            self.cli("contacts", "--remove", cid, "--dir", a)
            self.assertEqual(self.contacts(a), {})

            # removing an unknown contact fails loudly
            self.cli("contacts", "--remove", "ghost", "--dir", a, expect=2)
            # --show and --remove are mutually exclusive
            self.cli("add", bid, "--name", "bob", "--dir", a)
            self.cli("contacts", "--show", "bob", "--remove", "bob",
                     "--dir", a, expect=2)
            print("PASS: contacts --remove deletes by name and fingerprint; "
                  "--show/--remove conflict refused")

    def inbox(self, d):
        return [json.loads(l) for l in self.cli(
            "import", "--inbox", "--list", "--json", "--dir", d
        ).stdout.splitlines()]

    def test_import_inbox(self):
        """receive saves shared contacts to the contact-inbox; import --inbox
        promotes them into saved peers and empties the inbox (a move)."""
        with tempfile.TemporaryDirectory() as tmp:
            self.tmp = tmp
            server = start_server(os.path.join(tmp, "server.db"), PORT)
            try:
                a = os.path.join(tmp, "alice")
                b = os.path.join(tmp, "bob")
                c = os.path.join(tmp, "carol")
                aid = self.cli("init", "--dir", a,
                               "--display-name", "alice").stdout.strip()
                bid = self.cli("init", "--dir", b,
                               "--display-name", "bob").stdout.strip()
                cid = self.cli("init", "--dir", c,
                               "--display-name", "carol").stdout.strip()
                self.cli("receive", "--all", "--dir", b)  # bob/carol publish keys
                self.cli("receive", "--all", "--dir", c)
                self.cli("add", bid, "--name", "bob", "--dir", a)
                self.cli("verify", "bob", "--dir", a)
                self.cli("add", cid, "--name", "carol", "--dir", a)

                # alice introduces bob to carol AND sends her a chat message
                self.cli("share", "--peer", "carol", "bob", "--dir", a)
                self.cli("send", "--peer", cid, "hi carol", "--dir", a)

                # receive prints chat + contact and stages the contact; carol is
                # not yet a peer of bob (the inbox is a staging area, not a peer)
                recs = [json.loads(l) for l in
                        self.cli("receive", "--all", "--dir", c).stdout.splitlines()]
                self.assertIn("hi carol", [r.get("text") for r in recs])
                self.assertEqual(self.cli("contacts", "--dir", c).stdout, "")

                # the inbox lists bob, verified, with provenance (from alice)
                staged = self.inbox(c)
                self.assertEqual(len(staged), 1)
                self.assertEqual((staged[0]["fingerprint"], staged[0]["name"],
                                  staged[0]["verified"], staged[0]["from_fp"]),
                                 (bid, "bob", True, aid))

                # import --inbox promotes bob into peers and empties the inbox
                res = self.cli("import", "--inbox", "--dir", c)
                self.assertIn("imported contact 'bob'", res.stderr)
                cbob = self.contacts(c)["bob"]
                self.assertEqual((cbob["fingerprint"], cbob["verified"]),
                                 (bid, True))
                self.assertEqual(self.inbox(c), [])       # moved, not copied

                # --no-save-contacts: a later share is delivered but not staged
                self.cli("share", "--peer", "carol", "bob", "--dir", a)
                self.cli("receive", "--all", "--no-save-contacts", "--dir", c)
                self.assertEqual(self.inbox(c), [])

                # selector + --as: stage again, import just "bob" under a new name
                self.cli("share", "--peer", "carol", "bob", "--dir", a)
                self.cli("receive", "--all", "--dir", c)
                self.assertEqual(len(self.inbox(c)), 1)
                self.cli("import", "--inbox", "bob", "--as", "bobby", "--dir", c)
                self.assertTrue(self.contacts(c)["bobby"]["verified"])
                self.assertEqual(self.inbox(c), [])
                print("PASS: receive stages shared contacts; import --inbox moves "
                      "them into peers (all / selector / --no-save-contacts)")
            finally:
                server.terminate()
                server.wait(timeout=10)


    def test_save_messages(self):
        """receive --save-messages keeps a sealed local copy that `history`
        replays; without the flag nothing is kept; the body is encrypted at
        rest."""
        with tempfile.TemporaryDirectory() as tmp:
            self.tmp = tmp
            server = start_server(os.path.join(tmp, "server.db"), PORT)
            try:
                a = os.path.join(tmp, "alice")
                b = os.path.join(tmp, "bob")
                aid = self.cli("init", "--dir", a,
                               "--display-name", "alice").stdout.strip()
                bid = self.cli("init", "--dir", b,
                               "--display-name", "bob").stdout.strip()
                self.cli("receive", "--all", "--dir", b)   # bob publishes keys

                # 1. without the flag, nothing is kept
                self.cli("send", "--peer", bid, "first", "--dir", a)
                self.cli("receive", "--all", "--dir", b)
                self.assertEqual(self.cli("history", "--dir", b).stdout, "")

                # 2. with the flag, the message is saved and history replays it
                #    in the same Message shape `receive` emits
                self.cli("send", "--peer", bid, "hello bob", "--dir", a)
                self.cli("receive", "--all", "--save-messages", "--dir", b)
                hist = [json.loads(l) for l in
                        self.cli("history", "--dir", b).stdout.splitlines()]
                self.assertEqual(len(hist), 1)
                self.assertEqual(set(hist[0]), {"id", "from", "name", "text"})
                self.assertEqual((hist[0]["from"], hist[0]["text"]),
                                 (aid, "hello bob"))

                # 3. the stored body is encrypted at rest (no plaintext on disk)
                conn = sqlite3.connect(os.path.join(b, "store.db"))
                body = conn.execute("SELECT body FROM messages").fetchone()[0]
                conn.close()
                self.assertNotIn("hello bob", body)

                # 4. --peer filters; saved messages keep their order
                self.cli("send", "--peer", bid, "again", "--dir", a)
                self.cli("receive", "--all", "--save-messages", "--dir", b)
                texts = [json.loads(l)["text"] for l in
                         self.cli("history", "--peer", aid, "--dir", b)
                         .stdout.splitlines()]
                self.assertEqual(texts, ["hello bob", "again"])
                print("PASS: receive --save-messages persists sealed copies; "
                      "history replays them")
            finally:
                server.terminate()
                server.wait(timeout=10)


if __name__ == "__main__":
    unittest.main()
