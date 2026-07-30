"""The Python library API (issue #48): contacts, groups, history, and group
sends as `User` methods, without shelling out to the CLI.

Three users on a live local relay, each with an isolated store. Asserts:
  1. Contacts: add/verify (relay fetch + fingerprint check), list as cards,
     lookup by name or fingerprint, remove; a tampered fingerprint raises
     PinMismatchError and records nothing.
  2. Groups: create (duplicate names refused), add/remove/rename, and
     send_group fan-out - every member's receive() gets the text with the
     group fields, and the receipt lists who was reached.
  3. Leave protocol: leave_group("name") notifies members, tombstones the
     gid (left_group_ids), and a straggler's next copy is refused, not
     delivered; join_group clears the tombstone.
  4. History: send/receive with save=True keep both directions, replayed
     oldest first; group history filters by room; peer+group refused.
  5. CLI interop: a library-created contact and group are visible to the
     CLI commands reading the same store, and vice versa - one schema, no
     drift (the regression jaredbarranco's issue worried about).

Uses port 8790 (see tests/README.md for the port registry).
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
from pathlib import Path

from retalk import PinMismatchError, User

PORT = 8790
URL = f"http://127.0.0.1:{PORT}"


def wait_for_port(port: int, timeout: float = 15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"server did not start on port {port}")


class TestLibraryAPI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        env = dict(os.environ, RETALK_SERVER_DB=os.path.join(self.tmp, "server.db"),
                   RETALK_SERVER_HOST="127.0.0.1", RETALK_SERVER_PORT=str(PORT),
                   RETALK_SERVER_AUDIENCE=URL)
        self.server = subprocess.Popen(
            [sys.executable, "-m", "retalk.server"], env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wait_for_port(PORT)
        self.u = {}
        for who in ("alice", "bob", "carol"):
            u = User(URL, f"{who}-secret", name=who,
                     store=os.path.join(self.tmp, f"{who}.db"))
            u.sync()                      # publish keys so peers can verify
            self.u[who] = u

    def tearDown(self):
        self.server.terminate()
        self.server.wait(timeout=10)

    def fp(self, who):
        return self.u[who].fingerprint()

    def test_contacts(self):
        a = self.u["alice"]
        # add by name, verify against the relay, and read back as a card
        card = a.add_contact(self.fp("bob"), "bob", verify=True)
        self.assertTrue(card["verified"])
        self.assertEqual(card["name"], "bob")
        self.assertEqual(card["fingerprint"], self.fp("bob"))
        # lookup by either handle; list is sorted cards
        self.assertEqual(a.contact("bob"), a.contact(self.fp("bob")))
        a.add_contact(self.fp("carol"), "carol")
        self.assertEqual([c["name"] for c in a.contacts()], ["bob", "carol"])
        self.assertFalse(a.contact("carol")["verified"])   # add-only, no keys
        # a fingerprint the relay's keys do NOT hash to is refused
        a.add_contact("f" * 32, "mallory")
        with self.assertRaises(Exception):   # relay: no such user / mismatch
            a.verify_contact("mallory")
        self.assertFalse(a.contact("mallory")["verified"])
        # manual keys that hash elsewhere raise PinMismatchError specifically
        with self.assertRaises(PinMismatchError):
            a.verify_contact("mallory",
                             identity_key=self.u["bob"].identity_key(),
                             signing_key=self.u["bob"].signing_key())
        # remove: by name, idempotent
        self.assertTrue(a.remove_contact("mallory"))
        self.assertFalse(a.remove_contact("mallory"))
        # bad input dies loudly
        with self.assertRaises(ValueError):
            a.add_contact("not-a-fingerprint")
        with self.assertRaises(KeyError):
            a.resolve_contact("stranger")

    def test_groups_and_fanout(self):
        a, b, c = self.u["alice"], self.u["bob"], self.u["carol"]
        a.add_contact(self.fp("bob"), "bob")
        a.add_contact(self.fp("carol"), "carol")
        g = a.create_group("team", ["bob", "carol"])
        self.assertEqual(sorted(g["members"]),
                         sorted([self.fp("bob"), self.fp("carol")]))
        with self.assertRaises(ValueError):        # duplicate local name
            a.create_group("team")
        # management: add/remove/rename by name or id
        a.group_remove("team", "carol")
        self.assertEqual(a.group("team")["members"], [self.fp("bob")])
        a.group_add(g["id"], "carol")
        self.assertIn(self.fp("carol"), a.group("team")["members"])
        a.rename_group("team", "work")
        self.assertIsNone(a.group("team"))
        self.assertEqual(a.group("work")["id"], g["id"])
        with self.assertRaises(ValueError):
            a.rename_group("work", "work")
        # fan-out: one call, both members receive the text with group fields
        receipt = a.send_group("work", "standup in 5")
        self.assertEqual(sorted(receipt["sent"]),
                         sorted([self.fp("bob"), self.fp("carol")]))
        self.assertEqual(receipt["failed"], {})
        self.assertEqual(receipt["group_id"], g["id"])
        for member in (b, c):
            msgs = member.receive(self.fp("alice"))
            self.assertEqual([m["text"] for m in msgs], ["standup in 5"])
            self.assertEqual(msgs[0]["group"]["id"], g["id"])
            self.assertEqual(msgs[0]["mid"], receipt["id"])

    def test_leave_join(self):
        a, b = self.u["alice"], self.u["bob"]
        a.add_contact(self.fp("bob"), "bob")
        b.add_contact(self.fp("alice"), "alice")
        g = a.create_group("room", ["bob"])
        a.send_group("room", "hello room")
        got = b.receive(self.fp("alice"))
        self.assertEqual(got[0]["text"], "hello room")
        # bob mirrors the roster and leaves: alice is told, the room dies
        b._group_save(g["id"], "room", [self.fp("alice")])
        result = b.leave_group("room")
        self.assertEqual(result["told"], [self.fp("alice")])
        self.assertIn(g["id"], b.left_group_ids())
        self.assertIsNone(b.group("room"))
        # alice consumes the control record and drops bob from her roster
        recs = a.receive(self.fp("bob"))
        self.assertEqual(recs[0]["kind"], "group_leave")
        self.assertEqual(recs[0]["group_id"], g["id"])
        # a straggler copy is refused, never delivered
        a.send(self.fp("bob"), "you still there?",
               group={"id": g["id"], "name": "room",
                      "members": [self.fp("alice"), self.fp("bob")]})
        self.assertEqual(b.receive(self.fp("alice")), [])
        # join clears the tombstone; fresh mail flows again
        b.join_group(g["id"])
        self.assertNotIn(g["id"], b.left_group_ids())
        a.send_group("room", "welcome back")
        texts = [m["text"] for m in b.receive(self.fp("alice"))]
        self.assertIn("welcome back", texts)

    def test_history(self):
        a, b = self.u["alice"], self.u["bob"]
        a.add_contact(self.fp("bob"), "bob")
        b.add_contact(self.fp("alice"), "alice")
        a.send(self.fp("bob"), "first", save=True)
        b.receive(self.fp("alice"), save=True)
        b.send(self.fp("alice"), "second", save=True)
        a.receive(self.fp("bob"), save=True)
        h = a.history(peer="bob")
        self.assertEqual([(m["direction"], m["text"]) for m in h],
                         [("out", "first"), ("in", "second")])
        self.assertEqual(h[1]["name"], "bob")      # saved-contact label
        # group history filters by room and carries the group fields
        g = a.create_group("thread", ["bob"])
        a.send_group("thread", "grouped", save=True)
        gh = a.history(group="thread")
        self.assertEqual([m["text"] for m in gh], ["grouped"])
        self.assertEqual(gh[0]["group_id"], g["id"])
        self.assertEqual(a.history(peer="bob"),
                         [m for m in a.history(peer="bob")])  # stable replay
        with self.assertRaises(ValueError):
            a.history(peer="bob", group="thread")
        # bob saved both directions too, from his own point of view
        self.assertEqual([(m["direction"], m["text"])
                          for m in b.history(peer="alice")],
                         [("in", "first"), ("out", "second")])
        # nothing is kept without save=True: retalk keeps no log by default
        a.send(self.fp("bob"), "third")
        self.assertNotIn("third", [m["text"] for m in a.history(peer="bob")])

    def test_cli_interop(self):
        """Library writes, CLI reads - and back. One schema, no drift."""
        home = os.path.join(self.tmp, "home")
        os.makedirs(home, exist_ok=True)
        Path(home, "config.json").write_text("{}")
        env = dict(os.environ, RETALK_HOME=home,
                   RETALK_PASSPHRASE="dana-secret", RETALK_RELAY=URL)
        for k in ("RETALK_USER", "RETALK_SAVE_MESSAGE"):
            env.pop(k, None)

        def cli(*cmd, expect=0):
            r = subprocess.run([sys.executable, "-m", "retalk.cli", *cmd],
                               capture_output=True, text=True, env=env)
            self.assertEqual(r.returncode, expect,
                             f"{cmd}: rc={r.returncode}\n{r.stderr}")
            return r

        cli("init", "-u", "dana", "--display-name", "dana")
        store = os.path.join(home, "dana", "store.db")
        # the library opens the SAME store the CLI made
        dana = User(URL, "dana-secret", name="dana", store=store)
        dana.add_contact(self.fp("bob"), "bob", verify=True)
        dana.create_group("shared", ["bob"])
        # CLI sees the library's contact (verified) and group
        out = cli("contacts", "--json", "-u", "dana").stdout
        cards = [json.loads(l) for l in out.splitlines() if l.strip()]
        self.assertEqual([(c["name"], c["verified"]) for c in cards],
                         [("bob", True)])
        out = cli("group", "list", "--json", "-u", "dana").stdout
        rooms = [json.loads(l) for l in out.splitlines() if l.strip()]
        self.assertEqual([r["name"] for r in rooms], ["shared"])
        # and the library sees a CLI-made contact
        cli("add", self.fp("carol"), "--peer", "carol", "-u", "dana")
        self.assertEqual(dana.contact("carol")["fingerprint"],
                         self.fp("carol"))


if __name__ == "__main__":
    unittest.main()
