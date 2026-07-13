"""Group chat = client-side fan-out: `send --group` encrypts one pairwise copy
per member, the roster travels inside the encrypted envelope, receivers
materialize the group automatically and can reply to everyone, and roster
changes propagate cooperatively (last sender wins). The relay only ever sees
ordinary pairwise messages.
"""
from __future__ import annotations

import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

PORT = 8776


def wait_for_port(port: int, timeout: float = 15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"server did not start on port {port}")


class TestGroups(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        env = dict(os.environ, RETALK_SERVER_DB=os.path.join(self.tmp, "server.db"),
                   RETALK_SERVER_HOST="127.0.0.1", RETALK_SERVER_PORT=str(PORT),
                   RETALK_SERVER_AUDIENCE=f"http://127.0.0.1:{PORT}")
        self.server = subprocess.Popen(
            [sys.executable, "-m", "retalk.server"], env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wait_for_port(PORT)
        self.fp = {}
        for who in ("alice", "bob", "carol", "dave"):
            self.fp[who] = self.cli(
                "init", "-u", who, "--no-passphrase",
                "--relay", f"http://127.0.0.1:{PORT}").stdout.strip()
        # everyone saves everyone (names make assertions readable)
        for me in ("alice", "bob", "carol", "dave"):
            for other in ("alice", "bob", "carol", "dave"):
                if me != other:
                    self.cli("add", self.fp[other], "--peer", other, "-u", me)

    def tearDown(self):
        self.server.terminate()
        self.server.wait(timeout=10)

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

    def recv(self, who, frm):
        out = self.cli("receive", "--peer", frm, "-u", who, "--save").stdout
        return [json.loads(l) for l in out.splitlines()]

    def test_roundtrip_reply_all_and_drift(self):
        # alice creates the room and posts
        r = self.cli("group", "create", "team", "--members", "bob,carol",
                     "-u", "alice")
        gid = json.loads(r.stdout)["group_id"]
        self.cli("send", "--group", "team", "hello room", "-u", "alice",
                 "--save")

        # both members get it, tagged with the group
        for who in ("bob", "carol"):
            msgs = self.recv(who, "alice")
            self.assertEqual([m["text"] for m in msgs], ["hello room"])
            self.assertEqual(msgs[0]["group"], "team")
            self.assertEqual(msgs[0]["group_id"], gid)

        # carol never created anything, yet the group materialized for her
        groups = self.cli("group", "list", "-u", "carol").stdout
        self.assertIn("team", groups)
        self.assertIn(gid, groups)

        # ...well enough to reply to EVERYONE
        self.cli("send", "--group", "team", "hi all, carol here",
                 "-u", "carol", "--save")
        self.assertEqual([m["text"] for m in self.recv("alice", "carol")],
                         ["hi all, carol here"])
        self.assertEqual([m["text"] for m in self.recv("bob", "carol")],
                         ["hi all, carol here"])

        # drift: alice adds dave; her next send teaches bob the new roster
        self.cli("group", "add", "team", "dave", "-u", "alice")
        self.cli("send", "--group", "team", "welcome dave", "-u", "alice")
        self.recv("bob", "alice")
        bob_groups = [json.loads(l) for l in
                      self.cli("group", "list", "--json", "-u", "bob")
                      .stdout.splitlines()]
        team = next(g for g in bob_groups if g["group_id"] == gid)
        self.assertIn(self.fp["dave"], team["members"])
        # and dave — brand new to the room — got the message too
        self.assertEqual([m["text"] for m in self.recv("dave", "alice")],
                         ["welcome dave"])
        print("PASS: group round-trip, non-creator reply-all, roster drift")

    def test_history_and_show_group_views(self):
        self.cli("group", "create", "team", "--members", "bob,carol",
                 "-u", "alice")
        self.cli("send", "--group", "team", "first post", "-u", "alice",
                 "--save")
        self.recv("bob", "alice")
        self.cli("send", "--group", "team", "second post", "-u", "bob",
                 "--save")
        self.recv("alice", "bob")

        hist = [json.loads(l) for l in
                self.cli("history", "--group", "team", "-u", "alice")
                .stdout.splitlines()]
        self.assertEqual([h["text"] for h in hist],
                         ["first post", "second post"])
        self.assertTrue(all(h["group"] == "team" for h in hist))

        out = self.cli("show", "alice", "--group", "team").stdout
        self.assertIn("alice ⇄ team", out)
        self.assertIn("first post", out)
        self.assertIn("second post", out)
        self.assertIn("🔵 bob", out)              # senders get their own look
        self.assertLess(out.index("first post"), out.index("second post"))
        print("PASS: history --group and show --group render the room")

    def test_migration_and_errors(self):
        # a pre-group messages table (no gid/gname) migrates in place
        self.cli("send", "--peer", "bob", "dm", "-u", "alice", "--save")
        db = os.path.join(self.tmp, "store", "alice", "store.db")
        con = sqlite3.connect(db)
        with con:
            con.execute("CREATE TABLE _m AS SELECT msg_id, from_fp, from_name,"
                        " peer_fp, direction, body, ts FROM messages")
            con.execute("DROP TABLE messages")
            con.execute("ALTER TABLE _m RENAME TO messages")
        con.close()
        hist = self.cli("history", "-u", "alice").stdout
        self.assertIn("dm", hist)                 # migrated, old rows intact

        r = self.cli("send", "--group", "nope", "x", "-u", "alice", expect=2)
        self.assertIn("no group", r.stderr)
        r = self.cli("send", "--peer", "bob", "--group", "team", "x",
                     "-u", "alice", expect=2)
        self.assertIn("not both", r.stderr)
        r = self.cli("group", "create", "team", "-u", "alice", expect=2)
        self.assertIn("at least one member", r.stderr)
        print("PASS: messages-table migration and group error paths")


if __name__ == "__main__":
    unittest.main()
