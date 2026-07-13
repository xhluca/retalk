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

    def _env(self, user):
        # one RETALK_HOME per user: four separate simulated machines that
        # share nothing but the relay (no common config or global contacts)
        home = os.path.join(self.tmp, f"home-{user}")
        os.makedirs(home, exist_ok=True)
        cfg = os.path.join(home, "config.json")
        if not os.path.exists(cfg):
            Path(cfg).write_text("{}")          # hermetic: no default relay
        env = dict(os.environ, RETALK_HOME=home)
        for k in ("RETALK_USER", "RETALK_PASSPHRASE", "RETALK_RELAY",
                  "RETALK_SAVE_MESSAGE"):
            env.pop(k, None)
        return env

    def cli(self, *cmd, expect=0):
        cmd = list(cmd)
        if "-u" in cmd:                        # whose machine runs this?
            user = cmd[cmd.index("-u") + 1]
        elif cmd and cmd[0] == "show":
            user = cmd[1]
        else:
            self.fail(f"can't tell whose machine runs {cmd}")
        r = subprocess.run([sys.executable, "-m", "retalk.cli", *cmd],
                           capture_output=True, text=True,
                           env=self._env(user))
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
        db = os.path.join(self.tmp, "home-alice", "alice", "store.db")
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

    def test_membership_management(self):
        self.cli("group", "create", "team", "--members", "bob,carol",
                 "-u", "alice")
        # members: roster with local names
        out = self.cli("group", "members", "team", "-u", "alice").stdout
        self.assertIn("bob", out)
        self.assertIn(self.fp["carol"], out)
        # duplicate name refused
        r = self.cli("group", "create", "team", "--members", "bob",
                     "-u", "alice", expect=2)
        self.assertIn("already exists", r.stderr)
        # remove carol: she stops getting alice's copies, bob still does
        self.cli("group", "remove", "team", "carol", "-u", "alice")
        self.cli("send", "--group", "team", "post-removal", "-u", "alice")
        self.assertEqual(self.recv("carol", "alice"), [])
        self.assertEqual([m["text"] for m in self.recv("bob", "alice")],
                         ["post-removal"])
        # removing a non-member is a clear error
        r = self.cli("group", "remove", "team", "carol", "-u", "alice",
                     expect=2)
        self.assertIn("none of those are members", r.stderr)
        # delete: the group is gone locally, sends to it refuse
        self.cli("group", "delete", "team", "-u", "alice")
        self.assertNotIn("team", self.cli("group", "list", "-u", "alice")
                         .stdout)
        r = self.cli("send", "--group", "team", "x", "-u", "alice", expect=2)
        self.assertIn("no group", r.stderr)
        print("PASS: members/remove/delete manage the roster as documented")

    def test_fanout_partial_failure_isolated(self):
        # one roster member that exists nowhere: their copy fails, the
        # others' still go out, and the receipt says exactly that
        ghost = "0123456789abcdef0123456789abcdef"
        self.cli("group", "create", "team", "--members",
                 f"bob,carol,{ghost}", "-u", "alice")
        r = self.cli("send", "--group", "team", "who is missing?",
                     "-u", "alice", expect=2)      # exit 2 flags the failure
        receipt = json.loads(r.stdout)
        self.assertEqual((receipt["sent"], receipt["failed"]), (2, 1))
        self.assertIn(ghost, r.stderr)
        for who in ("bob", "carol"):               # the live members got it
            self.assertEqual([m["text"] for m in self.recv(who, "alice")],
                             ["who is missing?"])
        print("PASS: a dead member never blocks the rest of the fan-out")

    def test_show_group_follow_live(self):
        self.cli("group", "create", "team", "--members", "bob,carol",
                 "-u", "alice")
        self.cli("send", "--group", "team", "opener", "-u", "alice", "--save")
        self.recv("bob", "alice")                  # bob materializes the group
        # alice leaves the room open with --follow; bob posts while it runs
        proc = subprocess.Popen(
            [sys.executable, "-m", "retalk.cli", "show", "alice",
             "--group", "team", "--follow"],
            env=self._env("alice"), stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL)
        try:
            time.sleep(2)                          # let the first poll run
            self.cli("send", "--group", "team", "bob live post", "-u", "bob")
            deadline = time.time() + 15
            got = ""
            os.set_blocking(proc.stdout.fileno(), False)
            while time.time() < deadline and "bob live post" not in got:
                got += (proc.stdout.read() or b"").decode("utf-8", "replace")
                time.sleep(0.5)
        finally:
            proc.terminate()
            proc.wait(timeout=10)
        self.assertIn("opener", got)               # backlog rendered
        self.assertIn("🔵 bob", got)               # sender got a room look
        self.assertIn("bob live post", got)        # and the live message landed
        print("PASS: show --group --follow renders live room traffic")

    def test_multiple_groups_isolated_views(self):
        # one user in two rooms at once: tags, filters, and audiences never
        # bleed between them
        self.cli("group", "create", "team", "--members", "bob,carol",
                 "-u", "alice")
        self.cli("group", "create", "family", "--members", "dave",
                 "-u", "alice")
        self.cli("send", "--group", "team", "work ping", "-u", "alice",
                 "--save")
        self.cli("send", "--group", "family", "dinner at 7", "-u", "alice",
                 "--save")
        bob = self.recv("bob", "alice")
        self.assertEqual([(m["group"], m["text"]) for m in bob],
                         [("team", "work ping")])
        dave = self.recv("dave", "alice")
        self.assertEqual([(m["group"], m["text"]) for m in dave],
                         [("family", "dinner at 7")])
        t = [json.loads(l)["text"] for l in
             self.cli("history", "--group", "team", "-u", "alice")
             .stdout.splitlines()]
        f = [json.loads(l)["text"] for l in
             self.cli("history", "--group", "family", "-u", "alice")
             .stdout.splitlines()]
        self.assertEqual((t, f), (["work ping"], ["dinner at 7"]))
        out = self.cli("show", "alice", "--group", "team").stdout
        self.assertIn("work ping", out)
        self.assertNotIn("dinner at 7", out)
        print("PASS: two concurrent rooms stay fully isolated")

    def test_group_name_collision_gets_suffixed(self):
        # bob already has his OWN room called "team"; alice's different
        # "team" arrives and must not shadow it (or vice versa)
        self.cli("group", "create", "team", "--members", "carol", "-u", "bob")
        r = self.cli("group", "create", "team", "--members", "bob,carol",
                     "-u", "alice")
        alice_gid = json.loads(r.stdout)["group_id"]
        self.cli("send", "--group", "team", "alice's room", "-u", "alice")
        self.recv("bob", "alice")
        rows = [json.loads(l) for l in
                self.cli("group", "list", "--json", "-u", "bob")
                .stdout.splitlines()]
        byname = {g["name"]: g for g in rows}
        self.assertEqual(len(rows), 2)
        self.assertIn("team", byname)             # bob's room keeps its name
        self.assertIn("team-2", byname)           # the foreign one is suffixed
        self.assertEqual(byname["team-2"]["group_id"], alice_gid)
        # bob's `send --group team` deterministically means HIS room
        self.cli("send", "--group", "team", "bobs own room", "-u", "bob")
        got = self.recv("carol", "bob")
        self.assertEqual(got[0]["group_id"], byname["team"]["group_id"])
        # further traffic on alice's room updates team-2 without rename churn
        self.cli("send", "--group", "team", "again", "-u", "alice")
        self.recv("bob", "alice")
        names = {json.loads(l)["name"] for l in
                 self.cli("group", "list", "--json", "-u", "bob")
                 .stdout.splitlines()}
        self.assertEqual(names, {"team", "team-2"})
        print("PASS: same-named foreign group is suffixed, never ambiguous")


if __name__ == "__main__":
    unittest.main()
