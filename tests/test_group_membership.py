"""Group membership like a group chat app: adding someone is announced to
everyone at once, rosters carry names, and fellow members can connect.

Asserts:
  1. `group add` announces the new roster to every member right away (no
     group message needed): the newcomer materializes the group, the others
     see a group_update record naming who was added and by whom.
  2. Rosters carry the sender's recommended names: `group members` shows
     ~name for members you have not saved.
  3. In --peers-only mode a fellow group member may write to you even if you
     never saved them; a stranger still may not, and a block still wins.
  4. `group connect` saves a fellow member as a verified contact, by
     ~name or fingerprint.
  5. `group remove` announces too: the removed member's client drops the
     group, after which their peers-only filter refuses the former co-members.
  6. `--no-notify` keeps the old offline behaviour (local change only).

Uses port 8784 (see tests/README.md for the port registry).
Run from the repo root: uv run python -m unittest discover -s tests
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

PORT = 8784
USERS = ("alice", "bob", "carol", "erin")


def wait_for_port(port: int, timeout: float = 15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"server did not start on port {port}")


class TestGroupMembership(unittest.TestCase):
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
        for who in USERS:
            self.fp[who] = self.cli(
                "init", "-u", who, "--no-passphrase",
                "--relay", f"http://127.0.0.1:{PORT}").stdout.strip()
        # alice knows everyone; the others only know alice (and are strict)
        for other in ("bob", "carol", "erin"):
            self.cli("add", self.fp[other], "--peer", other, "-u", "alice")
            self.cli("add", self.fp["alice"], "--peer", "alice", "-u", other)

    def tearDown(self):
        self.server.terminate()
        self.server.wait(timeout=10)

    def _env(self, user):
        home = os.path.join(self.tmp, f"home-{user}")
        os.makedirs(home, exist_ok=True)
        cfg = os.path.join(home, "config.json")
        if not os.path.exists(cfg):
            Path(cfg).write_text("{}")          # hermetic: no default relay
        env = dict(os.environ, RETALK_HOME=home)
        for k in ("RETALK_USER", "RETALK_PASSPHRASE", "RETALK_RELAY",
                  "RETALK_SAVE_MESSAGE", "RETALK_IDENTITY_FROM",
                  "RETALK_SESSION_ID"):
            env.pop(k, None)
        return env

    def cli(self, *cmd, expect=0):
        cmd = list(cmd)
        user = cmd[cmd.index("-u") + 1]
        r = subprocess.run([sys.executable, "-m", "retalk.cli", *cmd],
                           capture_output=True, text=True, env=self._env(user))
        self.assertEqual(r.returncode, expect,
                         f"{cmd}: rc={r.returncode}\n{r.stderr}")
        return r

    def recv(self, who):
        """Drain everything, strictly: --peers-only drops strangers."""
        out = self.cli("receive", "--all", "--peers-only", "-u", who).stdout
        return [json.loads(line) for line in out.splitlines() if line.strip()]

    def members(self, who, group="team"):
        out = self.cli("group", "members", group, "-u", who).stdout
        return dict(reversed(line.split("\t")) for line in out.splitlines())

    def start_team(self):
        """alice: team = {bob}; then adds carol, which is announced."""
        self.cli("group", "create", "team", "--members", "bob", "-u", "alice")
        r = self.cli("group", "add", "team", "carol", "-u", "alice")
        return json.loads(r.stdout)

    def test_add_is_announced_with_names(self):
        ann = self.start_team()
        self.assertEqual(ann["added"], [self.fp["carol"]])
        self.assertEqual(sorted(ann["sent"]),
                         sorted([self.fp["bob"], self.fp["carol"]]))
        # bob had never seen the room: the announcement materializes it
        recs = self.recv("bob")
        self.assertEqual([(r["kind"], r["from"], r["added"], r["group"])
                          for r in recs],
                         [("group_update", self.fp["alice"],
                           [self.fp["carol"]], "team")])
        m = self.members("bob")
        self.assertEqual(m[self.fp["carol"]], "~carol")   # recommended name
        self.assertEqual(m[self.fp["alice"]], "alice")    # bob's own label
        # the newcomer learns about the room at once, too
        self.assertEqual([r["kind"] for r in self.recv("carol")],
                         ["group_update"])
        listed = self.cli("group", "list", "--json", "-u", "carol").stdout
        self.assertEqual([json.loads(line)["name"] for line in listed.splitlines()],
                         ["team"])

    def test_co_members_reach_each_other_strangers_do_not(self):
        self.start_team()
        self.recv("bob")
        self.recv("carol")
        # bob never saved carol, carol never saved bob: co-members get through
        self.cli("send", "--peer", self.fp["carol"], "hi from bob", "-u", "bob")
        got = self.recv("carol")
        self.assertEqual([(r["from"], r["text"]) for r in got],
                         [(self.fp["bob"], "hi from bob")])
        # erin is in no group with carol: dropped by --peers-only
        self.cli("send", "--peer", self.fp["carol"], "hi from erin", "-u", "erin")
        self.assertEqual(self.recv("carol"), [])
        # a block still wins over group membership
        self.cli("block", self.fp["bob"], "-u", "carol")
        self.cli("send", "--peer", self.fp["carol"], "again", "-u", "bob")
        self.assertEqual(self.recv("carol"), [])

    def test_connect_saves_a_verified_contact(self):
        self.start_team()
        self.recv("bob")
        r = self.cli("group", "connect", "team", "~carol", "-u", "bob")
        card = json.loads(r.stdout)
        self.assertEqual((card["fingerprint"], card["name"], card["verified"]),
                         (self.fp["carol"], "carol", True))
        out = self.cli("contacts", "-u", "bob").stdout
        self.assertIn(f"carol\t{self.fp['carol']}\tverified", out)
        # by fingerprint, under a chosen name
        self.recv("carol")
        r = self.cli("group", "connect", "team", self.fp["bob"],
                     "--as", "bobby", "-u", "carol")
        self.assertEqual(json.loads(r.stdout)["name"], "bobby")
        # unknown member: a clear error
        r = self.cli("group", "connect", "team", "nobody", "-u", "carol",
                     expect=2)
        self.assertIn("no member", r.stderr)

    def test_remove_is_announced_and_drops_the_group(self):
        self.start_team()
        self.recv("bob")
        self.recv("carol")
        r = self.cli("group", "remove", "team", "carol", "-u", "alice")
        ann = json.loads(r.stdout)
        self.assertEqual(ann["removed"], [self.fp["carol"]])
        self.assertIn(self.fp["carol"], ann["sent"])       # told, too
        upd = self.recv("carol")
        self.assertEqual([(u["kind"], u["removed"]) for u in upd],
                         [("group_update", [self.fp["carol"]])])
        self.assertEqual(self.cli("group", "list", "-u", "carol").stdout, "")
        bob = self.recv("bob")
        self.assertEqual([u["removed"] for u in bob], [[self.fp["carol"]]])
        self.assertNotIn(self.fp["carol"], self.members("bob"))
        # no longer co-members: carol's strict filter refuses bob again
        self.cli("send", "--peer", self.fp["carol"], "still there?", "-u", "bob")
        self.assertEqual(self.recv("carol"), [])

    def test_no_notify_is_local_only(self):
        self.cli("group", "create", "team", "--members", "bob", "-u", "alice")
        r = self.cli("group", "add", "team", "carol", "--no-notify", "-u", "alice")
        self.assertEqual(r.stdout, "")
        self.assertIn("not announced", r.stderr)
        self.assertEqual(self.recv("carol"), [])
        # the change still spreads with the next group message
        self.cli("send", "--group", "team", "hello", "-u", "alice")
        got = self.recv("carol")
        self.assertEqual([(g["text"], g["group"]) for g in got],
                         [("hello", "team")])


if __name__ == "__main__":
    unittest.main()
