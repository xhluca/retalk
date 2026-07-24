"""Agent-integration receive flags: repeatable --peer, --interval, --quiet.

Asserts:
  1. --peer is repeatable: one call drains exactly the named senders (each
     scoped separately) and an unnamed third sender's mail stays put.
  2. A single --peer behaves exactly as before (regression).
  3. --quiet drops the identity banner from stderr; without it the banner is
     printed there (and never on stdout).
  4. --interval without --follow dies; --interval 0 dies; both loudly.
  5. --follow with a custom --interval delivers messages from BOTH peers
     through one follower process, on ticks after the initial drain.

Uses port 8798 (see tests/README.md for the port registry).
Run from the repo root: uv run python -m unittest discover -s tests
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

PORT = 8798


class TestReceiveMulti(unittest.TestCase):
    def cli(self, *cmd, secret="multi-secret", expect=0):
        env = dict(os.environ,
                   RETALK_PASSPHRASE=secret,
                   RETALK_RELAY=f"http://127.0.0.1:{PORT}",
                   RETALK_HOME=os.path.join(self.tmp, "store"))
        env.pop("RETALK_USER", None)
        env.pop("RETALK_SAVE_MESSAGE", None)
        _h = os.path.join(self.tmp, "store"); os.makedirs(_h, exist_ok=True)
        _c = os.path.join(_h, "config.json")
        if not os.path.exists(_c):
            with open(_c, "w") as f:
                f.write("{}")  # hermetic: no default relay
        res = subprocess.run([sys.executable, "-m", "retalk.cli", *cmd],
                             capture_output=True, text=True, env=env)
        self.assertEqual(res.returncode, expect,
                         f"{cmd}: rc={res.returncode}\n{res.stderr}")
        return res

    def texts(self, stdout):
        return [json.loads(l)["text"] for l in stdout.splitlines() if l.strip()]

    def test_flag_validation(self):
        # 4. bad flag combos die loudly, before any store or relay is touched
        with tempfile.TemporaryDirectory() as tmp:
            self.tmp = tmp
            res = self.cli("receive", "--peer", "bob", "--interval", "5",
                           expect=2)
            self.assertIn("--interval only applies with --follow", res.stderr)
            res = self.cli("receive", "--peer", "bob", "--follow",
                           "--interval", "0", expect=2)
            self.assertIn("positive", res.stderr)
            print("PASS 4: --interval needs --follow and a positive value")

    def test_multi_peer_quiet_follow(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.tmp = tmp
            server = subprocess.Popen(
                [sys.executable, "-m", "retalk.server"],
                env=dict(os.environ,
                         RETALK_SERVER_DB=os.path.join(tmp, "server.db"),
                         RETALK_SERVER_HOST="127.0.0.1",
                         RETALK_SERVER_PORT=str(PORT),
                         RETALK_SERVER_AUDIENCE=f"http://127.0.0.1:{PORT}"),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                self._flow(tmp)
            finally:
                server.terminate()
                server.wait(timeout=10)

    def _flow(self, tmp):
        dirs = {n: os.path.join(tmp, n) for n in
                ("alice", "bob", "carol", "dave")}
        fp = {}
        for n, d in dirs.items():
            res = self.cli("init", "--dir", d, "--display-name", n)
            fp[n] = res.stdout.strip()
            self.cli("sync", "--dir", d)               # publish keys

        # alice names bob and carol; every sender adds alice to send to her
        self.cli("add", fp["bob"], "--peer", "bob", "--dir", dirs["alice"])
        self.cli("add", fp["carol"], "--peer", "carol", "--dir", dirs["alice"])
        for n in ("bob", "carol", "dave"):
            self.cli("add", fp["alice"], "--peer", "alice", "--dir", dirs[n])

        self.cli("send", "--peer", "alice", "from-bob", "--dir", dirs["bob"])
        self.cli("send", "--peer", "alice", "from-carol", "--dir", dirs["carol"])
        self.cli("send", "--peer", "alice", "from-dave", "--dir", dirs["dave"])

        # 1. one call, two peers: exactly bob's and carol's mail, dave's stays
        res = self.cli("receive", "--peer", "bob", "--peer", "carol",
                       "--dir", dirs["alice"])
        self.assertEqual(sorted(self.texts(res.stdout)),
                         ["from-bob", "from-carol"])
        self.assertIn("using alice", res.stderr)        # banner, stderr only
        self.assertNotIn("using alice", res.stdout)
        res = self.cli("receive", "--peer", fp["dave"], "--dir", dirs["alice"])
        self.assertEqual(self.texts(res.stdout), ["from-dave"])
        print("PASS 1: repeatable --peer drains exactly the named senders")

        # repeating the same peer is harmless (deduped)
        res = self.cli("receive", "--peer", "bob", "--peer", "bob",
                       "--dir", dirs["alice"])
        self.assertEqual(self.texts(res.stdout), [])

        # 2. single --peer regression
        self.cli("send", "--peer", "alice", "again-bob", "--dir", dirs["bob"])
        res = self.cli("receive", "--peer", "bob", "--dir", dirs["alice"])
        self.assertEqual(self.texts(res.stdout), ["again-bob"])
        print("PASS 2: single --peer unchanged")

        # 3. --quiet drops the banner, keeps the records
        self.cli("send", "--peer", "alice", "quiet-carol", "--dir", dirs["carol"])
        res = self.cli("receive", "--peer", "carol", "--quiet",
                       "--dir", dirs["alice"])
        self.assertEqual(self.texts(res.stdout), ["quiet-carol"])
        self.assertNotIn("using alice", res.stderr)
        print("PASS 3: --quiet silences the identity banner")

        # 5. one --follow process, custom interval, both peers flow through
        out_path = os.path.join(tmp, "follow.out")
        err_path = os.path.join(tmp, "follow.err")
        env = dict(os.environ,
                   RETALK_PASSPHRASE="multi-secret",
                   RETALK_RELAY=f"http://127.0.0.1:{PORT}",
                   RETALK_HOME=os.path.join(self.tmp, "store"))
        with open(out_path, "w") as out, open(err_path, "w") as err:
            follower = subprocess.Popen(
                [sys.executable, "-m", "retalk.cli", "receive",
                 "--peer", "bob", "--peer", "carol",
                 "--follow", "--interval", "1", "--quiet",
                 "--dir", dirs["alice"]],
                stdout=out, stderr=err, env=env)
            try:
                time.sleep(2)                           # past the initial drain
                self.cli("send", "--peer", "alice", "tick-bob",
                         "--dir", dirs["bob"])
                self.cli("send", "--peer", "alice", "tick-carol",
                         "--dir", dirs["carol"])
                deadline = time.time() + 20
                got = []
                while time.time() < deadline:
                    with open(out_path) as f:
                        got = self.texts(f.read())
                    if sorted(got) == ["tick-bob", "tick-carol"]:
                        break
                    time.sleep(0.5)
                self.assertEqual(sorted(got), ["tick-bob", "tick-carol"])
            finally:
                follower.terminate()
                follower.wait(timeout=10)
        with open(err_path) as f:
            self.assertNotIn("using alice", f.read())
        print("PASS 5: --follow --interval serves both peers, quietly")


if __name__ == "__main__":
    unittest.main()
