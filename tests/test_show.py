"""`retalk show USER PEER` renders the saved conversation as a chat — time and
username per message, both directions interleaved. It reads only messages kept
by `--save` (send/receive); `--follow` keeps the chat live by polling the
relay and saving what arrives, like `receive --save` does.
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

PORT = 8775


def wait_for_port(port: int, timeout: float = 15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"server did not start on port {port}")


class TestShow(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        env = dict(os.environ, RETALK_SERVER_DB=os.path.join(self.tmp, "server.db"),
                   RETALK_SERVER_HOST="127.0.0.1", RETALK_SERVER_PORT=str(PORT),
                   RETALK_SERVER_AUDIENCE=f"http://127.0.0.1:{PORT}")
        self.server = subprocess.Popen(
            [sys.executable, "-m", "retalk.server"], env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wait_for_port(PORT)
        self.aid = self.cli("init", "-u", "alice", "--no-passphrase",
                            "--relay", f"http://127.0.0.1:{PORT}").stdout.strip()
        self.bid = self.cli("init", "-u", "bob", "--no-passphrase",
                            "--relay", f"http://127.0.0.1:{PORT}").stdout.strip()
        self.cli("add", self.bid, "--peer", "bob", "-u", "alice")
        self.cli("add", self.aid, "--peer", "alice", "-u", "bob")

    def tearDown(self):
        self.server.terminate()
        self.server.wait(timeout=10)

    def _env(self):
        home = os.path.join(self.tmp, "store")
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
        r = subprocess.run([sys.executable, "-m", "retalk.cli", *cmd],
                           capture_output=True, text=True, env=self._env())
        self.assertEqual(r.returncode, expect,
                         f"{cmd}: rc={r.returncode}\n{r.stderr}")
        return r

    def test_renders_saved_conversation(self):
        self.cli("send", "--peer", "bob", "hello bob", "-u", "alice", "--save")
        self.cli("receive", "--peer", "alice", "-u", "bob", "--save")
        self.cli("send", "--peer", "alice", "hi alice", "-u", "bob", "--save")
        self.cli("receive", "--peer", "bob", "-u", "alice", "--save")

        out = self.cli("show", "alice", "bob").stdout
        self.assertIn("alice ⇄ bob", out)          # header names both sides
        self.assertIn("hello bob", out)
        self.assertIn("hi alice", out)
        self.assertLess(out.index("hello bob"), out.index("hi alice"))
        self.assertIn("alice 🟢", out)             # your bubbles, marked
        self.assertIn("🔵 bob", out)               # the peer's, marked
        self.assertIn(time.strftime("📅 %Y-%m-%d"), out)      # date separator
        # bob's mirror view labels the directions his way
        out = self.cli("show", "bob", "alice").stdout
        self.assertIn("bob ⇄ alice", out)
        self.assertIn("bob 🟢", out)
        self.assertIn("🔵 alice", out)
        self.assertLess(out.index("hello bob"), out.index("hi alice"))
        print("PASS: show renders the saved two-way conversation in order")

    def test_nothing_saved_hint(self):
        out = self.cli("show", "alice", "bob").stdout
        self.assertIn("no saved messages", out)
        print("PASS: show hints at --save when nothing was kept")

    def test_follow_renders_incoming_live(self):
        self.cli("send", "--peer", "bob", "opener", "-u", "alice", "--save")
        proc = subprocess.Popen(
            [sys.executable, "-m", "retalk.cli", "show", "bob", "alice",
             "--follow"],
            env=self._env(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True)
        try:
            time.sleep(2)                       # let the first poll run
            self.cli("send", "--peer", "bob", "a live one", "-u", "alice")
            deadline = time.time() + 15
            got = ""
            os.set_blocking(proc.stdout.fileno(), False)
            while time.time() < deadline and "a live one" not in got:
                got += proc.stdout.read() or ""
                time.sleep(0.5)
        finally:
            proc.terminate()
            proc.wait(timeout=10)
        self.assertIn("🔵 alice", got)           # peer bubbles, marked
        self.assertIn("opener", got)             # backlog fetched and saved
        self.assertIn("a live one", got)         # and the live message too
        print("PASS: show --follow renders new messages as they arrive")


if __name__ == "__main__":
    unittest.main()
