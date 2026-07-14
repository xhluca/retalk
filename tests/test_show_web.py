"""`retalk show USER --web` serves the saved store as a local web app: a
conversation sidebar plus a bubble thread view, token-guarded, bound to
127.0.0.1, reading the same sealed rows as `show`/`history`. These tests
drive the real CLI as subprocesses and hit the real HTTP endpoints.
"""
from __future__ import annotations

import json
import os
import select
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

PORT = 8786      # relay
WPORT = 8787     # web view


def wait_for_port(port: int, timeout: float = 15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"server did not start on port {port}")


def read_until(stream, marker: str, timeout: float = 15.0) -> str:
    """Read the binary stream until `marker` appears; returns all text seen."""
    fd = stream.fileno()
    os.set_blocking(fd, False)
    buf, deadline = b"", time.time() + timeout
    while time.time() < deadline:
        if select.select([fd], [], [], 0.2)[0]:
            buf += os.read(fd, 65536) or b""
            if marker.encode() in buf:
                return buf.decode("utf-8", "replace")
    raise TimeoutError(f"marker {marker!r} not seen in: {buf!r}")


class TestShowWeb(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        env = dict(os.environ, RETALK_SERVER_DB=os.path.join(self.tmp, "server.db"),
                   RETALK_SERVER_HOST="127.0.0.1", RETALK_SERVER_PORT=str(PORT),
                   RETALK_SERVER_AUDIENCE=f"http://127.0.0.1:{PORT}")
        self.server = subprocess.Popen(
            [sys.executable, "-m", "retalk.server"], env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.web = None
        wait_for_port(PORT)
        self.aid = self.cli("init", "-u", "alice", "--no-passphrase",
                            "--relay", f"http://127.0.0.1:{PORT}").stdout.strip()
        self.bid = self.cli("init", "-u", "bob", "--no-passphrase",
                            "--relay", f"http://127.0.0.1:{PORT}").stdout.strip()
        self.cli("add", self.bid, "--peer", "bob", "-u", "alice")
        self.cli("add", self.aid, "--peer", "alice", "-u", "bob")

    def tearDown(self):
        if self.web:
            self.web.terminate()
            self.web.wait(timeout=10)
            if self.web.stderr:
                self.web.stderr.close()
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
        if expect is not None:
            self.assertEqual(r.returncode, expect,
                             f"{cmd}: rc={r.returncode}\n{r.stderr}")
        return r

    def start_web(self) -> str:
        """Launch `show alice --web`; returns the tokened URL it printed."""
        self.web = subprocess.Popen(
            [sys.executable, "-m", "retalk.cli", "show", "alice", "--web",
             "--port", str(WPORT)],
            env=self._env(), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        text = read_until(self.web.stderr, "?t=")
        url = next(w for w in text.split() if w.startswith("http://127.0.0.1"))
        wait_for_port(WPORT)
        return url

    def get(self, url: str, token: str | None = None, expect: int = 200):
        req = urllib.request.Request(url)
        if token:
            req.add_header("X-Retalk-Token", token)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                self.assertEqual(r.status, expect)
                return r.read().decode()
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, expect,
                             f"{url}: got {e.code}, wanted {expect}")
            return e.read().decode()

    def test_serves_conversations_thread_and_auth(self):
        # seed a two-way saved conversation, as in test_show
        self.cli("send", "--peer", "bob", "hello bob", "-u", "alice", "--save")
        self.cli("receive", "--peer", "alice", "-u", "bob", "--save")
        self.cli("send", "--peer", "alice", "hi alice", "-u", "bob", "--save")
        self.cli("receive", "--peer", "bob", "-u", "alice", "--save")

        url = self.start_web()
        token = url.split("?t=")[1]
        base = f"http://127.0.0.1:{WPORT}"

        # auth: no token and a wrong token are both rejected
        self.get(base + "/", expect=403)
        self.get(base + "/api/conversations", token="nope", expect=403)

        # the page itself, via the tokened URL exactly as printed
        page = self.get(url)
        self.assertIn("<!doctype html", page.lower())
        self.assertIn("retalk", page)

        # sidebar data: bob's conversation with both directions counted
        d = json.loads(self.get(base + "/api/conversations", token=token))
        self.assertEqual(d["me"], "alice")
        convo = next(c for c in d["conversations"]
                     if c["fingerprint"] == self.bid)
        self.assertEqual(convo["name"], "bob")
        self.assertEqual(convo["count"], 2)

        # the thread: decrypted texts, directions, and display names
        d = json.loads(self.get(
            f"{base}/api/messages?peer={self.bid}&after=0", token=token))
        msgs = d["messages"]
        self.assertEqual([m["text"] for m in msgs], ["hello bob", "hi alice"])
        self.assertEqual([m["direction"] for m in msgs], ["out", "in"])
        self.assertEqual([m["name"] for m in msgs], ["alice", "bob"])

        # incremental polling: nothing after the last row...
        last = max(m["rowid"] for m in msgs)
        d = json.loads(self.get(
            f"{base}/api/messages?peer={self.bid}&after={last}", token=token))
        self.assertEqual(d["messages"], [])

        # ...until another process saves a new row (the live-update path)
        self.cli("send", "--peer", "bob", "one more", "-u", "alice", "--save")
        d = json.loads(self.get(
            f"{base}/api/messages?peer={self.bid}&after={last}", token=token))
        self.assertEqual([m["text"] for m in d["messages"]], ["one more"])

    def test_peer_still_required_without_web(self):
        r = self.cli("show", "alice", expect=None)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("--web", r.stderr)


if __name__ == "__main__":
    unittest.main()
