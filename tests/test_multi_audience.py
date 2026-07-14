"""Multi-audience relay: drive `python -m retalk.cli` as real subprocesses.

Request signatures are bound to the relay URL the client uses, which must
match the server's audience. So that a relay can move domains without
breaking clients still on the old URL, the server accepts a comma-separated
audience list and verifies a signature against each entry. These tests run
the real server and real CLI, one RETALK_HOME per user (as if on separate
machines), sharing only the relay.
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

PORT = 8781         # dual-audience relay
PORT_SINGLE = 8782  # single-audience relay: exact match still enforced

NEW_URL = f"http://127.0.0.1:{PORT}"
OLD_URL = f"http://localhost:{PORT}"    # same socket, different audience


def wait_for_port(port: int, timeout: float = 15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"server did not start on port {port}")


class TestMultiAudience(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.servers = []

    def tearDown(self):
        for proc in self.servers:
            proc.terminate()
            proc.wait(timeout=10)

    def start_server(self, port: int, audience: str):
        env = dict(os.environ,
                   RETALK_SERVER_DB=os.path.join(self.tmp, f"server-{port}.db"),
                   RETALK_SERVER_HOST="127.0.0.1",
                   RETALK_SERVER_PORT=str(port),
                   RETALK_SERVER_AUDIENCE=audience)
        proc = subprocess.Popen(
            [sys.executable, "-m", "retalk.server"], env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.servers.append(proc)
        wait_for_port(port)

    def _env(self, machine):
        home = os.path.join(self.tmp, f"home-{machine}")
        os.makedirs(home, exist_ok=True)
        cfg = os.path.join(home, "config.json")
        if not os.path.exists(cfg):
            Path(cfg).write_text("{}")          # hermetic: no default relay
        env = dict(os.environ, RETALK_HOME=home)
        for k in ("RETALK_USER", "RETALK_PASSPHRASE", "RETALK_RELAY",
                  "RETALK_SAVE_MESSAGE"):
            env.pop(k, None)
        return env

    def cli(self, machine, *cmd, expect=0):
        r = subprocess.run([sys.executable, "-m", "retalk.cli", *cmd],
                           capture_output=True, text=True,
                           env=self._env(machine))
        if expect is not None:
            self.assertEqual(r.returncode, expect,
                             f"[{machine}] {cmd}: rc={r.returncode}\n{r.stderr}")
        return r

    def test_old_and_new_urls_both_serve(self):
        """A client on the old URL and one on the new URL interoperate."""
        self.start_server(PORT, f"{NEW_URL},{OLD_URL}")
        fp = {}
        fp["alice"] = self.cli("alice", "init", "-u", "alice", "--no-passphrase",
                               "--relay", NEW_URL).stdout.strip()
        fp["bob"] = self.cli("bob", "init", "-u", "bob", "--no-passphrase",
                             "--relay", OLD_URL).stdout.strip()
        # verify pulls keys through each client's own URL
        r = self.cli("alice", "add", fp["bob"], "--peer", "bob", "--verify",
                     "-u", "alice")
        self.assertIn("✓ Verified", r.stderr)
        self.cli("bob", "add", fp["alice"], "--peer", "alice", "--verify",
                 "-u", "bob")
        # a full round-trip across the two URLs
        self.cli("alice", "send", "--peer", "bob", "hello from the new url",
                 "-u", "alice")
        got = [json.loads(l) for l in
               self.cli("bob", "receive", "--peer", "alice",
                        "-u", "bob").stdout.splitlines()]
        self.assertEqual([m["text"] for m in got], ["hello from the new url"])
        self.cli("bob", "send", "--peer", "alice", "hi from the old url",
                 "-u", "bob")
        got = [json.loads(l) for l in
               self.cli("alice", "receive", "--peer", "bob",
                        "-u", "alice").stdout.splitlines()]
        self.assertEqual([m["text"] for m in got], ["hi from the old url"])

    def test_single_audience_still_exact(self):
        """One audience configured -> any other relay URL is still rejected."""
        self.start_server(PORT_SINGLE, f"http://127.0.0.1:{PORT_SINGLE}")
        # the listed URL works (so the rejection below is not a dead server)
        self.cli("erin", "init", "-u", "erin", "--no-passphrase",
                 "--relay", f"http://127.0.0.1:{PORT_SINGLE}")
        # an equivalent-but-unlisted URL must fail signature verification
        self.cli("dave", "init", "-u", "dave", "--no-passphrase",
                 "--no-register", "--relay", f"http://localhost:{PORT_SINGLE}")
        r = self.cli("dave", "register", "-u", "dave", expect=None)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("signature", (r.stdout + r.stderr).lower())


if __name__ == "__main__":
    unittest.main()
