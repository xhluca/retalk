"""CLI tests: drive `python -m retalk.cli` as real subprocesses.

Asserts:
  1. init creates an identity folder and prints the user id; a second init
     at the same place refuses.
  2. Commands without any identity fail loudly (no silent creation).
  3. id --json round-trips the id printed by init.
  4. add + send + receive --json: a full encrypted exchange through a live
     server, peer names resolving on the sender side.
  5. A wrong PICKLE_SECRET fails with a friendly error.

Uses port 8769 (see tests/README.md for the port registry).
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

PORT = 8769


def wait_for_port(port: int, timeout: float = 15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"server did not start on port {port}")


class TestCLI(unittest.TestCase):
    def cli(self, *cmd, secret="cli-secret", expect=0):
        env = dict(os.environ,
                   PICKLE_SECRET=secret,
                   SERVER_URL=f"http://127.0.0.1:{PORT}",
                   XDG_DATA_HOME=os.path.join(self.tmp, "xdg"))
        env.pop("STORE", None)
        res = subprocess.run([sys.executable, "-m", "retalk.cli", *cmd],
                             capture_output=True, text=True, env=env)
        self.assertEqual(res.returncode, expect,
                         f"{cmd}: rc={res.returncode}\n{res.stderr}")
        return res

    def test_cli_flow(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.tmp = tmp
            server = subprocess.Popen(
                [sys.executable, "-m", "retalk.server"],
                env=dict(os.environ,
                         SERVER_DB=os.path.join(tmp, "server.db"),
                         SERVER_HOST="127.0.0.1", SERVER_PORT=str(PORT),
                         SERVER_AUDIENCE=f"http://127.0.0.1:{PORT}"),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                self._flow(tmp)
            finally:
                server.terminate()
                server.wait(timeout=10)

    def _flow(self, tmp):
        alice_dir = os.path.join(tmp, "alice")

        # 2. no identity anywhere -> loud refusal, nothing created
        res = self.cli("id", expect=2)
        self.assertIn("no identity", res.stderr)

        # 1. init (explicit dir for alice, user-level for bob)
        res = self.cli("init", alice_dir, "--nickname", "alice-1")
        aid = res.stdout.strip()
        self.assertRegex(aid, r"^[0-9a-f]{32}$")
        self.assertTrue(os.path.exists(os.path.join(alice_dir, "store.db")))
        res = self.cli("init", alice_dir, expect=2)
        self.assertIn("already exists", res.stderr)

        res = self.cli("init", "-u", "--nickname", "bob-1", secret="bob-secret")
        bid = res.stdout.strip()
        self.assertRegex(bid, r"^[0-9a-f]{32}$")

        # 3. id --json matches what init printed (bob resolves via the
        # user-level default with no flags at all)
        res = self.cli("id", "--json", secret="bob-secret")
        self.assertEqual(json.loads(res.stdout)["user_id"], bid)
        res = self.cli("id", "-s", alice_dir)
        self.assertEqual(res.stdout.strip(), aid)

        # 4. full exchange: alice names bob, sends; bob receives
        self.cli("add", "bob", bid, "-s", alice_dir)
        res = self.cli("receive", "--json", secret="bob-secret")  # publishes bob
        self.assertEqual(res.stdout, "")
        self.cli("send", "bob", "hello over the cli", "-s", alice_dir)
        res = self.cli("receive", "--json", secret="bob-secret")
        msgs = [json.loads(line) for line in res.stdout.splitlines()]
        self.assertEqual(len(msgs), 1, msgs)
        self.assertEqual(msgs[0]["from"], aid)
        self.assertEqual(msgs[0]["text"], "hello over the cli")
        self.assertEqual(msgs[0]["name"], "~alice-1")  # bob never added alice

        # 5. wrong secret -> friendly refusal
        res = self.cli("id", "-s", alice_dir, secret="wrong", expect=2)
        self.assertIn("wrong secret", res.stderr)

    def test_help_screens(self):
        """Every command documents itself: --help exits 0 with substance."""
        self.tmp = tempfile.gettempdir()
        for cmd in ([], ["init"], ["id"], ["add"], ["send"], ["receive"]):
            res = self.cli(*cmd, "--help")
            self.assertGreater(len(res.stdout), 400,
                               f"{cmd or ['top-level']}: thin --help")
        self.assertIn("first match wins", self.cli("--help").stdout)
        self.assertIn("PIN MISMATCH", self.cli("send", "--help").stdout)
        self.assertIn("cannot be recovered", self.cli("init", "--help").stdout)


if __name__ == "__main__":
    unittest.main()
