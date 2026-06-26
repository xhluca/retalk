"""CLI tests: drive `python -m retalk.cli` as real subprocesses.

Asserts:
  1. init creates an identity folder and prints the user id; a second init
     at the same place refuses.
  2. Commands without any identity fail loudly (no silent creation).
  3. id --json round-trips the id printed by init.
  4. add + send + receive --json: a full encrypted exchange through a live
     server, peer names resolving on the sender side.
  5. A wrong RETALK_PASSPHRASE fails with a friendly error.
  6. A wiped server database heals: clients republish keys on their next
     command and the conversation continues.
  7. receive <peer> returns only that sender's mail; --all drains the rest.

Uses port 8769 (see tests/README.md for the port registry).
Run from the repo root: uv run python -m unittest discover -s tests
"""

import json
import os
import sqlite3
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
                   RETALK_PASSPHRASE=secret,
                   RETALK_RELAY=f"http://127.0.0.1:{PORT}",
                   RETALK_HOME=os.path.join(self.tmp, "store"))
        env.pop("RETALK_USER", None)
        _h = os.path.join(self.tmp, "store"); os.makedirs(_h, exist_ok=True)
        _c = os.path.join(_h, "config.json")
        if not os.path.exists(_c): open(_c, "w").write("{}")  # hermetic: no default relay
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
                         RETALK_SERVER_DB=os.path.join(tmp, "server.db"),
                         RETALK_SERVER_HOST="127.0.0.1", RETALK_SERVER_PORT=str(PORT),
                         RETALK_SERVER_AUDIENCE=f"http://127.0.0.1:{PORT}"),
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
        self.assertIn("no user selected", res.stderr)

        # 1. init (explicit dir for alice, local for bob)
        res = self.cli("init", "--dir", alice_dir, "--display-name", "alice-1")
        aid = res.stdout.strip()
        self.assertRegex(aid, r"^[0-9a-f]{32}$")
        self.assertTrue(os.path.exists(os.path.join(alice_dir, "store.db")))
        res = self.cli("init", "--dir", alice_dir, expect=2)
        self.assertIn("already exists", res.stderr)

        res = self.cli("init", "--user", "bob", "--display-name", "bob-1", secret="bob-secret")
        bid = res.stdout.strip()
        self.assertRegex(bid, r"^[0-9a-f]{32}$")

        # 3. id --json matches what init printed (bob resolves via -u bob)
        res = self.cli("id", "--json", "-u", "bob", secret="bob-secret")
        self.assertEqual(json.loads(res.stdout)["fingerprint"], bid)
        res = self.cli("id", "--dir", alice_dir)
        self.assertEqual(res.stdout.strip(), aid)

        # 4. full exchange: alice names bob, sends; bob receives
        self.cli("add", "bob", bid, "--dir", alice_dir)
        res = self.cli("receive", "--all", "-u", "bob", secret="bob-secret")  # publishes bob
        self.assertEqual(res.stdout, "")
        self.cli("send", "--peer", "bob", "hello over the cli", "--dir", alice_dir)
        res = self.cli("receive", "--all", "-u", "bob", secret="bob-secret")
        msgs = [json.loads(line) for line in res.stdout.splitlines()]
        self.assertEqual(len(msgs), 1, msgs)
        self.assertEqual(msgs[0]["from"], aid)
        self.assertEqual(msgs[0]["text"], "hello over the cli")
        self.assertEqual(msgs[0]["name"], "~alice-1")  # bob never added alice

        # 5. wrong passphrase -> friendly refusal
        res = self.cli("id", "--dir", alice_dir, secret="wrong", expect=2)
        self.assertIn("wrong passphrase", res.stderr)

        # 6. server database wiped -> clients notice and republish; the
        # conversation continues (sessions and outbox live client-side)
        conn = sqlite3.connect(os.path.join(tmp, "server.db"))
        with conn:
            for table in ("users", "otks", "messages"):
                conn.execute(f"DELETE FROM {table}")
        conn.close()
        self.cli("receive", "--all", "-u", "bob", secret="bob-secret")          # bob heals himself
        self.cli("send", "--peer", "bob", "after the wipe", "--dir", alice_dir)  # alice too
        res = self.cli("receive", "--all", "-u", "bob", secret="bob-secret")
        texts = [json.loads(l)["text"] for l in res.stdout.splitlines()]
        self.assertIn("after the wipe", texts)

    def test_default_display_name(self):
        """init defaults --display-name to the user name; --dir stays unnamed."""
        with tempfile.TemporaryDirectory() as tmp:
            self.tmp = tmp
            # --user NAME, no --display-name -> the stored name defaults to NAME
            self.cli("init", "-u", "carol", secret="carol-secret")
            res = self.cli("id", "--json", "-u", "carol", secret="carol-secret")
            self.assertEqual(json.loads(res.stdout)["name"], "carol")
            # an explicit --display-name still wins over the user name
            self.cli("init", "-u", "dave", "--display-name", "Dave the Bot",
                     secret="dave-secret")
            res = self.cli("id", "--json", "-u", "dave", secret="dave-secret")
            self.assertEqual(json.loads(res.stdout)["name"], "Dave the Bot")
            # selected only by --dir (no user name) -> unnamed
            d = os.path.join(tmp, "anon")
            self.cli("init", "--dir", d)
            res = self.cli("id", "--json", "--dir", d)
            self.assertEqual(json.loads(res.stdout)["name"], "")
            print("PASS: init display-name defaults to the user name")

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


    def test_receive_per_peer(self):
        """receive <peer> reads one sender; --all drains the whole mailbox."""
        with tempfile.TemporaryDirectory() as tmp:
            self.tmp = tmp
            server = subprocess.Popen(
                [sys.executable, "-m", "retalk.server"],
                env=dict(os.environ,
                         RETALK_SERVER_DB=os.path.join(tmp, "server.db"),
                         RETALK_SERVER_HOST="127.0.0.1", RETALK_SERVER_PORT=str(PORT),
                         RETALK_SERVER_AUDIENCE=f"http://127.0.0.1:{PORT}"),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                wait_for_port(PORT)
                a, b, c = (os.path.join(tmp, x) for x in "abc")
                aid = self.cli("init", "--dir", a, "--display-name", "alice").stdout.strip()
                bid = self.cli("init", "--dir", b, "--display-name", "bob").stdout.strip()
                cid = self.cli("init", "--dir", c, "--display-name", "carol").stdout.strip()

                self.cli("receive", "--all", "--dir", b)        # bob publishes keys
                self.cli("send", "--peer", bid, "from alice", "--dir", a)
                self.cli("send", "--peer", bid, "from carol", "--dir", c)

                def rcv(*extra):
                    out = self.cli("receive", *extra, "--dir", b).stdout
                    return [(m["from"], m["text"])
                            for m in (json.loads(l) for l in out.splitlines())]

                # one sender only; the other's mail is left on the server
                self.assertEqual(rcv("--peer", aid), [(aid, "from alice")])
                # --all then delivers the remaining message from carol
                self.assertEqual(rcv("--all"), [(cid, "from carol")])
                # mailbox drained, and a target is mandatory
                self.assertEqual(rcv("--all"), [])
                self.cli("receive", "--dir", b, expect=2)                # no target
                self.cli("receive", "--peer", aid, "--all", "--dir", b, expect=2)  # both
                print("PASS: receive <peer> filters by sender; --all drains rest")
            finally:
                server.terminate()
                server.wait(timeout=10)


    def test_json_standard(self):
        """send/receive output matches docs/STANDARD.md exactly."""
        with tempfile.TemporaryDirectory() as tmp:
            self.tmp = tmp
            server = subprocess.Popen(
                [sys.executable, "-m", "retalk.server"],
                env=dict(os.environ,
                         RETALK_SERVER_DB=os.path.join(tmp, "server.db"),
                         RETALK_SERVER_HOST="127.0.0.1", RETALK_SERVER_PORT=str(PORT),
                         RETALK_SERVER_AUDIENCE=f"http://127.0.0.1:{PORT}"),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                wait_for_port(PORT)
                a, b = os.path.join(tmp, "a"), os.path.join(tmp, "b")
                aid = self.cli("init", "--dir", a, "--display-name", "alice").stdout.strip()
                bid = self.cli("init", "--dir", b, "--display-name", "bob").stdout.strip()
                self.cli("receive", "--all", "--dir", b)        # bob publishes keys

                # send receipt: exactly {"id", "to"}
                receipt = json.loads(self.cli("send", "--peer", bid, "hi", "--dir", a).stdout)
                self.assertEqual(set(receipt), {"id", "to"})
                self.assertEqual(receipt["to"], bid)
                self.assertRegex(receipt["id"], r"^[0-9a-f]{32}$")

                # received message: exactly {"id", "from", "name", "text"}
                lines = self.cli("receive", "--all", "--dir", b).stdout.splitlines()
                self.assertEqual(len(lines), 1)
                m = json.loads(lines[0])
                self.assertEqual(set(m), {"id", "from", "name", "text"})
                self.assertRegex(m["from"], r"^[0-9a-f]{32}$")
                # the id correlates the two sides (STANDARD.md)
                self.assertEqual((m["id"], m["from"], m["text"]),
                                 (receipt["id"], aid, "hi"))
                print("PASS: send/receive JSON matches docs/STANDARD.md")
            finally:
                server.terminate()
                server.wait(timeout=10)


if __name__ == "__main__":
    unittest.main()
