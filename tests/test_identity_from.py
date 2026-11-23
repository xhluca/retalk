"""--identity-from: one identity per coding-agent session.

Asserts:
  1. `--identity-from claude` creates the session's identity on first use,
     under sessions/claude-<id>/, named after the session; later commands
     reuse it (same fingerprint).
  2. Renaming the session renames the identity on the next command; the
     fingerprint does not change.
  3. Two sessions get two different identities.
  4. `env:VAR:NAME_VAR` works for any agent that exports a session id.
  5. A missing session id or an unknown source fails loudly; nothing is created.
  6. Precedence: --user beats --identity-from; RETALK_IDENTITY_FROM beats
     RETALK_USER.
  7. End to end through a live relay: a message from a session identity
     arrives labelled ~<session name>, and after a rename ~<new name>.

The `claude` CLI is replaced by a stub on PATH that answers
`claude agents --json` with the session name in $FAKE_CLAUDE_NAME.

Uses port 8783 (see tests/README.md for the port registry).
Run from the repo root: uv run python -m unittest discover -s tests
"""

import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest

PORT = 8783

STUB = """#!{python}
import json, os, sys
if sys.argv[1:3] == ["agents", "--json"]:
    print(json.dumps([{{"sessionId": os.environ.get("CLAUDE_CODE_SESSION_ID", ""),
                        "name": os.environ.get("FAKE_CLAUDE_NAME", "")}}]))
"""


def wait_for_port(port: int, timeout: float = 15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"server did not start on port {port}")


class TestIdentityFrom(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.home = os.path.join(self.tmp, "store")
        os.makedirs(self.home)
        with open(os.path.join(self.home, "config.json"), "w") as f:
            f.write("{}")                        # hermetic: no default relay
        self.bin = os.path.join(self.tmp, "bin")
        os.makedirs(self.bin)
        stub = os.path.join(self.bin, "claude")
        with open(stub, "w") as f:
            f.write(STUB.format(python=sys.executable))
        os.chmod(stub, os.stat(stub).st_mode | stat.S_IEXEC)

    def tearDown(self):
        self._tmp.cleanup()

    def cli(self, *cmd, expect=0, **env_over):
        env = dict(os.environ, RETALK_HOME=self.home,
                   RETALK_RELAY=f"http://127.0.0.1:{PORT}",
                   PATH=self.bin + os.pathsep + os.environ.get("PATH", ""))
        for k in ("RETALK_USER", "RETALK_PASSPHRASE", "RETALK_PASSPHRASE_FILE",
                  "RETALK_IDENTITY_FROM", "RETALK_SESSION_NAME",
                  "CLAUDE_CODE_SESSION_ID", "FAKE_CLAUDE_NAME"):
            env.pop(k, None)
        for k, val in env_over.items():
            if val is None:
                env.pop(k, None)
            else:
                env[k] = val
        res = subprocess.run([sys.executable, "-m", "retalk.cli", *cmd],
                             capture_output=True, text=True, env=env)
        self.assertEqual(res.returncode, expect,
                         f"{cmd}: rc={res.returncode}\n{res.stderr}")
        return res

    def card(self, **env):
        res = self.cli("id", "--json", "--identity-from", "claude", **env)
        return json.loads(res.stdout), res.stderr

    def session_dir(self, key):
        return os.path.join(self.home, "sessions", key)

    def test_created_on_first_use_and_reused(self):
        env = dict(CLAUDE_CODE_SESSION_ID="aaaa-1111", FAKE_CLAUDE_NAME="alpha")
        c1, err = self.card(**env)
        self.assertEqual(c1["name"], "alpha")
        self.assertIn("created session identity alpha", err)
        self.assertTrue(os.path.exists(
            os.path.join(self.session_dir("claude-aaaa-1111"), "store.db")))
        mode = stat.S_IMODE(os.stat(self.session_dir("claude-aaaa-1111")).st_mode)
        self.assertEqual(mode, 0o700)
        parent = stat.S_IMODE(os.stat(os.path.join(self.home, "sessions")).st_mode)
        self.assertEqual(parent & 0o077, 0)   # others can't list the sessions
        c2, err = self.card(**env)
        self.assertEqual(c2["fingerprint"], c1["fingerprint"])
        self.assertNotIn("created session identity", err)

    def test_rename_follows_session(self):
        c1, _ = self.card(CLAUDE_CODE_SESSION_ID="s1", FAKE_CLAUDE_NAME="old")
        c2, err = self.card(CLAUDE_CODE_SESSION_ID="s1", FAKE_CLAUDE_NAME="new")
        self.assertEqual(c2["name"], "new")
        self.assertEqual(c2["fingerprint"], c1["fingerprint"])
        self.assertIn("session renamed: old -> new", err)
        # an override wins over the CLI's name
        c3, _ = self.card(CLAUDE_CODE_SESSION_ID="s1", FAKE_CLAUDE_NAME="new",
                          RETALK_SESSION_NAME="custom")
        self.assertEqual(c3["name"], "custom")

    def test_two_sessions_two_identities(self):
        a, _ = self.card(CLAUDE_CODE_SESSION_ID="sa", FAKE_CLAUDE_NAME="a")
        b, _ = self.card(CLAUDE_CODE_SESSION_ID="sb", FAKE_CLAUDE_NAME="b")
        self.assertNotEqual(a["fingerprint"], b["fingerprint"])

    def test_env_source(self):
        res = self.cli("id", "--json", "--identity-from", "env:MY_SID:MY_NAME",
                       MY_SID="t-42", MY_NAME="helper")
        c = json.loads(res.stdout)
        self.assertEqual(c["name"], "helper")
        self.assertTrue(os.path.isdir(self.session_dir("my-sid-t-42")))

    def test_missing_id_or_unknown_source_fails(self):
        res = self.cli("id", "--identity-from", "claude", expect=2)
        self.assertIn("CLAUDE_CODE_SESSION_ID is not set", res.stderr)
        res = self.cli("id", "--identity-from", "env:NOPE", expect=2)
        self.assertIn("$NOPE is not set", res.stderr)
        res = self.cli("id", "--identity-from", "mystery", expect=2)
        self.assertIn("unknown --identity-from source", res.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.home, "sessions")))

    def test_precedence(self):
        self.cli("init", "--user", "bob", "--no-passphrase", "--no-register")
        bob = self.cli("id", "--user", "bob").stdout.strip()
        # --user beats --identity-from
        got = self.cli("id", "--user", "bob", "--identity-from", "claude",
                       CLAUDE_CODE_SESSION_ID="p1").stdout.strip()
        self.assertEqual(got, bob)
        # RETALK_IDENTITY_FROM beats RETALK_USER
        got = self.cli("id", RETALK_USER="bob", RETALK_IDENTITY_FROM="claude",
                       CLAUDE_CODE_SESSION_ID="p1",
                       FAKE_CLAUDE_NAME="sess").stdout.strip()
        self.assertNotEqual(got, bob)

    def test_messages_carry_the_session_name(self):
        server = subprocess.Popen(
            [sys.executable, "-m", "retalk.server"],
            env=dict(os.environ,
                     RETALK_SERVER_DB=os.path.join(self.tmp, "server.db"),
                     RETALK_SERVER_HOST="127.0.0.1",
                     RETALK_SERVER_PORT=str(PORT),
                     RETALK_SERVER_AUDIENCE=f"http://127.0.0.1:{PORT}"),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            wait_for_port(PORT)
            sender = dict(CLAUDE_CODE_SESSION_ID="snd", FAKE_CLAUDE_NAME="writer")
            reader = dict(CLAUDE_CODE_SESSION_ID="rcv", FAKE_CLAUDE_NAME="reader")
            s_fp = self.card(**sender)[0]["fingerprint"]
            r_fp = self.card(**reader)[0]["fingerprint"]
            # publish both sessions' keys
            self.cli("register", "--identity-from", "claude", **sender)
            self.cli("register", "--identity-from", "claude", **reader)

            self.cli("send", "--identity-from", "claude", "--peer", r_fp,
                     "hello", **sender)
            out = self.cli("receive", "--identity-from", "claude", "--all",
                           **reader).stdout
            msgs = [json.loads(line) for line in out.splitlines() if line.strip()]
            self.assertEqual([(m["from"], m["name"], m["text"]) for m in msgs],
                             [(s_fp, "~writer", "hello")])

            # rename the sending session: its next message carries the new name
            sender["FAKE_CLAUDE_NAME"] = "editor"
            self.cli("send", "--identity-from", "claude", "--peer", r_fp,
                     "again", **sender)
            out = self.cli("receive", "--identity-from", "claude", "--all",
                           **reader).stdout
            msgs = [json.loads(line) for line in out.splitlines() if line.strip()]
            self.assertEqual([(m["name"], m["text"]) for m in msgs],
                             [("~editor", "again")])
        finally:
            server.terminate()
            server.wait(timeout=10)


if __name__ == "__main__":
    unittest.main()
