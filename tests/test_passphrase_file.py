"""--passphrase-file: name the passphrase by PATH, never by value.

Agents driving an encrypted identity used to need a compound command that
read a secret file into the environment:

    RETALK_PASSPHRASE="$(cat "$D/passphrase")" retalk sync --dir "$D/identity"

which is both unallowlistable (a compound command, not a flat one) and
indistinguishable from credential exfiltration to a reviewer. The flag makes
every call one flat command with the secret named, not embedded.

Asserts:
  1. init accepts --passphrase-file, and the identity reopens with it.
  2. Interop: a file whose content ends in a newline unlocks the SAME store
     as the equivalent RETALK_PASSPHRASE value (matching `$(cat file)`), so
     existing passphrase files keep working either way.
  3. Precedence: -p beats --passphrase-file beats RETALK_PASSPHRASE_FILE
     beats RETALK_PASSPHRASE.
  4. Failures are loud and never fall through to "no passphrase": missing
     file, empty file, and a directory each exit 2 with a clear message.
  5. A wrong passphrase from a file fails exactly like a wrong inline one.
  6. A group/world-readable file warns (with a chmod hint) but proceeds.
  7. --passphrase-path is accepted as an alias.

No relay needed: these are local unlock paths, so the tests use
--no-register and offline commands only.
Run from the repo root: uv run python -m unittest discover -s tests
"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SECRET = "correct horse battery staple"


class TestPassphraseFile(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.home, exist_ok=True)
        Path(self.home, "config.json").write_text("{}")   # hermetic
        self.pf = os.path.join(self.tmp, "passphrase")
        # written the way agent-talk writes it: a trailing newline
        Path(self.pf).write_text(SECRET + "\n")
        os.chmod(self.pf, 0o600)

    def cli(self, *cmd, expect=0, env_extra=None):
        env = dict(os.environ, RETALK_HOME=self.home)
        for k in ("RETALK_USER", "RETALK_RELAY", "RETALK_PASSPHRASE",
                  "RETALK_PASSPHRASE_FILE", "RETALK_SAVE_MESSAGE"):
            env.pop(k, None)
        env.update(env_extra or {})
        r = subprocess.run([sys.executable, "-m", "retalk.cli", *cmd],
                           capture_output=True, text=True, env=env)
        if expect is not None:
            self.assertEqual(r.returncode, expect,
                             f"{cmd}: rc={r.returncode}\n{r.stderr}")
        return r

    def init(self, *extra, **kw):
        return self.cli("init", "-u", "a", "--no-register",
                        "--relay", "http://127.0.0.1:1", *extra, **kw)

    def test_init_and_reopen_with_file(self):
        fp = self.init("--passphrase-file", self.pf).stdout.strip()
        self.assertEqual(len(fp), 32)
        got = self.cli("id", "-u", "a", "--passphrase-file", self.pf)
        self.assertEqual(got.stdout.strip(), fp)
        # the alias spelling works too
        got = self.cli("id", "-u", "a", "--passphrase-path", self.pf)
        self.assertEqual(got.stdout.strip(), fp)
        # ...and so does the env var naming the PATH (systemd/cron friendly)
        got = self.cli("id", "-u", "a",
                       env_extra={"RETALK_PASSPHRASE_FILE": self.pf})
        self.assertEqual(got.stdout.strip(), fp)

    def test_interop_with_env_var(self):
        """A file ending in a newline == the same value in RETALK_PASSPHRASE,
        exactly like $(cat file). Existing passphrase files keep working."""
        fp = self.init(env_extra={"RETALK_PASSPHRASE": SECRET}).stdout.strip()
        got = self.cli("id", "-u", "a", "--passphrase-file", self.pf)
        self.assertEqual(got.stdout.strip(), fp)
        # and the reverse direction: file-created identity, env-var unlock
        self.cli("init", "-u", "b", "--no-register", "--relay",
                 "http://127.0.0.1:1", "--passphrase-file", self.pf)
        b1 = self.cli("id", "-u", "b", "--passphrase-file", self.pf).stdout
        b2 = self.cli("id", "-u", "b",
                      env_extra={"RETALK_PASSPHRASE": SECRET}).stdout
        self.assertEqual(b1.strip(), b2.strip())

    def test_precedence(self):
        fp = self.init("--passphrase-file", self.pf).stdout.strip()
        wrong = os.path.join(self.tmp, "wrong")
        Path(wrong).write_text("not the passphrase\n")
        # -p wins over a WRONG file
        got = self.cli("id", "-u", "a", "-p", SECRET,
                       "--passphrase-file", wrong)
        self.assertEqual(got.stdout.strip(), fp)
        # --passphrase-file wins over a wrong env var (both kinds)
        got = self.cli("id", "-u", "a", "--passphrase-file", self.pf,
                       env_extra={"RETALK_PASSPHRASE": "nope",
                                  "RETALK_PASSPHRASE_FILE": wrong})
        self.assertEqual(got.stdout.strip(), fp)
        # RETALK_PASSPHRASE_FILE wins over RETALK_PASSPHRASE
        got = self.cli("id", "-u", "a",
                       env_extra={"RETALK_PASSPHRASE": "nope",
                                  "RETALK_PASSPHRASE_FILE": self.pf})
        self.assertEqual(got.stdout.strip(), fp)

    def test_failures_are_loud(self):
        self.init("--passphrase-file", self.pf)
        # missing file: must NOT fall through to "no passphrase given"
        r = self.cli("id", "-u", "a", "--passphrase-file",
                     os.path.join(self.tmp, "absent"), expect=2)
        self.assertIn("no passphrase file at", r.stderr)
        # empty file
        empty = os.path.join(self.tmp, "empty")
        Path(empty).write_text("\n")
        r = self.cli("id", "-u", "a", "--passphrase-file", empty, expect=2)
        self.assertIn("is empty", r.stderr)
        # a directory
        r = self.cli("id", "-u", "a", "--passphrase-file", self.tmp, expect=2)
        self.assertIn("directory", r.stderr)
        # wrong content fails like any wrong passphrase
        wrong = os.path.join(self.tmp, "wrong")
        Path(wrong).write_text("nope\n")
        r = self.cli("id", "-u", "a", "--passphrase-file", wrong, expect=None)
        self.assertNotEqual(r.returncode, 0)

    def test_loose_permissions_warn_but_work(self):
        fp = self.init("--passphrase-file", self.pf).stdout.strip()
        loose = os.path.join(self.tmp, "loose")
        Path(loose).write_text(SECRET + "\n")
        os.chmod(loose, 0o644)
        r = self.cli("id", "-u", "a", "--passphrase-file", loose)
        self.assertEqual(r.stdout.strip(), fp)          # still works
        self.assertIn("readable by other users", r.stderr)
        self.assertIn("chmod 600", r.stderr)            # actionable
        # a 0600 file says nothing
        r = self.cli("id", "-u", "a", "--passphrase-file", self.pf)
        self.assertNotIn("readable by other users", r.stderr)


if __name__ == "__main__":
    unittest.main()
