"""Invite codes end to end (cross-repo spec: .claude/invite-code-spec.md).

Three identities on a live local relay. Asserts, via the real CLI:
  1. Happy path: inviter mints a code, requester redeems with
     `retalk request`, `invite watch` accepts - contact saved under the
     minted --peer name with keys pinned (verified), single-use code
     consumed, and the acceptance record matches the spec shape.
  2. Both sides can message immediately after acceptance (the session
     established by the request survives acceptance).
  3. A consumed single-use code is rejected for a second sender with
     reason "consumed"; a revoked code with "revoked"; an unknown code
     with "unknown-code". Rejected senders are NOT contacts, and their
     rejected request stops resending (outbox heals via nack).
  4. A permanent code accepts several senders.
  5. Ordinary stranger mail (not a contact_request) is never surfaced,
     acked, or nacked by watch; unacknowledged, it re-delivers from the
     sender's outbox and a later scoped receive still gets it.
  6. Duplicate delivery of an accepted request re-acks silently: no second
     record, no second use.

Uses port 8799 (see tests/README.md for the port registry).
Run from the repo root: uv run python -m unittest discover -s tests
"""

import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

PORT = 8799
URL = f"http://127.0.0.1:{PORT}"


def wait_for_port(port: int, timeout: float = 15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"server did not start on port {port}")


class TestInviteCodes(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        env = dict(os.environ, RETALK_SERVER_DB=os.path.join(self.tmp, "server.db"),
                   RETALK_SERVER_HOST="127.0.0.1", RETALK_SERVER_PORT=str(PORT),
                   RETALK_SERVER_AUDIENCE=URL)
        self.server = subprocess.Popen(
            [sys.executable, "-m", "retalk.server"], env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wait_for_port(PORT)
        self.fp = {}
        for who in ("ana", "ben", "cal"):
            self.fp[who] = self.cli(who, "init", "-u", who,
                                    "--display-name", who,
                                    "--relay", URL).stdout.strip()

    def tearDown(self):
        self.server.terminate()
        self.server.wait(timeout=10)

    def _env(self, who):
        home = os.path.join(self.tmp, f"home-{who}")
        os.makedirs(home, exist_ok=True)
        cfg = os.path.join(home, "config.json")
        if not os.path.exists(cfg):
            Path(cfg).write_text("{}")          # hermetic: no default relay
        env = dict(os.environ, RETALK_HOME=home,
                   RETALK_PASSPHRASE=f"{who}-secret")
        for k in ("RETALK_USER", "RETALK_RELAY", "RETALK_SAVE_MESSAGE"):
            env.pop(k, None)
        return env

    def cli(self, who, *cmd, expect=0):
        r = subprocess.run([sys.executable, "-m", "retalk.cli", *cmd],
                           capture_output=True, text=True,
                           env=self._env(who))
        if expect is not None:
            self.assertEqual(r.returncode, expect,
                             f"[{who}] {cmd}: rc={r.returncode}\n{r.stderr}")
        return r

    def mint(self, who, *extra):
        out = self.cli(who, "invite", "new", "-u", who, *extra).stdout
        return json.loads(out)

    def watch(self, who):
        out = self.cli(who, "invite", "watch", "-u", who, "--quiet").stdout
        return [json.loads(l) for l in out.splitlines() if l.strip()]

    def test_happy_path_and_consumed_replay(self):
        code = self.mint("ana", "--peer", "benny")["code"]
        # ben redeems: this saves+verifies ana on ben's side and sends the
        # encrypted request
        r = self.cli("ben", "request", self.fp["ana"], "--code", code,
                     "-u", "ben", "--peer", "ana")
        receipt = json.loads(r.stdout)
        self.assertEqual(receipt["to"], self.fp["ana"])
        # ana's watch accepts: spec-shaped record, contact saved + verified
        recs = self.watch("ana")
        self.assertEqual(len(recs), 1)
        rec = recs[0]
        self.assertEqual(rec["kind"], "contact_accepted")
        self.assertEqual(rec["from"], self.fp["ben"])
        self.assertEqual(rec["name"], "benny")      # the minted --peer name
        self.assertEqual(rec["code"], code)
        self.assertTrue(rec["card"]["verified"])
        card = [json.loads(l) for l in self.cli(
            "ana", "contacts", "--json", "-u", "ana").stdout.splitlines()]
        self.assertEqual([(c["name"], c["verified"]) for c in card],
                         [("benny", True)])
        # the code is consumed
        row = json.loads(self.cli("ana", "invite", "list", "--json",
                                  "-u", "ana").stdout)
        self.assertEqual((row["uses"], row["active"], row["used_by"]),
                         (1, False, [self.fp["ben"]]))
        # both directions message immediately
        self.cli("ana", "send", "--peer", "benny", "welcome aboard",
                 "-u", "ana")
        got = [json.loads(l) for l in self.cli(
            "ben", "receive", "--peer", "ana", "-u", "ben").stdout.splitlines()]
        self.assertEqual([m["text"] for m in got], ["welcome aboard"])
        self.cli("ben", "send", "--peer", "ana", "glad to be here", "-u", "ben")
        got = [json.loads(l) for l in self.cli(
            "ana", "receive", "--peer", "benny",
            "-u", "ana").stdout.splitlines()]
        self.assertEqual([m["text"] for m in got], ["glad to be here"])
        # cal replays the consumed code: rejected, not a contact
        self.cli("cal", "request", self.fp["ana"], "--code", code, "-u", "cal")
        recs = self.watch("ana")
        self.assertEqual([(r["kind"], r["reason"], r["from"])
                          for r in recs],
                         [("contact_request_rejected", "consumed",
                           self.fp["cal"])])
        names = [json.loads(l)["name"] for l in self.cli(
            "ana", "contacts", "--json", "-u", "ana").stdout.splitlines()]
        self.assertEqual(names, ["benny"])
        # the rejection nacked cal's request: cal's outbox heals on sync
        self.cli("cal", "sync", "-u", "cal")
        self.cli("cal", "sync", "-u", "cal")
        import sqlite3
        con = sqlite3.connect(os.path.join(self.tmp, "home-cal", "cal",
                                           "store.db"))
        left = con.execute("SELECT COUNT(*) FROM outbox").fetchone()[0]
        con.close()
        self.assertEqual(left, 0, "rejected request should stop resending")

    def test_revoked_unknown_and_permanent(self):
        dead = self.mint("ana")["code"]
        self.cli("ana", "invite", "revoke", dead, "-u", "ana")
        self.cli("ben", "request", self.fp["ana"], "--code", dead, "-u", "ben")
        self.cli("cal", "request", self.fp["ana"], "--code", "not-a-code",
                 "-u", "cal")
        recs = self.watch("ana")
        reasons = {r["from"]: r["reason"] for r in recs}
        self.assertEqual(reasons[self.fp["ben"]], "revoked")
        self.assertEqual(reasons[self.fp["cal"]], "unknown-code")
        self.assertTrue(all(r["kind"] == "contact_request_rejected"
                            for r in recs))
        # a permanent code accepts both of them afterwards
        perm = self.mint("ana", "--permanent")["code"]
        self.cli("ben", "request", self.fp["ana"], "--code", perm, "-u", "ben")
        self.cli("cal", "request", self.fp["ana"], "--code", perm, "-u", "cal")
        recs = self.watch("ana")
        self.assertEqual(sorted(r["from"] for r in recs),
                         sorted([self.fp["ben"], self.fp["cal"]]))
        self.assertTrue(all(r["kind"] == "contact_accepted" for r in recs))
        rows = {r["code"]: r for r in
                (json.loads(l) for l in self.cli(
                    "ana", "invite", "list", "--json",
                    "-u", "ana").stdout.splitlines())}
        self.assertEqual(rows[perm]["uses"], 2)
        self.assertTrue(rows[perm]["active"])   # permanent stays active

    def test_stranger_mail_left_alone(self):
        # ben knows ana (manual add) and sends ORDINARY chat - no code
        self.cli("ben", "add", self.fp["ana"], "--peer", "ana", "--verify",
                 "-u", "ben")
        self.cli("ben", "send", "--peer", "ana", "psst, ordinary mail",
                 "-u", "ben")
        # ana's watch must not surface, ack, or nack it
        self.assertEqual(self.watch("ana"), [])
        self.assertEqual(self.watch("ana"), [])   # and it must not loop
        # the fetch is destructive relay-side, but the mail was never acked:
        # ben's outbox still holds it and re-delivers on his next sync
        # (at-least-once, same as any crashed receive)
        self.cli("ben", "sync", "-u", "ben")
        got = [json.loads(l) for l in self.cli(
            "ana", "receive", "--peer", self.fp["ben"],
            "-u", "ana").stdout.splitlines()]
        self.assertEqual([m["text"] for m in got], ["psst, ordinary mail"])

    def test_duplicate_delivery_reacks_silently(self):
        code = self.mint("ana")["code"]
        self.cli("ben", "request", self.fp["ana"], "--code", code, "-u", "ben")
        self.assertEqual(self.watch("ana")[0]["kind"], "contact_accepted")
        # ben never received the ack (simulate by resending from his outbox
        # before syncing acks): force a resend via sync, then watch again
        self.cli("ben", "sync", "-u", "ben")
        recs = self.watch("ana")
        self.assertEqual(recs, [], "duplicate must not emit a second record")
        row = json.loads(self.cli("ana", "invite", "list", "--json",
                                  "-u", "ana").stdout)
        self.assertEqual(row["uses"], 1, "duplicate must not count a use")


class TestInviteCodeShape(unittest.TestCase):
    """A minted code has to survive being typed as a CLI argument. No relay
    and no identity here: this is about the code itself."""

    def test_minted_code_never_starts_with_a_dash(self):
        # Regression: token_urlsafe draws from base64url, so about one code in
        # 64 began with '-'. argparse then read `invite revoke -Xy...` and
        # `--code -Xy...` as option flags and exited 2 with "unrecognized
        # arguments", which made the feature fail at random.
        from retalk import store

        real = secrets.token_urlsafe
        drawn = ["-leading-dash-is-unusable", "safe-code-with-no-lead-dash"]

        def fake(n):
            return drawn.pop(0) if drawn else real(n)

        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "store.db")
            secrets.token_urlsafe = fake
            try:
                rec = store.mint_invite(db)
            finally:
                secrets.token_urlsafe = real
            self.assertEqual(rec["code"], "safe-code-with-no-lead-dash",
                             "a leading '-' must be redrawn, not minted")
            self.assertEqual([r["code"] for r in store.load_invites(db)],
                             ["safe-code-with-no-lead-dash"],
                             "only the usable code may reach the table")

        # and the real generator agrees, over enough draws to have caught it
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "store.db")
            codes = [store.mint_invite(db)["code"] for _ in range(300)]
        self.assertFalse([c for c in codes if c.startswith("-")])


if __name__ == "__main__":
    unittest.main()
