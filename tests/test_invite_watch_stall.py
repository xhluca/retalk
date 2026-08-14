"""Regression: `invite watch` must not swallow a saved contact's mail.

The bug (shipped in 0.3.0rc1): `read_messages` DELETES on fetch, and the
watcher fetched the whole mailbox and then dropped anything from a known
sender. Those messages were gone from the relay, and only the sender's
outbox resend brought them back -- which a `--follow` watcher promptly ate
again. So a running watcher stalled mail from established contacts for as
long as it ran: exactly the window the invite flow exists to serve, since
a peer accepted by invite becomes a contact and then tries to talk.

Asserts:
  1. One watch cycle leaves an existing contact's pending message intact:
     the very next `receive` gets it (before the fix: empty).
  2. Repeated watch cycles, as `--follow` does, never consume it.
  3. The watcher still accepts a genuine invite request in the same
     mailbox, so fixing the stall did not break the feature.
  4. Mail that arrives from a contact WHILE the watcher runs is likewise
     untouched.

Uses port 8792 (see tests/README.md for the port registry).
Run from the repo root: uv run python -m unittest discover -s tests
"""

import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest

from retalk import User

PORT = 8792
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


class TestInviteWatchStall(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        env = dict(os.environ,
                   RETALK_SERVER_DB=os.path.join(self.tmp, "server.db"),
                   RETALK_SERVER_HOST="127.0.0.1",
                   RETALK_SERVER_PORT=str(PORT), RETALK_SERVER_AUDIENCE=URL)
        self.server = subprocess.Popen(
            [sys.executable, "-m", "retalk.server"], env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wait_for_port(PORT)
        self.u = {}
        for who in ("ana", "ben", "cal"):
            u = User(URL, f"{who}-secret", name=who,
                     store=os.path.join(self.tmp, f"{who}.db"))
            u.sync()
            self.u[who] = u
        # ana and ben are established contacts, both directions
        self.u["ana"].add_contact(self.fp("ben"), "ben", verify=True)
        self.u["ben"].add_contact(self.fp("ana"), "ana", verify=True)

    def tearDown(self):
        self.server.terminate()
        self.server.wait(timeout=10)

    def fp(self, who):
        return self.u[who].fingerprint()

    def test_watch_leaves_contact_mail_for_receive(self):
        ana, ben = self.u["ana"], self.u["ben"]
        ben.send(self.fp("ana"), "did the deploy finish?")
        # a watch cycle runs (as the invite watcher does, alongside receive)
        self.assertEqual(ana.invite_watch(), [])
        # the contact's message must still be there for the normal reader
        got = ana.receive(self.fp("ben"))
        self.assertEqual([m["text"] for m in got], ["did the deploy finish?"],
                         "invite watch swallowed a saved contact's message")

    def test_follow_loop_never_consumes_contact_mail(self):
        ana, ben = self.u["ana"], self.u["ben"]
        ben.send(self.fp("ana"), "ping 1")
        for _ in range(5):                     # what --follow does
            self.assertEqual(ana.invite_watch(), [])
        got = ana.receive(self.fp("ben"))
        self.assertEqual([m["text"] for m in got], ["ping 1"])
        # and mail that lands mid-watch survives too
        ben.send(self.fp("ana"), "ping 2")
        for _ in range(3):
            ana.invite_watch()
        got = ana.receive(self.fp("ben"))
        self.assertEqual([m["text"] for m in got], ["ping 2"])

    def test_still_accepts_requests_alongside_contact_mail(self):
        """Fixing the stall must not break the feature it protects."""
        ana, ben, cal = self.u["ana"], self.u["ben"], self.u["cal"]
        code = ana.new_invite(peer="cally")["code"]
        ben.send(self.fp("ana"), "unrelated chatter")      # contact mail
        cal.request_contact(self.fp("ana"), code, peer_name="ana")
        recs = ana.invite_watch()
        self.assertEqual([r["kind"] for r in recs], ["contact_accepted"])
        self.assertEqual(recs[0]["from"], self.fp("cal"))
        self.assertEqual(ana.contact("cally")["fingerprint"], self.fp("cal"))
        # ben's message was never touched
        got = ana.receive(self.fp("ben"))
        self.assertEqual([m["text"] for m in got], ["unrelated chatter"])
        # and cal's request is consumed, not re-offered on the next cycle
        self.assertEqual(ana.invite_watch(), [])


if __name__ == "__main__":
    unittest.main()
