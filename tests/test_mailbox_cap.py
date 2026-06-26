"""Server mailbox-cap tests: --max-mailbox / --max-mailbox-per-sender.

Drives a live `retalk-server` started with a low cap and real `User` clients,
asserting:

  1. Filling a recipient's mailbox to the cap makes the next send reject
     (HTTP 400 -> RuntimeError "mailbox full"), and sends under the cap work.
  2. A rejected send does NOT delete or evict existing mail (reject-not-evict):
     the row count is unchanged and the recipient still reads every prior
     message back.
  3. The per-(sender, recipient) sub-cap stops one sender from filling a
     mailbox, while a second sender can still deposit up to the same sub-cap
     (so one sender can't crowd out others).

Uses port 8770 (see tests/README.md for the port registry).
Run from the repo root: uv run python -m unittest discover -s tests
"""

from __future__ import annotations

import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

PORT = 8770


def wait_for_port(port: int, timeout: float = 15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"server did not start on port {port}")


def count_messages(db: str, recipient: str, sender: str | None = None) -> int:
    conn = sqlite3.connect(db)
    try:
        if sender is None:
            row = conn.execute(
                "SELECT COUNT(*) FROM messages WHERE recipient=?",
                (recipient,)).fetchone()
        else:
            row = conn.execute(
                "SELECT COUNT(*) FROM messages WHERE recipient=? AND sender=?",
                (recipient, sender)).fetchone()
        return row[0]
    finally:
        conn.close()


class TestMailboxCap(unittest.TestCase):
    def _start(self, tmp, **env_extra):
        db = os.path.join(tmp, "server.db")
        env = dict(os.environ,
                   RETALK_SERVER_DB=db,
                   RETALK_SERVER_HOST="127.0.0.1",
                   RETALK_SERVER_PORT=str(PORT),
                   RETALK_SERVER_AUDIENCE=f"http://127.0.0.1:{PORT}",
                   **env_extra)
        proc = subprocess.Popen(
            [sys.executable, "-m", "retalk.server"],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wait_for_port(PORT)
        return proc, db

    def test_overall_cap_rejects_and_preserves(self):
        """At/over the cap the send rejects; a rejected send keeps existing
        mail intact and readable (reject-not-evict)."""
        from retalk import User
        with tempfile.TemporaryDirectory() as tmp:
            proc, db = self._start(tmp, RETALK_SERVER_MAX_MAILBOX="3")
            try:
                url = f"http://127.0.0.1:{PORT}"
                a = User(url, "sec-a", name="alice",
                         store=os.path.join(tmp, "a.db"))
                b = User(url, "sec-b", name="bob",
                         store=os.path.join(tmp, "b.db"))
                aid, bid = a.fingerprint(), b.fingerprint()
                a.publish()
                b.publish()

                # Under the cap: three sends fill the mailbox exactly.
                for i in range(3):
                    a.send(bid, f"msg-{i}")
                self.assertEqual(count_messages(db, bid), 3)

                # At the cap: the next send is rejected, not stored.
                with self.assertRaises(RuntimeError) as ctx:
                    a.send(bid, "one too many")
                self.assertIn("mailbox full", str(ctx.exception))

                # Reject-not-evict: existing mail untouched on the server...
                self.assertEqual(count_messages(db, bid), 3)
                # ...and the recipient still reads back every prior message.
                got = sorted(m["text"] for m in b.receive())
                self.assertEqual(got, ["msg-0", "msg-1", "msg-2"])

                # Mailbox drained -> sends flow again.
                self.assertEqual(count_messages(db, bid), 0)
                a.send(bid, "after drain")
                self.assertEqual(count_messages(db, bid), 1)
                print("PASS: overall cap rejects at limit; existing mail kept")
            finally:
                proc.terminate()
                proc.wait(timeout=10)

    def test_per_sender_subcap(self):
        """One sender is capped by the per-sender sub-cap while another sender
        can still deposit up to that sub-cap (no crowding-out)."""
        from retalk import User
        with tempfile.TemporaryDirectory() as tmp:
            proc, db = self._start(
                tmp,
                RETALK_SERVER_MAX_MAILBOX="10",
                RETALK_SERVER_MAX_MAILBOX_PER_SENDER="2")
            try:
                url = f"http://127.0.0.1:{PORT}"
                a = User(url, "sec-a", name="alice",
                         store=os.path.join(tmp, "a.db"))
                b = User(url, "sec-b", name="bob",
                         store=os.path.join(tmp, "b.db"))
                c = User(url, "sec-c", name="carol",
                         store=os.path.join(tmp, "c.db"))
                aid, bid, cid = a.fingerprint(), b.fingerprint(), c.fingerprint()
                a.publish()
                b.publish()
                c.publish()

                # Alice deposits up to her per-sender sub-cap (2)...
                a.send(bid, "a-0")
                a.send(bid, "a-1")
                # ...the third from Alice is rejected even though the overall
                # mailbox (cap 10) is far from full.
                with self.assertRaises(RuntimeError) as ctx:
                    a.send(bid, "a-2")
                self.assertIn("mailbox full for sender", str(ctx.exception))
                self.assertEqual(count_messages(db, bid, aid), 2)

                # Carol is unaffected: she can still deposit her own sub-cap.
                c.send(bid, "c-0")
                c.send(bid, "c-1")
                self.assertEqual(count_messages(db, bid, cid), 2)
                # Total respects the overall cap, both senders represented.
                self.assertEqual(count_messages(db, bid), 4)
                print("PASS: per-sender sub-cap caps one sender, not others")
            finally:
                proc.terminate()
                proc.wait(timeout=10)


if __name__ == "__main__":
    unittest.main()
