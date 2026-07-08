"""Both peers initiating an Olm session at the same time must not wedge the pair.

If A sends to B while B sends to A (before either receives), each side creates
its own outbound session. A store that keeps ONE session per peer then
overwrites its own with the inbound one, the two sides end up holding each
other's session, and every later message fails to decrypt
(OlmDecryptionException: "invalid MAC") forever. Regression tests for exactly
that wedge — and for an already-wedged pair healing itself: the receiver
refuses (nacks) mail it cannot decrypt instead of crashing, and the sender
drops its stale sessions on a verified refusal so the next send starts fresh.

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

PORT = 8774


def wait_for_port(port: int, timeout: float = 15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"server did not start on port {port}")


def start_server(db: str, port: int) -> subprocess.Popen:
    env = dict(os.environ, RETALK_SERVER_DB=db, RETALK_SERVER_HOST="127.0.0.1",
               RETALK_SERVER_PORT=str(port),
               RETALK_SERVER_AUDIENCE=f"http://127.0.0.1:{port}")
    proc = subprocess.Popen(
        [sys.executable, "-m", "retalk.server"],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    wait_for_port(port)
    return proc


class TestCrossedSessions(unittest.TestCase):
    def setUp(self):
        from retalk import User
        self.tmp = tempfile.TemporaryDirectory()
        self.server = start_server(os.path.join(self.tmp.name, "server.db"), PORT)
        url = f"http://127.0.0.1:{PORT}"
        self.a = User(url, "sa", name="a", store=os.path.join(self.tmp.name, "a.db"))
        self.b = User(url, "sb", name="b", store=os.path.join(self.tmp.name, "b.db"))
        self.a.sync(resend=False)   # publish keys so either side can initiate
        self.b.sync(resend=False)

    def tearDown(self):
        self.server.terminate()
        self.server.wait(timeout=10)
        self.tmp.cleanup()

    def texts(self, user, frm):
        return [m["text"] for m in user.receive(frm.fingerprint())
                if "text" in m]

    def test_crossed_initiation_no_wedge(self):
        # both sides send BEFORE either receives: two competing sessions
        self.a.send(self.b.fingerprint(), "m1")
        self.b.send(self.a.fingerprint(), "m2")
        self.assertEqual(self.texts(self.a, self.b), ["m2"])
        self.assertEqual(self.texts(self.b, self.a), ["m1"])
        # the conversation must keep working in BOTH directions afterwards
        # (a one-session-per-peer store crashes here with "invalid MAC")
        self.b.send(self.a.fingerprint(), "reply-from-b")
        self.assertEqual(self.texts(self.a, self.b), ["reply-from-b"])
        self.a.send(self.b.fingerprint(), "reply-from-a")
        self.assertEqual(self.texts(self.b, self.a), ["reply-from-a"])
        # and the acks flowed: nothing is stuck in either outbox
        self.a.receive(self.b.fingerprint())
        self.b.receive(self.a.fingerprint())
        for u in (self.a, self.b):
            con = sqlite3.connect(u._store_path)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM outbox")
                             .fetchone()[0], 0)
            con.close()
        print("PASS: crossed session initiation does not wedge the pair")

    def sids(self, u):
        con = sqlite3.connect(u._store_path)
        r = {x[0] for x in con.execute("SELECT sid FROM sessions").fetchall()}
        con.close()
        return r

    def test_wedged_pair_heals(self):
        # Recreate the state a pre-fix pair is left wedged in: both sides
        # initiated at once and each side kept only the OTHER's session
        # (the old one-session-per-peer store overwrote its own with it).
        self.a.send(self.b.fingerprint(), "m1")
        a_own = self.sids(self.a)                 # a's own outbound session
        self.b.send(self.a.fingerprint(), "m2")
        b_own = self.sids(self.b)                 # b's own outbound session
        self.assertEqual(self.texts(self.a, self.b), ["m2"])
        self.assertEqual(self.texts(self.b, self.a), ["m1"])

        def drop(u, ids):
            con = sqlite3.connect(u._store_path)
            with con:
                for s in ids:
                    con.execute("DELETE FROM sessions WHERE sid=?", (s,))
            con.close()

        drop(self.a, a_own)                       # a keeps only b's session
        drop(self.b, b_own)                       # b keeps only a's session

        # b talks on its (crossed) session: a must NOT crash — it refuses the
        # undecryptable ciphertext (signed nack) and keeps going
        self.b.send(self.a.fingerprint(), "wedged")
        self.assertEqual(self.texts(self.a, self.b), [])

        # b's next sync sees the verified refusal: outbox row dropped AND the
        # stale sessions dropped, so the send after that starts a fresh session
        self.b.sync()
        con = sqlite3.connect(self.b._store_path)
        self.assertEqual(
            con.execute("SELECT COUNT(*) FROM outbox").fetchone()[0], 0)
        self.assertEqual(
            con.execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 0)
        con.close()

        self.b.send(self.a.fingerprint(), "healed")
        self.assertEqual(self.texts(self.a, self.b), ["healed"])
        self.a.send(self.b.fingerprint(), "back at you")
        self.assertEqual(self.texts(self.b, self.a), ["back at you"])
        print("PASS: a wedged pair refuses, resets, and heals")

    def test_legacy_single_session_store_migrates(self):
        from retalk import User
        self.a.send(self.b.fingerprint(), "hello")
        self.assertEqual(self.texts(self.b, self.a), ["hello"])
        # demote both stores to the pre-fix schema: sessions(peer PK, blob)
        for u in (self.a, self.b):
            con = sqlite3.connect(u._store_path)
            with con:
                con.execute("CREATE TABLE _old(peer TEXT PRIMARY KEY, blob TEXT)")
                con.execute("INSERT INTO _old SELECT peer, blob FROM sessions")
                con.execute("DROP TABLE sessions")
                con.execute("ALTER TABLE _old RENAME TO sessions")
            con.close()
        # re-opening migrates the store; the old session keeps working
        url = f"http://127.0.0.1:{PORT}"
        a2 = User(url, "sa", name="a", store=self.a._store_path)
        b2 = User(url, "sb", name="b", store=self.b._store_path)
        b2.send(a2.fingerprint(), "post-migration")
        self.assertEqual(self.texts(a2, b2), ["post-migration"])
        # and the migrated rows were re-keyed by their real session ids
        self.assertTrue(all(self.sids(a2)))
        print("PASS: legacy one-session stores migrate and keep working")


if __name__ == "__main__":
    unittest.main()
