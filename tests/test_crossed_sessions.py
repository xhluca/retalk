"""Simultaneous session initiation + undecryptable-message handling.

Reproduces the two-agent deadlock seen in the wild: both sides send a
pre-key hello before either receives. With a single stored session per
peer, each side ended up holding only the session built from the OTHER's
pre-key (crossed ratchets) — every later message failed its MAC, the
follower crash-looped on the poison message, and acked-but-unreturned
messages in the same batch were lost.

Asserts:
  1. Simultaneous first contact: both hellos decrypt, and every follow-up
     in both directions decrypts (multiple sessions per peer, try each).
  2. Both outboxes drain: crossed traffic is acked end-to-end.
  3. A store with the old single-session schema is migrated in place and
     keeps decrypting.
  4. An undecryptable non-duplicate message no longer aborts the batch: it
     is negative-acked and the rest of the inbox is still delivered; the
     sender's outbox drops the refused ciphertext on its next flush.

Run from the repo root:
  .venv/bin/python -m unittest tests.test_crossed_sessions
"""

import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

try:                                            # unittest discovery (tests.*)
    from tests.test_e2ee import start_server, sql
except ImportError:                             # run directly from tests/
    from test_e2ee import start_server, sql    # noqa: F401

PORT = 8771


def texts(msgs):
    return [m["text"] for m in msgs]


class CrossedSessions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.server_db = os.path.join(cls.tmp.name, "server.db")
        cls.proc = start_server(cls.server_db, PORT)
        cls.url = f"http://127.0.0.1:{PORT}"

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        cls.proc.wait()
        cls.tmp.cleanup()

    def _user(self, name):
        from retalk import User
        store = os.path.join(self.tmp.name, f"{name}.db")
        u = User(self.url, f"secret-{name}", name=name, store=store)
        u.publish()
        return u

    def test_simultaneous_initiation_converges(self):
        a, b = self._user("alice"), self._user("bob")
        aid, bid = a.fingerprint(), b.fingerprint()
        a.names, b.names = {bid: "bob"}, {aid: "alice"}

        # 1) both initiate BEFORE either receives -> two distinct sessions
        a.send(bid, "hello from a")          # a's outbound session S_a
        b.send(aid, "hello from b")          # b's outbound session S_b
        self.assertEqual(texts(a.receive()), ["hello from b"])   # a learns S_b
        self.assertEqual(texts(b.receive()), ["hello from a"])   # b learns S_a

        # both sides now hold TWO sessions for the peer
        self.assertEqual(sql(a._store_path,
                             "SELECT count(*) FROM sessions WHERE peer=?",
                             bid)[0][0], 2)
        self.assertEqual(sql(b._store_path,
                             "SELECT count(*) FROM sessions WHERE peer=?",
                             aid)[0][0], 2)

        # 2) crossed follow-ups decrypt in BOTH directions (the old deadlock)
        a.send(bid, "a follow-up 1")
        b.send(aid, "b follow-up 1")
        self.assertEqual(texts(a.receive()), ["b follow-up 1"])
        self.assertEqual(texts(b.receive()), ["a follow-up 1"])
        a.send(bid, "a follow-up 2")
        self.assertEqual(texts(b.receive()), ["a follow-up 2"])
        b.send(aid, "b follow-up 2")
        self.assertEqual(texts(a.receive()), ["b follow-up 2"])

        # 3) acks flowed both ways -> outboxes drain
        a.receive(), b.receive()             # pick up the last acks
        self.assertEqual(sql(a._store_path, "SELECT count(*) FROM outbox")[0][0], 0)
        self.assertEqual(sql(b._store_path, "SELECT count(*) FROM outbox")[0][0], 0)

    def test_v1_single_session_schema_migrates(self):
        from retalk import User
        c, d = self._user("carol"), self._user("dave")
        cid, did = c.fingerprint(), d.fingerprint()
        c.send(did, "pre-migration")
        self.assertEqual(texts(d.receive()), ["pre-migration"])

        # rewrite d's sessions table to the old single-session shape
        conn = sqlite3.connect(d._store_path)
        with conn:
            rows = conn.execute(
                "SELECT peer, blob FROM sessions GROUP BY peer").fetchall()
            conn.execute("DROP TABLE sessions")
            conn.execute("CREATE TABLE sessions(peer TEXT PRIMARY KEY, blob TEXT)")
            conn.executemany("INSERT INTO sessions VALUES(?,?)", rows)
        conn.close()

        # re-opening the store migrates it; the session still decrypts
        d2 = User(self.url, "secret-dave", name="dave",
                  store=d._store_path)
        cols = [r[1] for r in sqlite3.connect(d._store_path).execute(
            "PRAGMA table_info(sessions)")]
        self.assertEqual(cols, ["peer", "session_id", "blob", "mru"])
        c.send(did, "post-migration")
        self.assertEqual(texts(d2.receive()), ["post-migration"])

    def test_undecryptable_message_is_nacked_not_fatal(self):
        e, f, g = self._user("erin"), self._user("frank"), self._user("gary")
        eid, fid, gid = e.fingerprint(), f.fingerprint(), g.fingerprint()

        # establish a session f -> e, then wipe e's side of it (simulates the
        # pre-fix crossed-session state or a lost store)
        m1 = f.send(eid, "establishes session")
        self.assertEqual(texts(e.receive()), ["establishes session"])
        sql(e._store_path, "DELETE FROM sessions")
        sql(e._store_path, "DELETE FROM processed")

        m2 = f.send(eid, "poison: e cannot decrypt this")  # mtype 1, dead session
        g.send(eid, "fresh hello from g")                  # decryptable pre-key

        # the poison message must not abort the batch: g's message arrives
        got = e.receive()
        self.assertEqual(texts(got), ["fresh hello from g"])

        # the poison ciphertext was nacked: f's next flush gets a refusal for
        # m2 and drops it; m1 (acked by e, ack not yet processed by f) remains
        self.assertEqual(sorted(r[0] for r in sql(
            f._store_path, "SELECT id FROM outbox")), sorted([m1, m2]))
        f.flush_outbox()
        remaining = [r[0] for r in sql(f._store_path, "SELECT id FROM outbox")]
        self.assertNotIn(m2, remaining)                    # poison dropped
        self.assertIn(m1, remaining)                       # normal row intact


if __name__ == "__main__":
    unittest.main()
