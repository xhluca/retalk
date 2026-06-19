"""Unified sync semantics (src/retalk/user.py `sync()` + CLI wiring).

Asserts the design we settled on:
  - `receive` reconciles keys but NEVER resends the outbox
    (`sync(resend=False)`); `send` and an explicit `sync` both resend.
  - `sync` re-publishes keys when the relay has forgotten the user.

Uses ports 8796 (library) / 8797 (CLI); see tests/README.md.
Run from the repo root: uv run python -m unittest discover -s tests
"""

import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

PORT = 8796
CLI_PORT = 8797


def sql(db, q, *p):
    conn = sqlite3.connect(db)
    try:
        with conn:
            return conn.execute(q, p).fetchall()
    finally:
        conn.close()


def mailbox(db, rid):
    return sql(db, "SELECT COUNT(*) FROM messages WHERE recipient=?", rid)[0][0]


def wait_for_port(port, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"server did not start on port {port}")


def start_server(db, port):
    env = dict(os.environ, RETALK_SERVER_DB=db, RETALK_SERVER_HOST="127.0.0.1",
               RETALK_SERVER_PORT=str(port),
               RETALK_SERVER_AUDIENCE=f"http://127.0.0.1:{port}")
    proc = subprocess.Popen([sys.executable, "-m", "retalk.server"], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    wait_for_port(port)
    return proc


class TestSync(unittest.TestCase):
    def test_resend_only_via_sync(self):
        from retalk import User
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "server.db")
            proc = start_server(db, PORT)
            url = f"http://127.0.0.1:{PORT}"
            try:
                a = User(url, "sa", name="a", store=os.path.join(tmp, "a.db"))
                b = User(url, "sb", name="b", store=os.path.join(tmp, "b.db"))
                bid = b.fingerprint()
                a.publish(); b.publish()

                a.send(bid, "m1")
                self.assertEqual(mailbox(db, bid), 1)

                # the relay loses its stored mail before Bob reads it
                sql(db, "DELETE FROM messages")
                self.assertEqual(mailbox(db, bid), 0)

                # a receive-style pass (resend=False) must NOT re-upload it
                a.sync(resend=False)
                self.assertEqual(mailbox(db, bid), 0,
                                 "sync(resend=False) resent the outbox")

                # a full sync DOES re-upload it (loss recovery)
                res = a.sync()
                self.assertEqual(res["resent"], 1)
                self.assertEqual(mailbox(db, bid), 1, "sync did not resend")

                self.assertEqual([m["text"] for m in b.receive()], ["m1"])
            finally:
                proc.terminate(); proc.wait(timeout=10)

    def test_sync_republishes_after_wipe(self):
        from retalk import User
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "server.db")
            proc = start_server(db, PORT)
            url = f"http://127.0.0.1:{PORT}"
            try:
                a = User(url, "sa", name="a", store=os.path.join(tmp, "a.db"))
                aid = a.fingerprint()
                a.publish()
                self.assertTrue(a._call("count_keys")["has_fallback"])

                # the relay forgets Alice (DB wiped/migrated)
                sql(db, "DELETE FROM users WHERE id=?", aid)
                sql(db, "DELETE FROM otks WHERE owner=?", aid)
                self.assertFalse(a._call("count_keys")["has_fallback"])

                # sync notices and re-publishes keys + a fresh OTK batch
                res = a.sync()
                self.assertTrue(res["republished"])
                ck = a._call("count_keys")
                self.assertTrue(ck["has_fallback"])
                self.assertGreater(ck["unclaimed"], 0)
            finally:
                proc.terminate(); proc.wait(timeout=10)

    def test_server_side_nack_stops_resend_without_alice_receiving(self):
        # Bob refuses Alice's message; the relay records the signed negative ack
        # and rejects the resend, handing Alice Bob's signature. Alice deletes
        # the entry from her outbox on that rejection -- she NEVER calls
        # receive, proving the fire-and-forget sender is covered.
        from retalk import User
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "server.db")
            proc = start_server(db, PORT)
            url = f"http://127.0.0.1:{PORT}"
            a_store = os.path.join(tmp, "a.db")
            try:
                a = User(url, "sa", name="a", store=a_store)
                b = User(url, "sb", name="b", store=os.path.join(tmp, "b.db"))
                aid, bid = a.fingerprint(), b.fingerprint()
                a.publish(); b.publish()

                b.blocked = {aid}
                a.send(bid, "let me in")
                self.assertEqual(b.receive(), [])    # dropped -> nack on the relay
                self.assertEqual(
                    sql(db, "SELECT COUNT(*) FROM refused WHERE recipient=?",
                        bid)[0][0], 1, "relay did not record the negative ack")

                # Alice's resend is refused; she deletes it from her outbox (no
                # receive needed)
                self.assertEqual(a.sync()["resent"], 0, "resent a refused message")
                self.assertEqual(
                    sql(a_store, "SELECT COUNT(*) FROM outbox")[0][0], 0,
                    "refusal proof did not remove the outbox entry")
                self.assertEqual(mailbox(db, bid), 0, "refused message got stored")
            finally:
                proc.terminate(); proc.wait(timeout=10)

    def test_forged_refusal_is_ignored(self):
        # A hostile relay (or attacker with DB access) can mark a hash refused,
        # but WITHOUT the recipient's signature the sender must not treat it as a
        # real refusal -- else the relay could forge refusals to make senders
        # give up. The send stays blocked at the relay, but the outbox entry
        # stays put, so nothing is silently abandoned on a lie.
        from retalk import User
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "server.db")
            proc = start_server(db, PORT)
            url = f"http://127.0.0.1:{PORT}"
            a_store = os.path.join(tmp, "a.db")
            try:
                a = User(url, "sa", name="a", store=a_store)
                b = User(url, "sb", name="b", store=os.path.join(tmp, "b.db"))
                bid = b.fingerprint()
                a.publish(); b.publish()
                a.send(bid, "hi")

                body = sql(a_store, "SELECT body FROM outbox")[0][0]
                h = hashlib.sha256(body.encode()).hexdigest()
                sql(db, "INSERT INTO refused(recipient, hash, sig, ts) "
                        "VALUES(?,?,?,?)", bid, h, "not-a-real-signature",
                    time.time())

                a.sync()
                self.assertEqual(
                    sql(a_store, "SELECT COUNT(*) FROM outbox")[0][0], 1,
                    "trusted a forged (unsigned) refusal and dropped the message")
            finally:
                proc.terminate(); proc.wait(timeout=10)

    def test_refused_entry_expires(self):
        # An expired refusal (older than the server's TTL) no longer blocks a
        # resend -- the message goes through and the outbox entry is kept (only a
        # *verified, live* refusal removes it). This is the count aging out.
        from retalk import User
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "server.db")
            proc = start_server(db, PORT)
            url = f"http://127.0.0.1:{PORT}"
            a_store = os.path.join(tmp, "a.db")
            try:
                a = User(url, "sa", name="a", store=a_store)
                b = User(url, "sb", name="b", store=os.path.join(tmp, "b.db"))
                bid = b.fingerprint()
                a.publish(); b.publish()
                a.send(bid, "x")
                sql(db, "DELETE FROM messages")                  # relay loses it

                body = sql(a_store, "SELECT body FROM outbox")[0][0]
                h = hashlib.sha256(body.encode()).hexdigest()
                sql(db, "INSERT INTO refused(recipient, hash, sig, ts) "
                        "VALUES(?,?,?,?)", bid, h, "sig",
                    time.time() - 8 * 24 * 3600)             # older than 7d TTL

                a.sync()
                self.assertEqual(mailbox(db, bid), 1,
                                 "an expired refusal still blocked delivery")
                self.assertEqual(
                    sql(a_store, "SELECT COUNT(*) FROM outbox")[0][0], 1,
                    "outbox entry wrongly removed on an expired refusal")
            finally:
                proc.terminate(); proc.wait(timeout=10)

    def test_expired_refusals_pruned_on_new_nack(self):
        # A fresh nack prunes server-wide expired refusals, so the table shrinks
        # over time rather than only at the per-recipient cap.
        from retalk import User
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "server.db")
            proc = start_server(db, PORT)
            url = f"http://127.0.0.1:{PORT}"
            try:
                a = User(url, "sa", name="a", store=os.path.join(tmp, "a.db"))
                b = User(url, "sb", name="b", store=os.path.join(tmp, "b.db"))
                aid, bid = a.fingerprint(), b.fingerprint()
                a.publish(); b.publish()

                old = time.time() - 8 * 24 * 3600                # past the TTL
                for hh in ("a" * 64, "b" * 64):
                    sql(db, "INSERT INTO refused(recipient, hash, sig, ts) "
                            "VALUES(?,?,?,?)", bid, hh, "s", old)
                self.assertEqual(sql(db, "SELECT COUNT(*) FROM refused")[0][0], 2)

                b.blocked = {aid}                               # trigger a nack
                a.send(bid, "let me in")
                self.assertEqual(b.receive(), [])
                rows = sql(db, "SELECT hash FROM refused WHERE recipient=?", bid)
                self.assertEqual(len(rows), 1,
                                 f"stale refusals not pruned on a new nack: {rows}")
            finally:
                proc.terminate(); proc.wait(timeout=10)


class TestSyncCLI(unittest.TestCase):
    def cli(self, *cmd, secret="cli", expect=0):
        env = dict(os.environ, RETALK_PASSPHRASE=secret,
                   RETALK_RELAY=f"http://127.0.0.1:{CLI_PORT}",
                   XDG_DATA_HOME=os.path.join(self.tmp, "xdg"))
        env.pop("RETALK_USER", None)
        res = subprocess.run([sys.executable, "-m", "retalk.cli", *cmd],
                             capture_output=True, text=True, env=env)
        self.assertEqual(res.returncode, expect, f"{cmd}: {res.stderr}")
        return res

    def test_receive_never_resends_but_send_and_sync_do(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.tmp = tmp
            db = os.path.join(tmp, "server.db")
            proc = start_server(db, CLI_PORT)
            try:
                a = os.path.join(tmp, "alice")
                b = os.path.join(tmp, "bob")
                self.cli("init", "--dir", a, "--display-name", "alice")
                bid = self.cli("init", "--dir", b,
                               "--display-name", "bob").stdout.strip()
                self.cli("receive", "--all", "--dir", b)   # bob publishes
                self.cli("add", "bob", bid, "--dir", a)

                self.cli("send", "--peer", "bob", "m1", "--dir", a)
                self.assertEqual(mailbox(db, bid), 1)
                sql(db, "DELETE FROM messages")            # relay loses it
                self.assertEqual(mailbox(db, bid), 0)

                # alice receiving must not resend the lost m1
                self.cli("receive", "--all", "--dir", a)
                self.assertEqual(mailbox(db, bid), 0, "receive resent the outbox")

                # alice sending m2 also resends the still-unacked m1
                # (send runs a full sync first), recovering the lost message
                self.cli("send", "--peer", "bob", "m2", "--dir", a)
                self.assertEqual(mailbox(db, bid), 2,
                                 "send did not resend the unacked outbox")

                # an explicit sync resends both again (the relay has no dedup;
                # the recipient de-duplicates by id on receive)
                sql(db, "DELETE FROM messages")
                self.cli("sync", "--dir", a)
                self.assertEqual(mailbox(db, bid), 2, "sync did not resend")

                # bob ends up with both, de-duplicated
                out = self.cli("receive", "--all", "--dir", b).stdout
                got = {json.loads(l)["text"] for l in out.splitlines()}
                self.assertEqual(got, {"m1", "m2"}, out)
            finally:
                proc.terminate(); proc.wait(timeout=10)


if __name__ == "__main__":
    unittest.main()
