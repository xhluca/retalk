"""End-to-end test: local server + two users using signed-request auth.

Asserts:
  1. A can send to B (addressed by fingerprint ID) and B decrypts the exact
     plaintext — with zero registration calls; publishing keys is the only
     onboarding.
  2. B can reply and A decrypts the exact plaintext.
  3. The server's stored message bodies contain no plaintext.
  4. After tampering with B's identity key in the server DB (and clearing A's
     cached session), A's next send raises a PIN MISMATCH error — even
     without an explicit pin, because the user ID is the keys' fingerprint.
  5. With B's one-time keys drained, a new session is established via B's
     fallback key.
  6. maintain() replenishes the one-time-key stash and rotates a stale
     fallback key.
  7. A message in flight to the OLD fallback key still decrypts after one
     rotation (grace window).
  8. Two OS processes sharing one user store send concurrently without
     corrupting the ratchet (the per-store lock serializes operations).
  9. Migrating to a brand-new server keeps existing sessions working:
     publish keys, send, decrypt — no other onboarding, no new handshake.
 10. Every delivered message is acknowledged end-to-end, emptying the
     senders' outboxes.
 11. A message stranded on a dead server is recovered by flushing the
     outbox to the new server; the late duplicate from the old server is
     rejected by the ratchet and dropped gracefully (re-acked, not surfaced).
 12. A captured signed request, submitted again, is rejected (nonce cache).
 13. A request with an hour-old timestamp is rejected.
 14. A request signed for server 1 is rejected at server 2 (signatures are
     bound to the server URL).

Run from the repo root:
  .venv/bin/python -m unittest discover -s tests   (all test files)
  .venv/bin/python tests/test_e2ee.py              (this file directly)
"""

import hashlib
import unittest
import os
import secrets
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time

PORT = 8767
PORT2 = 8768


def sql(db: str, query: str, *params) -> list:
    """Run one statement against a SQLite file; returns all rows."""
    conn = sqlite3.connect(db)
    try:
        with conn:
            return conn.execute(query, params).fetchall()
    finally:
        conn.close()


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
    env = dict(os.environ, SERVER_DB=db, SERVER_HOST="127.0.0.1",
               SERVER_PORT=str(port),
               SERVER_AUDIENCE=f"http://127.0.0.1:{port}")
    proc = subprocess.Popen(
        [sys.executable, "-m", "retalk.server"],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    wait_for_port(port)
    return proc


def main(tmp: str):
    import vodozemac as vz

    from retalk import User, PinMismatchError

    server_db = os.path.join(tmp, "server.db")
    store_a = os.path.join(tmp, "user_a.db")
    store_b = os.path.join(tmp, "user_b.db")
    servers = [start_server(server_db, PORT)]
    try:
        url = f"http://127.0.0.1:{PORT}"

        a = User(url, "pickle-secret-a", name="alice-user-1", store=store_a)
        b = User(url, "pickle-secret-b", name="bob-user-1", store=store_b)
        aid, bid = a.user_id(), b.user_id()
        # the IDs are self-verifying fingerprints; explicit pins on top
        a.pins = {bid: b.identity_key()}
        b.pins = {aid: a.identity_key()}
        # A assigns B a local peer name; B relies on the ~unverified name
        a.names = {bid: "bob"}

        # onboarding is publish_keys alone — no registration call exists
        a.publish()
        b.publish()

        # 1. A -> B
        msg_ab = "hello from A: the launch code is swordfish-7741"
        a.send(bid, msg_ab)
        got = b.receive()
        assert got == [(aid, "~alice-user-1", msg_ab)], f"B received {got!r}"
        print("PASS 1: A -> B decrypted exact plaintext (no registration)")

        # 2. B -> A
        msg_ba = "reply from B: acknowledged swordfish-7741"
        b.send(aid, msg_ba)
        got = a.receive()
        assert got == [(bid, "bob", msg_ba)], f"A received {got!r}"
        print("PASS 2: B -> A decrypted exact plaintext")

        # 3. server stores no plaintext (2 messages + 2 acks, all ciphertext)
        bodies = [r[0] for r in sql(server_db, "SELECT body FROM messages")]
        assert len(bodies) == 4, len(bodies)
        for body in bodies:
            for needle in (msg_ab, msg_ba, "swordfish", "hello from A", "reply from B"):
                assert needle not in body, f"plaintext leaked to server: {needle!r}"
        print("PASS 3: server-stored bodies contain no plaintext")

        # 4. tampered identity key -> PIN MISMATCH on next send
        evil_key = vz.Account().curve25519_key.to_base64()
        sql(server_db, "UPDATE users SET identity_key=? WHERE id=?", evil_key, bid)
        sql(store_a, "DELETE FROM sessions WHERE peer=?", bid)
        a.pins = {}  # the fingerprint ID alone must catch the tamper
        try:
            a.send(bid, "this must never be encrypted to the evil key")
        except PinMismatchError as e:
            assert "PIN MISMATCH" in str(e)
            print("PASS 4: tampered server key triggered PIN MISMATCH refusal")
        else:
            raise AssertionError("send succeeded despite tampered identity key")

        # restore B's real identity key for the remaining tests
        sql(server_db, "UPDATE users SET identity_key=? WHERE id=?",
            b.identity_key(), bid)

        # 5. drained one-time keys -> session established via fallback key
        sql(server_db, "UPDATE otks SET claimed=1 WHERE owner=?", bid)
        counts = b._call("count_keys")
        assert counts == {"unclaimed": 0, "has_fallback": True}, counts
        claimed = a._call("claim_key", {"peer": bid})
        assert claimed["fallback"] is True, claimed
        # A's cached session was cleared in test 4 -> this send is a fresh
        # handshake, necessarily via the fallback key
        msg_fb = "session via fallback key: tango-19"
        a.send(bid, msg_fb)  # left in flight; B reads it in test 7
        old_fb = sql(server_db,
                     "SELECT fallback_key FROM users WHERE id=?", bid)[0][0]
        print("PASS 5: drained pool served the fallback key")

        # 6. maintain() replenishes the stash and rotates a stale fallback
        b._meta_set("fallback_ts", "0")  # pretend the fallback key is ancient
        status = b.maintain(min_otks=20, batch=60, fallback_max_age=3600)
        assert status["replenished"] and status["fallback_rotated"], status
        counts = b._call("count_keys")
        assert counts["unclaimed"] >= 60, counts
        new_fb = sql(server_db,
                     "SELECT fallback_key FROM users WHERE id=?", bid)[0][0]
        assert new_fb != old_fb, "fallback key was not rotated"
        status = b.maintain(min_otks=20, batch=60, fallback_max_age=3600)
        assert not status["replenished"] and not status["fallback_rotated"], (
            f"maintain() not idempotent when healthy: {status}")
        print("PASS 6: maintain() replenished one-time keys and rotated the fallback")

        # 7. in-flight message to the OLD fallback decrypts after rotation
        got = b.receive()
        assert got == [(aid, "~alice-user-1", msg_fb)], f"B received {got!r}"
        print("PASS 7: in-flight message to the pre-rotation fallback decrypted")

        # 8. concurrent sends from two processes sharing A's store
        sender_src = (
            "import sys\n"
            "from retalk import User\n"
            "a = User(sys.argv[1], 'pickle-secret-a', store=sys.argv[2])\n"
            "for i in range(5):\n"
            "    a.send(sys.argv[3], f'msg-{sys.argv[4]}-{i}')\n"
        )
        procs = [subprocess.Popen([sys.executable, "-c", sender_src,
                                   url, store_a, bid, tag])
                 for tag in ("P1", "P2")]
        for p in procs:
            assert p.wait(timeout=60) == 0, "concurrent sender crashed"
        got = sorted(text for _, _, text in b.receive())
        expected = sorted(f"msg-{tag}-{i}" for tag in ("P1", "P2") for i in range(5))
        assert got == expected, f"B received {got!r}"
        print("PASS 8: concurrent senders sharing one store stayed in sync")

        # 9. server migration: fresh server, same stores -> sessions continue
        # first complete a round-trip so A's session leaves the pre-key phase
        # (Olm sends handshake-type messages until a reply is received)
        b.send(aid, "establishing reply")
        got = a.receive()
        assert got == [(bid, "bob", "establishing reply")], got
        server2_db = os.path.join(tmp, "server2.db")
        servers.append(start_server(server2_db, PORT2))
        url2 = f"http://127.0.0.1:{PORT2}"
        a2 = User(url2, "pickle-secret-a", name="alice-user-1", store=store_a)
        b2 = User(url2, "pickle-secret-b", name="bob-user-1", store=store_b)
        assert (a2.user_id(), b2.user_id()) == (aid, bid), "IDs not server-independent"
        # publishing keys is the only onboarding the new server needs (both
        # sides: a mailbox must exist before it can receive even an ack)
        a2.publish()
        b2.publish()
        msg_mig = "still here after the server moved"
        a2.send(bid, msg_mig)
        mtypes = [r[0] for r in sql(server2_db, "SELECT mtype FROM messages")]
        assert mtypes == [1], f"expected an existing-session message, got {mtypes}"
        got = b2.receive()
        assert got == [(aid, "~alice-user-1", msg_mig)], f"B received {got!r}"
        print("PASS 9: session survived migration to a brand-new server")

        # 10. ack lifecycle: drain everything on both servers; every sent
        # message must end up acknowledged, leaving both outboxes empty
        for _ in range(6):
            rounds = [x.receive() for x in (a, b, a2, b2)]
            if not any(rounds):
                break
        for store in (store_a, store_b):
            n = sql(store, "SELECT COUNT(*) FROM outbox")[0][0]
            assert n == 0, f"{store} still has {n} unacked outbox entries"
        print("PASS 10: every message acked end-to-end; outboxes empty")

        # 11. lost-message recovery: send via the old server, never read it
        # there, then flush the outbox to the new server
        msg_lost = "message stranded on the dying server"
        a.send(bid, msg_lost)  # server 1; B will not poll server 1 yet
        assert sql(store_a, "SELECT COUNT(*) FROM outbox")[0][0] == 1
        assert b2.receive() == []  # nothing on server 2 yet
        n = a2.flush_outbox()
        assert n == 1, n
        got = b2.receive()
        assert got == [(aid, "~alice-user-1", msg_lost)], f"B received {got!r}"
        # the stranded copy now arrives via server 1 too: the ratchet refuses
        # the re-used message key, and the client re-acks and drops it
        # instead of surfacing a duplicate or crashing
        got = b.receive()
        assert got == [], f"duplicate surfaced: {got!r}"
        a2.receive()  # consume B's ack
        assert sql(store_a, "SELECT COUNT(*) FROM outbox")[0][0] == 0
        print("PASS 11: unacked message recovered via outbox; duplicate copy "
              "rejected by the ratchet and dropped gracefully")

        # 12. replay: capture one signed request, submit it twice
        wire = {"auth": a._auth_fields("read_messages", {})}
        first = a._call_raw("read_messages", wire)
        assert isinstance(first, list)
        try:
            a._call_raw("read_messages", wire)
        except RuntimeError as e:
            assert "replay" in str(e), e
            print("PASS 12: replayed request rejected by the nonce cache")
        else:
            raise AssertionError("replayed request was accepted")

        # 13. stale timestamp (signed honestly, an hour ago)
        acct = a._load_account()
        old_ts = str(int(time.time()) - 3600)
        nonce = secrets.token_hex(16)
        args_hash = hashlib.sha256(b"{}").hexdigest()
        payload = f"read_messages|{url}|{aid}|{old_ts}|{nonce}|{args_hash}".encode()
        stale = a._auth_fields("read_messages", {})
        stale.update(ts=old_ts, nonce=nonce, sig=acct.sign(payload).to_base64())
        try:
            a._call_raw("read_messages", {"auth": stale})
        except RuntimeError as e:
            assert "stale" in str(e) or "timestamp" in str(e), e
            print("PASS 13: hour-old timestamp rejected")
        else:
            raise AssertionError("stale timestamp was accepted")

        # 14. cross-server replay: a signature for server 1 fails at server 2
        wire1 = {"auth": a._auth_fields("read_messages", {})}  # bound to url
        try:
            a2._call_raw("read_messages", wire1)
        except RuntimeError as e:
            assert "signature" in str(e), e
            print("PASS 14: server-1 signature rejected at server 2 (audience)")
        else:
            raise AssertionError("cross-server replay was accepted")

        print("\nALL 14 ACCEPTANCE CRITERIA PASSED")
    finally:
        for proc in servers:
            proc.terminate()
            proc.wait(timeout=10)


class TestE2EE(unittest.TestCase):
    """The 14 acceptance criteria are one deliberately ordered, stateful
    scenario (later criteria build on earlier state), so they run as a
    single test method rather than 14 isolated ones."""

    def test_acceptance_criteria(self):
        with tempfile.TemporaryDirectory() as tmp:
            main(tmp)


if __name__ == "__main__":
    unittest.main()
