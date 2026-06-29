"""Block list + peers-only receive policy (client-side).

Asserts, against a live local server (the same untrusted relay the other
suites use):

  1. A blocked sender's message is NOT returned by receive(), no inbound
     session is created for them, and — crucially — no one-time key is
     consumed: the skip happens before any handshake. Their mail stays on
     the server, unread.
  2. In peers-only mode an unsaved (unknown) sender is skipped while a saved
     peer's message is still delivered. Again, no key is consumed for the
     unknown sender.
  3. The CLI `block`/`block --remove`/`block --list` commands round-trip, and
     `receive --peers-only` drops an unknown sender while delivering a peer.

Uses port 8770 (see tests/README.md for the port registry).
Run from the repo root: uv run python -m unittest discover -s tests
"""

import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

PORT = 8770
CLI_PORT = 8771


def sql(db: str, query: str, *params) -> list:
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
    env = dict(os.environ, RETALK_SERVER_DB=db, RETALK_SERVER_HOST="127.0.0.1",
               RETALK_SERVER_PORT=str(port),
               RETALK_SERVER_AUDIENCE=f"http://127.0.0.1:{port}")
    proc = subprocess.Popen(
        [sys.executable, "-m", "retalk.server"],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    wait_for_port(port)
    return proc


def texts(msgs):
    return [m["text"] for m in msgs]


class TestBlockList(unittest.TestCase):
    def test_block_and_peers_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            server_db = os.path.join(tmp, "server.db")
            server = start_server(server_db, PORT)
            try:
                self._scenario(tmp, server_db)
            finally:
                server.terminate()
                server.wait(timeout=10)

    def _scenario(self, tmp, server_db):
        from retalk import User

        url = f"http://127.0.0.1:{PORT}"
        store_r = os.path.join(tmp, "recv.db")
        store_p = os.path.join(tmp, "peer.db")
        store_s = os.path.join(tmp, "stranger.db")

        r = User(url, "secret-r", name="recv", store=store_r)
        p = User(url, "secret-p", name="peer", store=store_p)
        s = User(url, "secret-s", name="stranger", store=store_s)
        rid, pid, sid = r.fingerprint(), p.fingerprint(), s.fingerprint()

        for u in (r, p, s):
            u.publish()

        def session_peers():
            return {row[0] for row in sql(store_r, "SELECT peer FROM sessions")}

        def get_keys_spy(user):
            """Count get_keys calls — the call made immediately before
            create_inbound_session consumes a one-time key. Zero calls means
            no handshake (and so no one-time key) was spent for that read."""
            calls = []
            orig = user._call

            def wrapped(tool, args=None):
                if tool == "get_keys":
                    calls.append(args)
                return orig(tool, args)

            user._call = wrapped
            return calls

        # --- 1. blocked sender is dropped before any crypto/key work ---
        # Target the stranger specifically so the read only touches her mail:
        # the block must drop it WITHOUT a handshake (no get_keys, no inbound
        # session, so no one-time key is consumed).
        r.blocked = {sid}
        s.send(rid, "spam from a blocked stranger")
        spy = get_keys_spy(r)
        got = r.receive(peer=sid)
        self.assertEqual(got, [], f"blocked sender surfaced: {got!r}")
        self.assertEqual(spy, [],
                         "blocked sender triggered a key handshake (one-time "
                         "key would be consumed)")
        self.assertNotIn(sid, session_peers(),
                         "an inbound session was created for a blocked sender")
        print("PASS 1: blocked sender dropped; no handshake, no session")

        # unblock -> a fresh message from the same sender now decrypts and,
        # being a first contact, performs the handshake (consuming an OTK)
        r.blocked = set()
        s.send(rid, "now that I'm unblocked")
        spy.clear()
        got = r.receive(peer=sid)
        self.assertEqual(texts(got), ["now that I'm unblocked"], got)
        self.assertIn(sid, session_peers())
        self.assertEqual(len(spy), 1,
                         "an accepted first-contact message should handshake once")
        print("PASS 2: after unblock the sender's message decrypts (handshakes)")

        # --- 3. peers-only: known peer delivered, unknown sender dropped ---
        # fresh receiver so neither sender has a session yet
        store_r2 = os.path.join(tmp, "recv2.db")
        r2 = User(url, "secret-r2", name="recv2", store=store_r2,
                  names={pid: "peer"}, known={pid},
                  receive_policy="peers-only")
        r2.publish()
        rid2 = r2.fingerprint()

        def session_peers2():
            return {row[0] for row in sql(store_r2, "SELECT peer FROM sessions")}

        p.send(rid2, "hello from a saved peer")
        s.send(rid2, "knock from an unknown sender")
        spy2 = get_keys_spy(r2)
        got = r2.receive()
        self.assertEqual(texts(got), ["hello from a saved peer"],
                         f"peers-only did not filter correctly: {got!r}")
        self.assertIn(pid, session_peers2())
        self.assertNotIn(sid, session_peers2(),
                         "unknown sender got a session in peers-only mode")
        # the handshake happened for the known peer only, never the stranger
        self.assertEqual([a["peer"] for a in spy2], [pid],
                         "unknown sender triggered a key handshake in peers-only")
        print("PASS 3: peers-only delivers a saved peer, drops an unknown sender")


class TestBlockCLI(unittest.TestCase):
    def cli(self, *cmd, secret="cli-secret", expect=0, env_extra=None):
        env = dict(os.environ,
                   RETALK_PASSPHRASE=secret,
                   RETALK_RELAY=f"http://127.0.0.1:{CLI_PORT}",
                   RETALK_HOME=os.path.join(self.tmp, "store"))
        env.pop("RETALK_USER", None)
        _h = os.path.join(self.tmp, "store"); os.makedirs(_h, exist_ok=True)
        _c = os.path.join(_h, "config.json")
        if not os.path.exists(_c): open(_c, "w").write("{}")  # hermetic: no default relay
        if env_extra:
            env.update(env_extra)
        res = subprocess.run([sys.executable, "-m", "retalk.cli", *cmd],
                             capture_output=True, text=True, env=env)
        self.assertEqual(res.returncode, expect,
                         f"{cmd}: rc={res.returncode}\n{res.stderr}")
        return res

    def test_block_commands_and_peers_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.tmp = tmp
            server = start_server(os.path.join(tmp, "server.db"), CLI_PORT)
            try:
                self._flow(tmp)
            finally:
                server.terminate()
                server.wait(timeout=10)

    def _flow(self, tmp):
        a = os.path.join(tmp, "alice")   # receiver
        b = os.path.join(tmp, "bob")     # saved peer
        c = os.path.join(tmp, "carol")   # unknown sender

        aid = self.cli("init", "--dir", a, "--display-name", "alice").stdout.strip()
        bid = self.cli("init", "--dir", b, "--display-name", "bob").stdout.strip()
        cid = self.cli("init", "--dir", c, "--display-name", "carol").stdout.strip()

        # alice knows bob, not carol
        self.cli("add", bid, "--name", "bob", "--dir", a)
        self.cli("receive", "--all", "--dir", a)  # alice publishes keys

        # block / block --list / block --remove round-trip (by name and raw id)
        self.cli("block", "bob", "--dir", a)
        self.cli("block", cid, "--dir", a)
        listed = {json.loads(l)["fingerprint"]
                  for l in self.cli("block", "--list", "--json", "--dir", a).stdout.splitlines()}
        self.assertEqual(listed, {bid, cid}, listed)
        self.cli("block", "--remove", "bob", "--dir", a)
        listed = {json.loads(l)["fingerprint"]
                  for l in self.cli("block", "--list", "--json", "--dir", a).stdout.splitlines()}
        self.assertEqual(listed, {cid}, listed)

        # re-block carol by name? she has no saved name; block already done by
        # id above and survives the bob-only unblock. carol is blocked -> her
        # message never surfaces. Target carol so the read only touches her mail.
        self.cli("send", "--peer", aid, "from carol (blocked)", "--dir", c)
        out = self.cli("receive", "--peer", cid, "--dir", a).stdout
        self.assertEqual(out, "", f"blocked carol surfaced via CLI: {out!r}")

        # bob (unblocked, saved) is delivered even in --peers-only mode
        self.cli("send", "--peer", aid, "hi from bob", "--dir", b)
        out = self.cli("receive", "--all", "--peers-only", "--dir", a).stdout
        msgs = [json.loads(l) for l in out.splitlines()]
        self.assertEqual([(m["from"], m["text"]) for m in msgs],
                         [(bid, "hi from bob")], msgs)

        # unblock carol, but with --peers-only she's still unknown -> dropped.
        # Target carol so only her mail is read (and dropped).
        self.cli("block", "--remove", cid, "--dir", a)
        self.cli("send", "--peer", aid, "first knock from carol", "--dir", c)
        out = self.cli("receive", "--peer", cid, "--peers-only", "--dir", a).stdout
        self.assertEqual(out, "", f"unknown carol surfaced in peers-only: {out!r}")
        # add carol as a peer -> peers-only now delivers her. Carol is a
        # fire-and-forget sender (she only ever `send`s, never `receive`s), yet
        # her earlier blocked/dropped messages are NOT resurrected: each was
        # refused server-side (a signed negative ack), so the relay rejects the
        # resends and carol marks them dropped from the rejection. Only her
        # latest, accepted message arrives.
        self.cli("add", cid, "--name", "carol", "--dir", a)
        self.cli("send", "--peer", aid, "second knock from carol", "--dir", c)
        out = self.cli("receive", "--all", "--peers-only", "--dir", a).stdout
        texts = [json.loads(l)["text"] for l in out.splitlines()]
        self.assertEqual(texts, ["second knock from carol"], texts)
        print("PASS: CLI block/block --list/block --remove + --peers-only; "
              "server-side nack keeps a send-only sender's refused mail from "
              "resurrecting")


if __name__ == "__main__":
    unittest.main()
