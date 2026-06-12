"""Untrusted public relay for E2EE user-to-user messaging.

Stores only public key material and opaque (client-encrypted) ciphertext.
Sees metadata (sender, recipient, timing, sizes) but never plaintext or
private keys. Plain HTTP+JSON, standard library only: every request is a
POST of {"tool": name, "args": {...}} and the response is the tool's JSON
result (HTTP 400 + {"error": ...} on failure). Put a TLS reverse proxy in
front for internet exposure.

Authentication: there are no accounts, tokens, or registration. Every tool
call carries an `auth` object self-signed with the user's ed25519 key; the
user ID is the fingerprint of the user's public keys, so each request
proves its own origin. Replay is blocked by a timestamp window plus a
nonce cache, and signatures are bound to this server's public URL so a
request captured here is worthless anywhere else. See docs/auth.md.

Env config:
  SERVER_DB        SQLite path (default server.db)
  SERVER_HOST      bind host (default 0.0.0.0)
  SERVER_PORT      bind port (default 8766)
  SERVER_AUDIENCE  the public URL users connect to, e.g.
                   https://server.example.com — REQUIRED for any
                   non-local deployment; signatures verify against it
                   (default http://127.0.0.1:<port>)
"""

import hashlib
import json
import os
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import vodozemac as v

DB_PATH = os.environ.get("SERVER_DB", "server.db")
HOST = os.environ.get("SERVER_HOST", "0.0.0.0")
PORT = int(os.environ.get("SERVER_PORT", "8766"))
AUDIENCE = os.environ.get("SERVER_AUDIENCE", f"http://127.0.0.1:{PORT}")
WINDOW = 150  # seconds of allowed clock skew, each direction

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
    id TEXT PRIMARY KEY,
    nickname TEXT,
    identity_key TEXT,
    signing_key TEXT,
    fallback_key_id TEXT,
    fallback_key TEXT
);
CREATE TABLE IF NOT EXISTS otks(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner TEXT,
    key_id TEXT,
    key TEXT,
    claimed INT DEFAULT 0
);
CREATE TABLE IF NOT EXISTS messages(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL,
    sender TEXT,
    recipient TEXT,
    mtype INT,
    body TEXT
);
CREATE TABLE IF NOT EXISTS cursors(
    user TEXT PRIMARY KEY,
    last_read_id INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS nonces(
    nonce TEXT PRIMARY KEY,
    ts REAL
);
"""


def _db() -> sqlite3.Connection:
    return sqlite3.connect(DB_PATH)


_schema_conn = _db()
_schema_conn.executescript(SCHEMA)
_schema_conn.close()


def _fingerprint(identity_key_b64: str, signing_key_b64: str) -> str:
    # must match user.fingerprint(); duplicated so the server stays standalone
    return hashlib.sha256(
        f"{identity_key_b64}|{signing_key_b64}".encode()).hexdigest()[:32]


def _caller(tool: str, args: dict, auth: dict) -> str:
    """Verify a self-certifying signed request; return the caller's user id.

    `args` must be rebuilt EXACTLY as the client serialized it (same keys,
    same values, None included) or the hash will not match. This is part of
    the wire spec — see docs/auth.md.
    """
    user_id = auth["user_id"]
    if _fingerprint(auth["identity_key"], auth["signing_key"]) != user_id:
        raise PermissionError("auth keys do not hash to user_id")
    if abs(time.time() - int(auth["ts"])) > WINDOW:
        raise PermissionError("stale or future timestamp (check the clock)")
    args_hash = hashlib.sha256(
        json.dumps(args, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    payload = (f"{tool}|{AUDIENCE}|{user_id}|{auth['ts']}|{auth['nonce']}|"
               f"{args_hash}").encode()
    try:
        v.Ed25519PublicKey.from_base64(auth["signing_key"]).verify_signature(
            payload, v.Ed25519Signature.from_base64(auth["sig"]))
    except Exception:
        raise PermissionError(
            "bad signature (wrong key, audience, or argument canonicalization)")
    conn = _db()
    try:
        with conn:
            conn.execute("DELETE FROM nonces WHERE ts<?", (time.time() - 2 * WINDOW,))
            try:
                conn.execute("INSERT INTO nonces(nonce, ts) VALUES(?,?)",
                             (auth["nonce"], time.time()))
            except sqlite3.IntegrityError:
                raise PermissionError("replay detected: nonce already used")
    finally:
        conn.close()
    return user_id


def publish_keys(identity_key: str, signing_key: str, one_time_keys: dict,
                 fallback_key: dict | None, nickname: str, auth: dict) -> str:
    """Set the caller's public keys, add one-time keys, and optionally
    replace the fallback key. Implicitly creates the user's mailbox."""
    user_id = _caller("publish_keys", {
        "identity_key": identity_key, "signing_key": signing_key,
        "one_time_keys": one_time_keys, "fallback_key": fallback_key,
        "nickname": nickname,
    }, auth)
    if _fingerprint(identity_key, signing_key) != user_id:
        raise ValueError("published keys do not match user id")
    conn = _db()
    try:
        with conn:
            conn.execute(
                "INSERT INTO users(id, nickname, identity_key, signing_key) "
                "VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
                "nickname=excluded.nickname, identity_key=excluded.identity_key, "
                "signing_key=excluded.signing_key",
                (user_id, nickname, identity_key, signing_key),
            )
            if fallback_key:
                fk_id, fk = next(iter(fallback_key.items()))
                conn.execute(
                    "UPDATE users SET fallback_key_id=?, fallback_key=? WHERE id=?",
                    (fk_id, fk, user_id),
                )
            conn.executemany(
                "INSERT INTO otks(owner, key_id, key, claimed) VALUES(?,?,?,0)",
                [(user_id, key_id, key) for key_id, key in one_time_keys.items()],
            )
        return json.dumps({"ok": True, "user_id": user_id,
                           "one_time_keys_added": len(one_time_keys),
                           "fallback_key_set": bool(fallback_key)})
    finally:
        conn.close()


def count_keys(auth: dict) -> str:
    """Return the caller's unclaimed one-time-key count and fallback-key
    status, so the caller can decide to replenish or rotate."""
    user_id = _caller("count_keys", {}, auth)
    conn = _db()
    try:
        n = conn.execute(
            "SELECT COUNT(*) FROM otks WHERE owner=? AND claimed=0", (user_id,)
        ).fetchone()[0]
        row = conn.execute(
            "SELECT fallback_key FROM users WHERE id=?", (user_id,)
        ).fetchone()
        return json.dumps({"unclaimed": n, "has_fallback": bool(row and row[0])})
    finally:
        conn.close()


def get_keys(peer: str, auth: dict) -> str:
    """Return a peer's public identity and signing keys and nickname
    (no one-time key consumed)."""
    _caller("get_keys", {"peer": peer}, auth)
    conn = _db()
    try:
        row = conn.execute(
            "SELECT identity_key, signing_key, nickname FROM users WHERE id=?",
            (peer,),
        ).fetchone()
        if row is None or row[0] is None:
            raise ValueError(f"unknown peer or no published keys: {peer}")
        return json.dumps({"identity_key": row[0], "signing_key": row[1],
                           "nickname": row[2]})
    finally:
        conn.close()


def claim_key(peer: str, auth: dict) -> str:
    """Atomically claim one unclaimed one-time key for a peer. If the peer's
    one-time keys are exhausted, serve their reusable fallback key instead
    (flagged with "fallback": true)."""
    _caller("claim_key", {"peer": peer}, auth)
    conn = _db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT identity_key, signing_key, fallback_key_id, fallback_key "
            "FROM users WHERE id=?", (peer,)
        ).fetchone()
        if row is None or row[0] is None:
            conn.execute("ROLLBACK")
            raise ValueError(f"unknown peer or no published keys: {peer}")
        otk = conn.execute(
            "SELECT id, key_id, key FROM otks WHERE owner=? AND claimed=0 "
            "ORDER BY id LIMIT 1", (peer,),
        ).fetchone()
        if otk is not None:
            conn.execute("UPDATE otks SET claimed=1 WHERE id=?", (otk[0],))
            conn.execute("COMMIT")
            return json.dumps({"identity_key": row[0], "signing_key": row[1],
                               "key_id": otk[1], "one_time_key": otk[2],
                               "fallback": False})
        conn.execute("ROLLBACK")
        if not row[3]:
            raise ValueError(
                f"no one-time keys left for peer: {peer} (and no fallback key)")
        return json.dumps({"identity_key": row[0], "signing_key": row[1],
                           "key_id": row[2], "one_time_key": row[3],
                           "fallback": True})
    finally:
        conn.close()


def send_message(to: str, mtype: int, body: str, auth: dict) -> str:
    """Store an opaque ciphertext message for a recipient (a user id)."""
    sender = _caller("send_message", {"to": to, "mtype": mtype, "body": body},
                     auth)
    conn = _db()
    try:
        ts = time.time()
        with conn:
            if not conn.execute("SELECT 1 FROM users WHERE id=?",
                                (to,)).fetchone():
                raise ValueError(f"unknown recipient: {to}")
            cur = conn.execute(
                "INSERT INTO messages(ts, sender, recipient, mtype, body) "
                "VALUES(?,?,?,?,?)", (ts, sender, to, mtype, body),
            )
        return json.dumps({"message_id": cur.lastrowid, "ts": ts})
    finally:
        conn.close()


def read_messages(auth: dict) -> str:
    """Return all unread messages for the caller and advance their cursor."""
    user_id = _caller("read_messages", {}, auth)
    conn = _db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        cur_row = conn.execute(
            "SELECT last_read_id FROM cursors WHERE user=?", (user_id,)
        ).fetchone()
        last_read = cur_row[0] if cur_row else 0
        rows = conn.execute(
            "SELECT m.id, m.ts, m.sender, a.nickname, m.mtype, m.body "
            "FROM messages m LEFT JOIN users a ON a.id = m.sender "
            "WHERE m.recipient=? AND m.id>? ORDER BY m.id",
            (user_id, last_read),
        ).fetchall()
        if rows:
            conn.execute(
                "INSERT INTO cursors(user, last_read_id) VALUES(?,?) "
                "ON CONFLICT(user) DO UPDATE SET last_read_id=excluded.last_read_id",
                (user_id, rows[-1][0]),
            )
        conn.execute("COMMIT")
        return json.dumps([
            {"message_id": r[0], "ts": r[1], "from": r[2], "nickname": r[3],
             "mtype": r[4], "body": r[5]}
            for r in rows
        ])
    finally:
        conn.close()


TOOLS = {fn.__name__: fn for fn in
         (publish_keys, count_keys, get_keys, claim_key,
          send_message, read_messages)}


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            length = int(self.headers.get("content-length", 0))
            req = json.loads(self.rfile.read(length))
            result = TOOLS[req["tool"]](**req.get("args", {}))
            self._reply(200, result.encode())
        except Exception as e:
            self._reply(400, json.dumps({"error": str(e)}).encode())

    def _reply(self, status: int, body: bytes):
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # no request logging (metadata hygiene)


def main():
    ThreadingHTTPServer((HOST, PORT), _Handler).serve_forever()


if __name__ == "__main__":
    main()
