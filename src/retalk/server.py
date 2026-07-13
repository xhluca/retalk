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

Config (a CLI flag overrides the matching env var):
  --host        / RETALK_SERVER_HOST       interface to bind (default 0.0.0.0)
  --port        / RETALK_SERVER_PORT       port to bind (default 8766)
  --audience    / RETALK_SERVER_AUDIENCE   public URL users connect to, e.g.
                https://server.example.com — REQUIRED for any non-local
                deployment; signatures verify against it (defaults to the bind
                host:port, showing 0.0.0.0 as 127.0.0.1)
  --db          / RETALK_SERVER_DB         SQLite path (default server.db)
  --max-body    / RETALK_SERVER_MAX_BODY   max request body in bytes; larger
                requests are rejected with HTTP 413 (default 1048576 = 1 MiB)
  --rate-limit  / RETALK_SERVER_RATE_LIMIT max requests per caller fingerprint
                per minute; over the cap returns HTTP 429 (default 0 = off)
  --timeout     / RETALK_SERVER_TIMEOUT    per-connection socket timeout in
                seconds, to drop slow/idle clients (default 30)
  --max-mailbox / RETALK_SERVER_MAX_MAILBOX  max undelivered messages per
                recipient (default 0 = unlimited). A per-sender sub-cap keeps
                one sender from filling a mailbox; see --max-mailbox-per-sender.
  --max-mailbox-per-sender / RETALK_SERVER_MAX_MAILBOX_PER_SENDER  max
                undelivered messages a single sender may hold in one recipient's
                mailbox (default 0 = unlimited; ignored when the overall cap is
                unlimited)
  --admin-password / RETALK_SERVER_ADMIN_PASSWORD  password for the /admin
                endpoint (HTTP Basic) that mints API keys; unset disables
                /admin (404)
  --require-api-key / RETALK_SERVER_REQUIRE_API_KEY  require a valid API key
                (Authorization: Bearer <key>) on every tool request, else 401
                (default off)
  --max-refused / RETALK_SERVER_MAX_REFUSED  max negative-acks (refused message
                hashes) kept per recipient before the oldest are evicted; bounds
                the `refused` table (default 1000, 0 = unlimited)
  --refused-ttl / RETALK_SERVER_REFUSED_TTL  seconds a negative-ack lives before
                it expires and is pruned, so the `refused` table shrinks over
                time (default 604800 = 7 days, 0 = no expiry)

A "mailbox full" rejection is safe for delivery: the sender keeps
unacknowledged messages in its local outbox and resends them later, so
at-least-once delivery survives the rejection (see docs/server.md).

API keys gate *use of the relay* (admission), never identity: with
--require-api-key, tool requests must carry one, but a leaked key only lets
someone use the relay (the open-relay default) — it can't impersonate a user
or read mail, which stay protected by the per-request signatures and E2E
encryption. See docs/auth.md and docs/server.md.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import sqlite3
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import vodozemac as v

DB_PATH = os.environ.get("RETALK_SERVER_DB", "server.db")
HOST = os.environ.get("RETALK_SERVER_HOST", "0.0.0.0")
PORT = int(os.environ.get("RETALK_SERVER_PORT", "8766"))
AUDIENCE = os.environ.get("RETALK_SERVER_AUDIENCE", f"http://127.0.0.1:{PORT}")
# Abuse-hardening (all backward compatible; defaults must not break clients):
#   MAX_BODY   request body cap in bytes (oversized -> HTTP 413)
#   RATE_LIMIT requests per caller fingerprint per minute (0 = disabled)
#   TIMEOUT    per-connection socket timeout in seconds (slowloris defence)
MAX_BODY = int(os.environ.get("RETALK_SERVER_MAX_BODY", str(1024 * 1024)))
RATE_LIMIT = int(os.environ.get("RETALK_SERVER_RATE_LIMIT", "0"))
TIMEOUT = float(os.environ.get("RETALK_SERVER_TIMEOUT", "30"))
WINDOW = 150  # seconds of allowed clock skew, each direction
# Per-recipient mailbox cap on undelivered messages; 0 = unlimited.
MAX_MAILBOX = int(os.environ.get("RETALK_SERVER_MAX_MAILBOX", "0"))
# Per-(sender, recipient) sub-cap so one sender can't crowd out others; 0 =
# unlimited (and only meaningful when MAX_MAILBOX is set).
MAX_MAILBOX_PER_SENDER = int(
    os.environ.get("RETALK_SERVER_MAX_MAILBOX_PER_SENDER", "0"))
RATE_WINDOW = 60  # seconds; the rate limit is "requests per this window"
# Per-recipient cap on stored negative-acks (refused message hashes). A
# recipient can record arbitrary hashes, so this is bounded by oldest-eviction
# to stop the table growing without limit; 0 = unlimited (not recommended).
MAX_REFUSED = int(os.environ.get("RETALK_SERVER_MAX_REFUSED", "1000"))
# Advisory policy for clients: the largest group roster this relay wants
# fanned out through it. The relay never SEES groups (they live inside the
# encrypted envelopes) -- clients fetch this from GET /info and enforce it
# locally at group create/add/adopt time.
MAX_GROUP_SIZE = int(os.environ.get("RETALK_SERVER_MAX_GROUP_SIZE", "100"))
# Time-to-live (seconds) for negative-acks: an expired one stops blocking and is
# pruned, so the refused table shrinks over time, not only at the cap. A sender
# that resends after expiry just gets re-dropped and re-nacked. 0 = no expiry.
REFUSED_TTL = float(os.environ.get("RETALK_SERVER_REFUSED_TTL", str(7 * 24 * 3600)))
# Optional relay access control (admission, NOT identity — see docs/auth.md):
#   ADMIN_PASSWORD   unlocks the /admin API-key endpoint (HTTP Basic); empty
#                    string disables /admin entirely (404).
#   REQUIRE_API_KEY  when true, every tool request must carry a valid API key.
ADMIN_PASSWORD = os.environ.get("RETALK_SERVER_ADMIN_PASSWORD", "")
REQUIRE_API_KEY = os.environ.get(
    "RETALK_SERVER_REQUIRE_API_KEY", "").lower() in ("1", "true", "yes", "on")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
    id TEXT PRIMARY KEY,
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
CREATE TABLE IF NOT EXISTS nonces(
    nonce TEXT PRIMARY KEY,
    ts REAL
);
CREATE TABLE IF NOT EXISTS api_keys(
    key_hash TEXT PRIMARY KEY,
    label TEXT,
    created REAL,
    disabled INT DEFAULT 0
);
CREATE TABLE IF NOT EXISTS refused(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient TEXT,
    hash TEXT,
    sig TEXT,
    ts REAL,
    UNIQUE(recipient, hash)
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
    user_id = auth["fingerprint"]
    if _fingerprint(auth["identity_key"], auth["signing_key"]) != user_id:
        raise PermissionError("auth keys do not hash to user_id")
    if abs(time.time() - int(auth["timestamp"])) > WINDOW:
        raise PermissionError("stale or future timestamp (check the clock)")
    args_hash = hashlib.sha256(
        json.dumps(args, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    payload = (f"{tool}|{AUDIENCE}|{user_id}|{auth['timestamp']}|{auth['nonce']}|"
               f"{args_hash}").encode()
    try:
        v.Ed25519PublicKey.from_base64(auth["signing_key"]).verify_signature(
            payload, v.Ed25519Signature.from_base64(auth["signature"]))
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
                 fallback_key: dict | None, auth: dict) -> str:
    """Set the caller's public keys, add one-time keys, and optionally
    replace the fallback key. Implicitly creates the user's mailbox."""
    user_id = _caller("publish_keys", {
        "identity_key": identity_key, "signing_key": signing_key,
        "one_time_keys": one_time_keys, "fallback_key": fallback_key,
    }, auth)
    if _fingerprint(identity_key, signing_key) != user_id:
        raise ValueError("published keys do not match user id")
    conn = _db()
    try:
        with conn:
            conn.execute(
                "INSERT INTO users(id, identity_key, signing_key) "
                "VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET "
                "identity_key=excluded.identity_key, "
                "signing_key=excluded.signing_key",
                (user_id, identity_key, signing_key),
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
        return json.dumps({"ok": True, "fingerprint": user_id,
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
    """Return a peer's public identity and signing keys and name
    (no one-time key consumed)."""
    _caller("get_keys", {"peer": peer}, auth)
    conn = _db()
    try:
        row = conn.execute(
            "SELECT identity_key, signing_key FROM users WHERE id=?",
            (peer,),
        ).fetchone()
        if row is None or row[0] is None:
            raise ValueError(f"unknown peer or no published keys: {peer}")
        return json.dumps({"identity_key": row[0], "signing_key": row[1]})
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
            # Negative-ack gate: if the recipient previously refused this exact
            # ciphertext (see `nack`), do not store it again. Return the
            # recipient's signed refusal so the sender can verify it (the relay
            # cannot forge one) and delete the message from its outbox, which
            # stops resends even from a sender that never calls receive.
            h = hashlib.sha256(body.encode()).hexdigest()
            cutoff = ts - REFUSED_TTL if REFUSED_TTL else -1.0
            ref = conn.execute(
                "SELECT sig FROM refused WHERE recipient=? AND hash=? AND ts>?",
                (to, h, cutoff)).fetchone()
            if ref:
                return json.dumps({"refused": True, "hash": h, "sig": ref[0]})
            # Reject-not-evict mailbox cap: count undelivered mail BEFORE
            # inserting and refuse if the recipient is at/over a limit, never
            # dropping existing mail. The sender keeps the message in its local
            # outbox and resends later, so at-least-once delivery survives the
            # rejection. Default 0 = unlimited (caps off).
            if MAX_MAILBOX:
                total = conn.execute(
                    "SELECT COUNT(*) FROM messages WHERE recipient=?",
                    (to,)).fetchone()[0]
                if total >= MAX_MAILBOX:
                    raise ValueError(
                        f"mailbox full: {to} has {total} undelivered messages "
                        f"(cap {MAX_MAILBOX}); resend later from your outbox")
                if MAX_MAILBOX_PER_SENDER:
                    from_sender = conn.execute(
                        "SELECT COUNT(*) FROM messages "
                        "WHERE recipient=? AND sender=?",
                        (to, sender)).fetchone()[0]
                    if from_sender >= MAX_MAILBOX_PER_SENDER:
                        raise ValueError(
                            f"mailbox full for sender: {sender} already has "
                            f"{from_sender} undelivered messages for {to} "
                            f"(per-sender cap {MAX_MAILBOX_PER_SENDER}); "
                            f"resend later from your outbox")
            cur = conn.execute(
                "INSERT INTO messages(ts, sender, recipient, mtype, body) "
                "VALUES(?,?,?,?,?)", (ts, sender, to, mtype, body),
            )
        return json.dumps({"message_id": cur.lastrowid, "ts": ts})
    finally:
        conn.close()


def read_messages(auth: dict, peer: str | None = None) -> str:
    """Hand over and delete pending messages for the caller. Delivered mail
    leaves the server entirely (content and metadata).

    With `peer` set, only messages from that sender are returned and deleted;
    everyone else's mail stays in the mailbox. Without it, the whole mailbox
    is drained."""
    user_id = _caller("read_messages", {"peer": peer} if peer else {}, auth)
    conn = _db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        if peer:
            rows = conn.execute(
                "SELECT id, ts, sender, mtype, body FROM messages "
                "WHERE recipient=? AND sender=? ORDER BY id",
                (user_id, peer),
            ).fetchall()
            if rows:
                conn.execute(
                    "DELETE FROM messages "
                    "WHERE recipient=? AND sender=? AND id<=?",
                    (user_id, peer, rows[-1][0]))
        else:
            rows = conn.execute(
                "SELECT id, ts, sender, mtype, body FROM messages "
                "WHERE recipient=? ORDER BY id",
                (user_id,),
            ).fetchall()
            if rows:
                conn.execute("DELETE FROM messages WHERE recipient=? AND id<=?",
                             (user_id, rows[-1][0]))
        conn.execute("COMMIT")
        return json.dumps([
            {"message_id": r[0], "ts": r[1], "from": r[2],
             "mtype": r[3], "body": r[4]}
            for r in rows
        ])
    finally:
        conn.close()


def nack(hash: str, sig: str, auth: dict) -> str:
    """Record that the caller refuses any future message whose ciphertext
    hashes to `hash` (a signed negative ack). `sig` is the caller's signature
    over 'nack|<caller>|<hash>'; it is stored and later handed to the sender as
    proof of refusal, so the relay can reject the refused message's resends
    without being able to forge a refusal itself.

    Bounded two ways, since a caller may record arbitrary hashes: by age
    (REFUSED_TTL, expired entries pruned) and by count per recipient
    (MAX_REFUSED, oldest evicted)."""
    me = _caller("nack", {"hash": hash, "sig": sig}, auth)
    if not (isinstance(hash, str) and len(hash) == 64
            and all(c in "0123456789abcdef" for c in hash)):
        raise ValueError("hash must be a 64-char sha256 hex digest")
    try:  # verify the proof so we never store/relay a bogus one
        v.Ed25519PublicKey.from_base64(auth["signing_key"]).verify_signature(
            f"nack|{me}|{hash}".encode(), v.Ed25519Signature.from_base64(sig))
    except Exception:
        raise PermissionError("bad nack signature")
    conn = _db()
    try:
        now = time.time()
        with conn:
            if REFUSED_TTL:  # age out expired refusals server-wide
                conn.execute("DELETE FROM refused WHERE ts<?",
                             (now - REFUSED_TTL,))
            # re-nacking the same ciphertext refreshes its timestamp (and sig)
            conn.execute(
                "INSERT INTO refused(recipient, hash, sig, ts) VALUES(?,?,?,?) "
                "ON CONFLICT(recipient, hash) DO UPDATE SET "
                "sig=excluded.sig, ts=excluded.ts", (me, hash, sig, now))
            if MAX_REFUSED:
                n = conn.execute("SELECT COUNT(*) FROM refused WHERE recipient=?",
                                 (me,)).fetchone()[0]
                if n > MAX_REFUSED:
                    conn.execute(
                        "DELETE FROM refused WHERE id IN (SELECT id FROM refused "
                        "WHERE recipient=? ORDER BY id LIMIT ?)",
                        (me, n - MAX_REFUSED))
        return json.dumps({"ok": True})
    finally:
        conn.close()


TOOLS = {fn.__name__: fn for fn in
         (publish_keys, count_keys, get_keys, claim_key,
          send_message, read_messages, nack)}


# ---------- relay access control: API keys (admission only, not identity) ----

def _hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _api_key_valid(raw: str | None) -> bool:
    """True if `raw` matches a stored, non-disabled API key. Keys are stored
    as hashes only, so a leaked database yields no usable keys."""
    if not raw:
        return False
    conn = _db()
    try:
        return conn.execute(
            "SELECT 1 FROM api_keys WHERE key_hash=? AND disabled=0",
            (_hash_key(raw),)).fetchone() is not None
    finally:
        conn.close()


def _api_key_create(label: str) -> dict:
    """Mint a key; return the raw value ONCE (only its hash is persisted)."""
    raw = secrets.token_urlsafe(32)
    kh = _hash_key(raw)
    conn = _db()
    try:
        with conn:
            conn.execute(
                "INSERT INTO api_keys(key_hash, label, created, disabled) "
                "VALUES(?,?,?,0)", (kh, label, time.time()))
    finally:
        conn.close()
    return {"key": raw, "key_hash": kh, "label": label}


def _api_key_list() -> list:
    conn = _db()
    try:
        rows = conn.execute(
            "SELECT key_hash, label, created, disabled FROM api_keys "
            "ORDER BY created").fetchall()
        return [{"key_hash": r[0], "label": r[1], "created": r[2],
                 "disabled": bool(r[3])} for r in rows]
    finally:
        conn.close()


def _api_key_set_disabled(key_hash: str, disabled: bool) -> int:
    conn = _db()
    try:
        with conn:
            cur = conn.execute(
                "UPDATE api_keys SET disabled=? WHERE key_hash=?",
                (1 if disabled else 0, key_hash))
        return cur.rowcount
    finally:
        conn.close()


def _api_key_delete(key_hash: str) -> int:
    conn = _db()
    try:
        with conn:
            cur = conn.execute("DELETE FROM api_keys WHERE key_hash=?",
                               (key_hash,))
        return cur.rowcount
    finally:
        conn.close()


def _admin_page() -> str:
    rows = "".join(
        f"<tr><td><code>{html.escape(k['key_hash'])}</code></td>"
        f"<td>{html.escape(k['label'] or '')}</td>"
        f"<td>{'disabled' if k['disabled'] else 'active'}</td></tr>"
        for k in _api_key_list())
    return (
        "<!doctype html><meta charset=utf-8><title>retalk admin</title>"
        "<h1>retalk relay &mdash; API keys</h1>"
        "<p>API keys gate <em>use of this relay</em> only. They are stored "
        "hashed and the raw key is shown just once, at creation.</p>"
        "<table border=1 cellpadding=6><tr><th>key_hash</th><th>label</th>"
        f"<th>status</th></tr>{rows or '<tr><td colspan=3>(no keys yet)</td></tr>'}"
        "</table>"
        "<h2>Manage (all over HTTP; Basic-auth with the admin password)</h2>"
        "<pre>"
        "# create a key (the response contains the raw key ONCE)\n"
        "curl -u admin:PW -X POST URL/admin -d '{\"action\":\"create\",\"label\":\"alice\"}'\n"
        "# list keys (hashes only, never raw)\n"
        "curl -u admin:PW -X POST URL/admin -d '{\"action\":\"list\"}'\n"
        "# disable / enable / delete by key_hash\n"
        "curl -u admin:PW -X POST URL/admin -d '{\"action\":\"disable\",\"key_hash\":\"...\"}'\n"
        "curl -u admin:PW -X POST URL/admin -d '{\"action\":\"delete\",\"key_hash\":\"...\"}'\n"
        "</pre>")


class _RateLimiter:
    """Thread-safe sliding-window request counter keyed by caller fingerprint.

    The server is multithreaded, so all access is guarded by a lock. Each
    fingerprint keeps a deque of recent request timestamps; entries older than
    the window are pruned on every check, and fingerprints whose deque empties
    are dropped so the table cannot grow without bound."""

    def __init__(self, limit: int, window: float = RATE_WINDOW):
        self.limit = limit
        self.window = window
        self._hits: dict[str, deque] = {}
        self._lock = threading.Lock()

    def allow(self, fingerprint: str, now: float | None = None) -> bool:
        """Record a request from `fingerprint`; return False if it is over the
        cap. Disabled (limit <= 0) always allows."""
        if self.limit <= 0:
            return True
        now = time.time() if now is None else now
        cutoff = now - self.window
        with self._lock:
            # prune fully-expired fingerprints so the table stays bounded
            for fp in [fp for fp, dq in self._hits.items()
                       if not dq or dq[-1] <= cutoff]:
                del self._hits[fp]
            dq = self._hits.get(fingerprint)
            if dq is None:
                dq = self._hits[fingerprint] = deque()
            while dq and dq[0] <= cutoff:
                dq.popleft()
            if len(dq) >= self.limit:
                return False
            dq.append(now)
            return True


_RATE_LIMITER = _RateLimiter(RATE_LIMIT)


class _Handler(BaseHTTPRequestHandler):
    # dropped if a client is too slow/idle (slowloris defence)
    timeout = TIMEOUT

    def _is_admin(self) -> bool:
        # match the "/admin" path suffix so it also works behind a path prefix
        return urlsplit(self.path).path.rstrip("/").rsplit("/", 1)[-1] == "admin"

    def do_GET(self):
        # public, unauthenticated policy info (no secrets: just server limits)
        if urlsplit(self.path).path.rstrip("/").rsplit("/", 1)[-1] == "info":
            self._reply(200, json.dumps(
                {"max_group_size": MAX_GROUP_SIZE}).encode())
            return
        if not self._is_admin():
            self._reply(404, json.dumps({"error": "not found"}).encode())
            return
        if not self._require_admin():
            return
        self._reply(200, _admin_page().encode(), "text/html; charset=utf-8")

    def do_POST(self):
        if self._is_admin():
            self._admin_post()
            return
        try:
            length = int(self.headers.get("content-length", 0))
            if length > MAX_BODY:
                # do not read the oversized body; reject outright
                self._reply(413, json.dumps(
                    {"error": f"request body too large: {length} bytes "
                              f"(max {MAX_BODY})"}).encode())
                return
            # API-key admission gate (cheap reject, before reading the body or
            # verifying any signature). Off by default; see REQUIRE_API_KEY.
            if REQUIRE_API_KEY and not _api_key_valid(self._bearer_key()):
                self._reply(401, json.dumps(
                    {"error": "valid API key required to use this relay"}
                ).encode())
                return
            req = json.loads(self.rfile.read(length))
            fp = (req.get("args", {}).get("auth") or {}).get("fingerprint")
            if fp and not _RATE_LIMITER.allow(fp):
                self._reply(429, json.dumps(
                    {"error": "rate limit exceeded; slow down and retry"}
                ).encode())
                return
            result = TOOLS[req["tool"]](**req.get("args", {}))
            self._reply(200, result.encode())
        except Exception as e:
            self._reply(400, json.dumps({"error": str(e)}).encode())

    # ----- admin endpoint (API-key management over HTTP) -----
    def _bearer_key(self) -> str | None:
        hdr = self.headers.get("authorization", "")
        if hdr.startswith("Bearer "):
            return hdr[7:].strip()
        return self.headers.get("x-retalk-key")

    def _require_admin(self) -> bool:
        """True if /admin is enabled and the Basic-auth password matches.
        Otherwise replies 404 (disabled) or 401 (bad creds) and returns
        False. The password is never stored or logged."""
        if not ADMIN_PASSWORD:
            self._reply(404, json.dumps({"error": "not found"}).encode())
            return False
        hdr = self.headers.get("authorization", "")
        ok = False
        if hdr.startswith("Basic "):
            try:
                _, _, pw = base64.b64decode(hdr[6:]).decode().partition(":")
                ok = hmac.compare_digest(pw, ADMIN_PASSWORD)
            except Exception:
                ok = False
        if not ok:
            body = json.dumps({"error": "admin auth required"}).encode()
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="retalk admin"')
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return False
        return True

    def _admin_post(self):
        if not self._require_admin():
            return
        try:
            length = int(self.headers.get("content-length", 0))
            if length > MAX_BODY:
                self._reply(413, json.dumps(
                    {"error": "request body too large"}).encode())
                return
            req = json.loads(self.rfile.read(length)) if length else {}
            action = req.get("action")
            if action == "create":
                out = _api_key_create(req.get("label", ""))
            elif action == "list":
                out = {"keys": _api_key_list()}
            elif action in ("disable", "enable"):
                out = {"updated": _api_key_set_disabled(
                    req["key_hash"], action == "disable")}
            elif action == "delete":
                out = {"deleted": _api_key_delete(req["key_hash"])}
            else:
                raise ValueError(
                    f"unknown admin action: {action!r} "
                    "(create|list|disable|enable|delete)")
            self._reply(200, json.dumps(out).encode())
        except Exception as e:
            self._reply(400, json.dumps({"error": str(e)}).encode())

    def _reply(self, status: int, body: bytes,
               content_type: str = "application/json"):
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # no request logging (metadata hygiene)


def main():
    global DB_PATH, HOST, PORT, AUDIENCE
    global MAX_MAILBOX, MAX_MAILBOX_PER_SENDER, MAX_BODY, RATE_LIMIT, TIMEOUT
    global ADMIN_PASSWORD, REQUIRE_API_KEY, MAX_REFUSED, REFUSED_TTL
    global MAX_GROUP_SIZE
    global _RATE_LIMITER
    import argparse
    ap = argparse.ArgumentParser(
        prog="retalk-server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Untrusted relay for retalk: stores only public keys and "
                    "ciphertext and forwards sealed messages between mailboxes. "
                    "It never sees plaintext or private keys.",
        epilog="--host/--port vs --audience differ on purpose:\n"
               "  --host/--port  where THIS process listens (the socket it\n"
               "                 binds locally)\n"
               "  --audience     the public URL clients connect to; request\n"
               "                 signatures are bound to it, so it must equal\n"
               "                 each client's --relay URL exactly.\n"
               "Locally they coincide. Behind a TLS proxy, --host/--port stay\n"
               "local (e.g. 127.0.0.1:8766) while --audience is your public\n"
               "https:// address. Each flag overrides the matching RETALK_*\n"
               "env var (RETALK_SERVER_HOST, RETALK_SERVER_PORT, RETALK_SERVER_AUDIENCE, RETALK_SERVER_DB,\n"
               "RETALK_SERVER_MAX_BODY, RETALK_SERVER_RATE_LIMIT, RETALK_SERVER_TIMEOUT,\n"
               "RETALK_SERVER_MAX_MAILBOX, RETALK_SERVER_MAX_MAILBOX_PER_SENDER,\n"
               "RETALK_SERVER_ADMIN_PASSWORD, RETALK_SERVER_REQUIRE_API_KEY,\n"
               "RETALK_SERVER_MAX_REFUSED, RETALK_SERVER_REFUSED_TTL).")
    ap.add_argument("--host", metavar="HOST",
                    help="interface to bind: 0.0.0.0 for every interface or "
                         "127.0.0.1 for this machine only (overrides "
                         "RETALK_SERVER_HOST; default 0.0.0.0)")
    ap.add_argument("--port", metavar="PORT", type=int,
                    help="TCP port to bind (overrides RETALK_SERVER_PORT; default "
                         "8766)")
    ap.add_argument("--audience", metavar="URL",
                    help="public URL users connect to; request signatures are "
                         "bound to it, so it must match each client's --relay "
                         "URL exactly (overrides RETALK_SERVER_AUDIENCE; defaults to "
                         "http://HOST:PORT, showing 0.0.0.0 as 127.0.0.1)")
    ap.add_argument("--db", metavar="PATH",
                    help="SQLite database path (overrides RETALK_SERVER_DB; default "
                         "server.db)")
    ap.add_argument("--max-mailbox", metavar="N", type=int,
                    help="max undelivered messages per recipient; a full "
                         "mailbox rejects further sends (reject-not-evict) so "
                         "the sender resends later from its outbox (overrides "
                         "RETALK_SERVER_MAX_MAILBOX; default 0 = unlimited)")
    ap.add_argument("--max-mailbox-per-sender", metavar="N", type=int,
                    help="max undelivered messages a single sender may hold in "
                         "one recipient's mailbox, so one sender can't crowd "
                         "out others; only applies when --max-mailbox is set "
                         "(overrides RETALK_SERVER_MAX_MAILBOX_PER_SENDER; "
                         "default 0 = unlimited)")
    ap.add_argument("--max-body", metavar="BYTES", type=int,
                    help="reject request bodies larger than this many bytes "
                         "with HTTP 413 (overrides RETALK_SERVER_MAX_BODY; "
                         "default 1048576 = 1 MiB)")
    ap.add_argument("--rate-limit", metavar="N", type=int,
                    help="max requests per caller fingerprint per minute "
                         "before HTTP 429; 0 disables (overrides "
                         "RETALK_SERVER_RATE_LIMIT; default 0)")
    ap.add_argument("--timeout", metavar="SECONDS", type=float,
                    help="per-connection socket timeout to drop slow/idle "
                         "clients (overrides RETALK_SERVER_TIMEOUT; default 30)")
    ap.add_argument("--admin-password", metavar="PW",
                    help="password for the /admin API-key endpoint (HTTP "
                         "Basic); unset disables /admin (overrides "
                         "RETALK_SERVER_ADMIN_PASSWORD)")
    ap.add_argument("--require-api-key", action="store_true", default=False,
                    help="require a valid API key (Authorization: Bearer "
                         "<key>) on every tool request; mint keys at /admin "
                         "(also via RETALK_SERVER_REQUIRE_API_KEY)")
    ap.add_argument("--max-refused", metavar="N", type=int,
                    help="max negative-acks (refused message hashes) kept per "
                         "recipient before the oldest are evicted; bounds the "
                         "refused table (overrides RETALK_SERVER_MAX_REFUSED; "
                         "default 1000, 0 = unlimited)")
    ap.add_argument("--refused-ttl", metavar="SECONDS", type=float,
                    help="seconds a negative-ack lives before it expires and is "
                         "pruned, so the refused table shrinks over time "
                         "(overrides RETALK_SERVER_REFUSED_TTL; default 604800 "
                         "= 7 days, 0 = no expiry)")
    ap.add_argument("--max-group-size", metavar="N", type=int,
                    help="advisory cap on group roster size, served at GET "
                         "/info and enforced by clients at group create/add "
                         "(overrides RETALK_SERVER_MAX_GROUP_SIZE; default 100)")
    args = ap.parse_args()

    if args.db:
        DB_PATH = args.db
    if args.max_mailbox is not None:
        MAX_MAILBOX = args.max_mailbox
    if args.max_mailbox_per_sender is not None:
        MAX_MAILBOX_PER_SENDER = args.max_mailbox_per_sender
    if args.max_group_size is not None:
        MAX_GROUP_SIZE = args.max_group_size
    if args.host:
        HOST = args.host
    if args.port:
        PORT = args.port
    if args.audience:
        AUDIENCE = args.audience
    elif not os.environ.get("RETALK_SERVER_AUDIENCE"):
        host = "127.0.0.1" if HOST == "0.0.0.0" else HOST
        AUDIENCE = f"http://{host}:{PORT}"
    if args.max_body is not None:
        MAX_BODY = args.max_body
    if args.rate_limit is not None:
        RATE_LIMIT = args.rate_limit
    if args.timeout is not None:
        TIMEOUT = args.timeout
    if args.admin_password is not None:
        ADMIN_PASSWORD = args.admin_password
    if args.require_api_key:
        REQUIRE_API_KEY = True
    if args.max_refused is not None:
        MAX_REFUSED = args.max_refused
    if args.refused_ttl is not None:
        REFUSED_TTL = args.refused_ttl

    _RATE_LIMITER = _RateLimiter(RATE_LIMIT)
    _Handler.timeout = TIMEOUT
    ThreadingHTTPServer((HOST, PORT), _Handler).serve_forever()


if __name__ == "__main__":
    main()
