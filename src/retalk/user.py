"""Client-side E2EE user for the retalk message bus.

A "user" is anything with a keypair and a mailbox — an AI agent, a human at
a terminal, a service. The human or organization who runs one or more users
is their "owner" (the protocol itself does not model owners).

All encryption/decryption happens here with vodozemac (Olm). The server (a message server: it only stores and forwards sealed envelopes) is
untrusted: it only ever receives public keys and ciphertext.

Identity and auth are one mechanism: a user's ID is the fingerprint
(sha256 hex, 32 chars) of its public keys, and every server call is signed
with the user's ed25519 key — no tokens, no registration, no credential
at rest. An ID shared out-of-band is simultaneously address and pin: any
keys the server serves for an ID must hash to that ID or the client
refuses. IDs are server-independent, so sessions survive a server
migration. See docs/auth.md.

Private keys are persisted locally in SQLite, encrypted at rest with a key
derived from `passphrase`. The process is stateless: account and session
state live only on disk, loaded per operation and written back immediately.
A per-store file lock serializes operations, so multiple processes may
safely share one store.
"""

import base64
import fcntl
import hashlib
import json
import secrets
import sqlite3
import time
import urllib.error
import urllib.request
import uuid
from contextlib import contextmanager

import vodozemac as v


def fingerprint(identity_key_b64: str, signing_key_b64: str) -> str:
    """User ID: sha256 fingerprint (hex, 128 bits) of both public keys."""
    return hashlib.sha256(
        f"{identity_key_b64}|{signing_key_b64}".encode()).hexdigest()[:32]


def canonical_hash(args: dict) -> str:
    """Hash of the canonical JSON encoding of a tool's arguments. Part of
    the signed-request wire spec — the server rebuilds this byte-for-byte."""
    return hashlib.sha256(
        json.dumps(args, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class PinMismatchError(Exception):
    pass


class User:
    def __init__(self, server_url: str, passphrase: str, name: str = "",
                 store: str = "user.db", identity_keys: dict | None = None,
                 names: dict | None = None, blocked: set | None = None,
                 receive_policy: str = "open", known: set | None = None,
                 api_key: str | None = None):
        self.server_url = server_url
        self.name = name
        # optional relay access key (admission only) sent as a Bearer header;
        # it gates use of the relay, never identity (signatures do that)
        self.api_key = api_key
        # {peer_id: full identity key} to pin, on top of the fingerprint ID
        self.identity_keys = identity_keys or {}
        # local peer names {peer_id: name}; server-supplied names are
        # attacker-chosen text and are only ever shown marked with "~"
        self.names = names or {}
        # fingerprints whose mail is silently dropped before any crypto work
        self.blocked = set(blocked) if blocked else set()
        # "open" accepts anyone; "peers-only" accepts only known peers
        self.receive_policy = receive_policy
        # known-peer fingerprints; defaults to the union of pins and names so
        # the caller can pass either source (or an explicit `known` set)
        self.known = set(known) if known is not None else (
            set(self.identity_keys) | set(self.names))
        self._store_key = hashlib.sha256(passphrase.encode()).digest()
        self._store_path = store
        self._init_store()
        self._load_account()  # create the account on first run; fail early on a wrong passphrase

    # ---------- local encrypted store ----------

    @contextmanager
    def _locked(self):
        """Serialize a whole operation across processes sharing this store."""
        with open(self._store_path + ".lock", "w") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            yield

    def _init_store(self):
        self._exec("CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT)")
        self._exec("CREATE TABLE IF NOT EXISTS sessions(peer TEXT PRIMARY KEY, blob TEXT)")
        # sent-but-unacknowledged ciphertext, for re-delivery (server loss/migration)
        self._exec("CREATE TABLE IF NOT EXISTS outbox("
                   "id TEXT PRIMARY KEY, peer TEXT, mtype INT, body TEXT, ts REAL)")
        # hash of every processed ciphertext -> its message id, to re-ack duplicates
        self._exec("CREATE TABLE IF NOT EXISTS processed(hash TEXT PRIMARY KEY, msg_id TEXT)")

    def _fetchone(self, sql: str, *params) -> str | None:
        conn = sqlite3.connect(self._store_path)
        try:
            row = conn.execute(sql, params).fetchone()
        finally:
            conn.close()
        return row[0] if row else None

    def _fetchall(self, sql: str, *params) -> list:
        conn = sqlite3.connect(self._store_path)
        try:
            return conn.execute(sql, params).fetchall()
        finally:
            conn.close()

    def _exec(self, sql: str, *params):
        conn = sqlite3.connect(self._store_path)
        try:
            with conn:
                conn.execute(sql, params)
        finally:
            conn.close()

    def _meta_get(self, k: str) -> str | None:
        return self._fetchone("SELECT v FROM meta WHERE k=?", k)

    def _meta_set(self, k: str, val: str):
        self._exec("INSERT INTO meta(k, v) VALUES(?,?) "
                   "ON CONFLICT(k) DO UPDATE SET v=excluded.v", k, val)

    def _load_account(self) -> v.Account:
        blob = self._meta_get("account")
        if blob:
            return v.Account.from_pickle(blob, self._store_key)
        acct = v.Account()
        self._save_account(acct)
        return acct

    def _save_account(self, acct: v.Account):
        self._meta_set("account", acct.pickle(self._store_key))

    def _load_session(self, peer: str) -> v.Session | None:
        blob = self._fetchone("SELECT blob FROM sessions WHERE peer=?", peer)
        return v.Session.from_pickle(blob, self._store_key) if blob else None

    def _save_session(self, peer: str, session: v.Session):
        self._exec("INSERT INTO sessions(peer, blob) VALUES(?,?) "
                   "ON CONFLICT(peer) DO UPDATE SET blob=excluded.blob",
                   peer, session.pickle(self._store_key))

    # ---------- signed server RPC ----------

    def _auth_fields(self, tool: str, args: dict) -> dict:
        """Build the self-certifying auth object for one request."""
        acct = self._load_account()
        ident = acct.curve25519_key.to_base64()
        signk = acct.ed25519_key.to_base64()
        aid = fingerprint(ident, signk)
        ts = str(int(time.time()))
        nonce = secrets.token_hex(16)
        payload = (f"{tool}|{self.server_url}|{aid}|{ts}|{nonce}|"
                   f"{canonical_hash(args)}").encode()
        sig = acct.sign(payload)
        return {"fingerprint": aid, "identity_key": ident, "signing_key": signk,
                "timestamp": ts, "nonce": nonce, "signature": sig.to_base64()}

    def _call(self, tool: str, args: dict | None = None):
        args = args or {}
        wire = dict(args)
        wire["auth"] = self._auth_fields(tool, args)
        return self._call_raw(tool, wire)

    def _call_raw(self, tool: str, wire: dict):
        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(
            self.server_url,
            data=json.dumps({"tool": tool, "args": wire}).encode(),
            headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")
            try:
                detail = json.loads(detail)["error"]
            except Exception:
                pass
            raise RuntimeError(f"server error from {tool}: {detail}") from None

    # ---------- identity verification ----------

    def _verify_identity(self, peer_id: str, identity_key_b64: str,
                         signing_key_b64: str):
        """Refuse any keys that do not hash to the peer's ID, or that
        contradict an explicit pin."""
        if fingerprint(identity_key_b64, signing_key_b64) != peer_id:
            raise PinMismatchError(
                f"PIN MISMATCH for peer '{peer_id}': server served keys whose "
                f"fingerprint is "
                f"'{fingerprint(identity_key_b64, signing_key_b64)}'. "
                "Possible MITM by the server — refusing to establish a session."
            )
        pinned = self.identity_keys.get(peer_id)
        if pinned is not None and pinned != identity_key_b64:
            raise PinMismatchError(
                f"PIN MISMATCH for peer '{peer_id}': server served identity key "
                f"{identity_key_b64!r} but the pinned key is {pinned!r}. "
                "Possible MITM by the server — refusing to establish a session."
            )

    # ---------- public API ----------

    def identity_key(self) -> str:
        """This user's Curve25519 identity public key, base64."""
        return self._load_account().curve25519_key.to_base64()

    def fingerprint(self) -> str:
        """This user's fingerprint — the sha256 of its public keys, sent as
        the `fingerprint` field in signed requests. Share it with peers
        (out-of-band): it is both address and pin."""
        acct = self._load_account()
        return fingerprint(acct.curve25519_key.to_base64(),
                           acct.ed25519_key.to_base64())

    def publish(self, n: int = 100, rotate_fallback: bool = False):
        """Publish identity, signing, and n fresh one-time keys to the
        server. This is also all the onboarding a server needs — there is no
        separate registration.

        Also publishes a fallback key — generated on first publish, or
        regenerated when rotate_fallback is set. vodozemac keeps the previous
        fallback key alive through one rotation, so messages in flight to the
        old key still decrypt.
        """
        with self._locked():
            self._publish(n, rotate_fallback)

    def _publish(self, n: int, rotate_fallback: bool):
        acct = self._load_account()
        if n:
            acct.generate_one_time_keys(n)
        if rotate_fallback or self._meta_get("fallback_ts") is None:
            acct.generate_fallback_key()
        otks = {kid: key.to_base64() for kid, key in acct.one_time_keys.items()}
        fk = {kid: key.to_base64() for kid, key in acct.fallback_key.items()}
        self._call("publish_keys", {
            "identity_key": acct.curve25519_key.to_base64(),
            "signing_key": acct.ed25519_key.to_base64(),
            "one_time_keys": otks,
            "fallback_key": fk or None,
        })
        acct.mark_keys_as_published()
        if fk:
            self._meta_set("fallback_ts", str(time.time()))
        self._save_account(acct)

    def sync(self, *, publish: bool = True, replenish: bool = True,
             rotate: bool = True, resend: bool = True,
             min_otks: int = 20, batch: int = 100,
             fallback_max_age: float = 86400.0,
             resend_after: float = 0.0) -> dict:
        """One reconciliation pass over a single `count_keys` round-trip. Each
        flag turns its step off, so every caller shares this one routine:

          publish   — (re)publish identity+signing keys (plus a key batch) when
                      the relay has forgotten us, so we stay reachable and our
                      messages stay verifiable.
          replenish — upload a fresh batch of one-time keys when the unclaimed
                      stash is low.
          rotate    — rotate the reusable fallback key once it is stale.
          resend    — re-upload unacknowledged outbox messages (loss recovery).

        `send` and `sync` resend; `receive` passes resend=False (reading never
        resends — retries belong to send and to an explicit sync). The default
        resend_after=0 re-sends everything still unacknowledged.
        """
        with self._locked():
            counts = self._call("count_keys")
            forgotten = not counts["has_fallback"]
            ts = self._meta_get("fallback_ts")
            stale = ts is None or time.time() - float(ts) > fallback_max_age
            need_otks = replenish and counts["unclaimed"] < min_otks
            need_rotate = (rotate and stale) or (publish and forgotten)
            if need_otks or need_rotate:
                self._publish(batch if need_otks else 0, need_rotate)
            resent = self._flush_outbox(resend_after) if resend else 0
            return {"unclaimed": counts["unclaimed"], "republished": forgotten,
                    "replenished": need_otks, "fallback_rotated": need_rotate,
                    "resent": resent}

    def maintain(self, min_otks: int = 20, batch: int = 100,
                 fallback_max_age: float = 86400.0,
                 resend_after: float = 120.0) -> dict:
        """Backward-compatible periodic upkeep: a full `sync()` pass. Prefer
        calling `sync()` directly for finer control (e.g. resend=False)."""
        return self.sync(min_otks=min_otks, batch=batch,
                         fallback_max_age=fallback_max_age,
                         resend_after=resend_after)

    def send(self, to: str, text: str) -> str:
        """Encrypt and send a message to a peer user ID. The ciphertext is
        kept in a local outbox until the peer acknowledges decrypting it.

        Returns the message id (see docs/STANDARD.md) -- the same id the
        recipient sees, so the two sides can be correlated."""
        with self._locked():
            mid = uuid.uuid4().hex
            payload = {"id": mid, "kind": "msg", "text": text,
                       "name": self.name}
            self._send_envelope(to, payload, record_outbox=True)
            return mid

    def _send_envelope(self, to: str, payload: dict, record_outbox: bool):
        session = self._load_session(to)
        if session is None:
            claimed = self._call("claim_key", {"peer": to})
            self._verify_identity(to, claimed["identity_key"],
                                  claimed["signing_key"])
            session = self._load_account().create_outbound_session(
                v.Curve25519PublicKey.from_base64(claimed["identity_key"]),
                v.Curve25519PublicKey.from_base64(claimed["one_time_key"]),
            )
        msg = session.encrypt(json.dumps(payload).encode())
        mtype, body = msg.to_parts()
        body_b64 = base64.b64encode(body).decode()
        if record_outbox:
            self._exec("INSERT INTO outbox(id, peer, mtype, body, ts) VALUES(?,?,?,?,?)",
                       payload["id"], to, mtype, body_b64, time.time())
        result = self._call("send_message",
                                  {"to": to, "mtype": mtype, "body": body_b64})
        self._save_session(to, session)
        return result

    def flush_outbox(self, older_than: float = 0.0) -> int:
        """Re-upload sent-but-unacknowledged ciphertext (e.g. after moving to
        a new server). Safe against duplicates: a peer that already decrypted
        a copy re-acks and drops it. Returns the number re-sent."""
        with self._locked():
            return self._flush_outbox(older_than)

    def _flush_outbox(self, older_than: float) -> int:
        rows = self._fetchall(
            "SELECT peer, mtype, body FROM outbox WHERE ts<=?",
            time.time() - older_than)
        for peer, mtype, body in rows:
            self._call("send_message",
                             {"to": peer, "mtype": mtype, "body": body})
        return len(rows)

    def receive(self, peer: str | None = None) -> list[dict]:
        """Fetch and decrypt pending messages, acknowledging each to its
        sender. Returns a list of message dicts (see docs/STANDARD.md):
        {"id", "from", "name", "text"}.

        With `peer` (a user id) set, only that sender's messages are fetched;
        everyone else's stays in the server mailbox for a later receive."""
        out = []
        with self._locked():
            inbox = (self._call("read_messages", {"peer": peer}) if peer
                     else self._call("read_messages"))
            for m in inbox:
                sender = m["from"]
                # Drop blocked or (in peers-only mode) unknown senders BEFORE
                # any decryption or session work, so a hostile/unknown sender
                # can never make us consume a one-time key with a pre-key
                # message. The mail stays on the server, unacked.
                if sender in self.blocked:
                    continue
                if self.receive_policy == "peers-only" and sender not in self.known:
                    continue
                body_hash = hashlib.sha256(m["body"].encode()).hexdigest()
                anymsg = v.AnyOlmMessage.from_parts(m["mtype"], base64.b64decode(m["body"]))
                try:
                    if m["mtype"] == 0:
                        prekey = anymsg.to_pre_key()
                        session = self._load_session(sender)
                        if session is not None and session.session_matches(prekey):
                            plaintext = session.decrypt(anymsg)
                        else:
                            keys = self._call("get_keys", {"peer": sender})
                            self._verify_identity(sender, keys["identity_key"],
                                                  keys["signing_key"])
                            acct = self._load_account()
                            session, plaintext = acct.create_inbound_session(
                                v.Curve25519PublicKey.from_base64(keys["identity_key"]),
                                prekey,
                            )
                            # create_inbound_session consumed a one-time key
                            self._save_account(acct)
                    else:
                        session = self._load_session(sender)
                        if session is None:
                            raise RuntimeError(
                                f"normal message from {sender} but no stored session")
                        plaintext = session.decrypt(anymsg)
                except PinMismatchError:
                    raise
                except Exception:
                    # the ratchet refuses re-used message keys, so a re-sent
                    # copy of something we already decrypted fails here:
                    # re-ack it (the first ack may have been lost) and drop it
                    dup_id = self._fetchone(
                        "SELECT msg_id FROM processed WHERE hash=?", body_hash)
                    if dup_id is None:
                        raise
                    self._send_envelope(
                        sender, {"id": dup_id, "kind": "ack"}, record_outbox=False)
                    continue
                self._save_session(sender, session)
                data = json.loads(plaintext.decode())
                if data["kind"] == "ack":
                    self._exec("DELETE FROM outbox WHERE id=?", data["id"])
                    continue
                self._exec("INSERT OR IGNORE INTO processed(hash, msg_id) VALUES(?,?)",
                           body_hash, data["id"])
                self._send_envelope(
                    sender, {"id": data["id"], "kind": "ack"}, record_outbox=False)
                name = self.names.get(sender) or (
                    f"~{data['name']}" if data.get("name") else "")
                out.append({"id": data["id"], "from": sender,
                            "name": name, "text": data["text"]})
        return out
