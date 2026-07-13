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

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sqlite3
import sys
import time
import urllib.error
import urllib.request
import uuid
from contextlib import contextmanager

import vodozemac as v

try:                     # POSIX: advisory whole-file lock
    import fcntl
except ImportError:      # Windows has no fcntl -- use msvcrt region locks
    fcntl = None
    import msvcrt


def _lock_exclusive(f):
    """Blocking exclusive lock on an open file. POSIX flock, or an msvcrt
    region lock (1 byte at offset 0) on Windows. Either way the OS releases
    the lock when the file closes or the process dies, so a crash can never
    leave a stale lock behind."""
    if fcntl is not None:
        fcntl.flock(f, fcntl.LOCK_EX)
        return
    while True:          # LK_LOCK gives up after ~10s; loop to block like flock
        try:
            msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
            return
        except OSError:
            time.sleep(0.05)


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
                 api_key: str | None = None,
                 left_groups: set | None = None):
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
        # group ids this user LEFT: their mail is refused (signed nack, like a
        # block) after decryption identifies the group -- the group id lives
        # inside the envelope, so it cannot be filtered any earlier
        self.left_groups = set(left_groups) if left_groups else set()
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
            _lock_exclusive(f)
            yield

    def _init_store(self):
        self._exec("CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT)")
        # One row per (peer, olm session): a pair can hold SEVERAL sessions —
        # when both sides initiate at once each side makes its own — and
        # decrypt tries each. A single-session-per-peer store overwrites its
        # own session with the inbound one, both sides end up holding only the
        # other's, and every later message fails MAC ("wedged").
        self._exec("CREATE TABLE IF NOT EXISTS sessions("
                   "peer TEXT, sid TEXT, blob TEXT, used REAL, "
                   "PRIMARY KEY(peer, sid))")
        cols = [r[1] for r in self._fetchall("PRAGMA table_info(sessions)")]
        if "sid" not in cols:              # migrate a one-session-per-peer table
            self._exec("ALTER TABLE sessions RENAME TO _sessions_old")
            self._exec("CREATE TABLE sessions(peer TEXT, sid TEXT, blob TEXT, "
                       "used REAL, PRIMARY KEY(peer, sid))")
            self._exec("INSERT INTO sessions(peer, sid, blob, used) "
                       "SELECT peer, '', blob, 0 FROM _sessions_old")
            self._exec("DROP TABLE _sessions_old")
        # sent-but-unacknowledged ciphertext, for re-delivery (server loss/migration).
        # A row is deleted on an ack, or when a resend comes back refused (the
        # recipient negative-acked it on the relay).
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

    def _load_sessions(self, peer: str) -> list:
        """Every Olm session held with `peer`, most recently used first.
        Decrypt tries each; send uses the freshest. A legacy row from the
        one-session-per-peer schema (sid='') is re-keyed by its real session
        id on first load."""
        out = []
        for sid, blob in self._fetchall(
                "SELECT sid, blob FROM sessions WHERE peer=? "
                "ORDER BY used DESC", peer):
            s = v.Session.from_pickle(blob, self._store_key)
            if not sid:
                self._exec("DELETE FROM sessions WHERE peer=? AND sid=''", peer)
                self._save_session(peer, s)
            out.append(s)
        return out

    def _save_session(self, peer: str, session: v.Session):
        self._exec("INSERT INTO sessions(peer, sid, blob, used) VALUES(?,?,?,?) "
                   "ON CONFLICT(peer, sid) DO UPDATE SET "
                   "blob=excluded.blob, used=excluded.used",
                   peer, session.session_id,
                   session.pickle(self._store_key), time.time())

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
        headers = {"content-type": "application/json",
                   # Some relays sit behind Cloudflare, whose Browser
                   # Integrity Check rejects a non-browser User-Agent
                   # (HTTP error 1010). Present a normal UA; override
                   # with the RETALK_USER_AGENT env var.
                   "user-agent": os.environ.get(
                       "RETALK_USER_AGENT",
                       "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")}
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

    def signing_key(self) -> str:
        """This user's Ed25519 signing public key, base64."""
        return self._load_account().ed25519_key.to_base64()

    def fingerprint(self) -> str:
        """This user's fingerprint — the sha256 of its public keys, sent as
        the `fingerprint` field in signed requests. Share it with peers
        (out-of-band): it is both address and pin."""
        acct = self._load_account()
        return fingerprint(acct.curve25519_key.to_base64(),
                           acct.ed25519_key.to_base64())

    # ---------- at-rest sealing (optional local copies) ----------

    def _at_rest_key(self):
        """A self-encryption keypair derived from the store key, for sealing
        optional local copies of messages (`retalk receive --save`).
        It is only as strong as the passphrase: a --no-passphrase identity
        derives the store key from a public constant, so its at-rest copies
        are not meaningfully encrypted (the caller is expected to warn)."""
        seed = hashlib.sha256(b"retalk:at-rest|" + self._store_key).digest()
        return v.Curve25519SecretKey.from_bytes(seed)

    def encrypt_at_rest(self, text: str) -> str:
        """Seal `text` for local storage, returning a blob that only this
        identity (with its passphrase) can open. The blob is the JSON triple
        [ciphertext, mac, ephemeral_key] (each base64). Reverse with
        decrypt_at_rest."""
        dec = v.PkDecryption.from_key(self._at_rest_key())
        msg = v.PkEncryption.from_key(dec.public_key).encrypt(text.encode())
        return json.dumps([base64.b64encode(b).decode()
                           for b in (msg.ciphertext, msg.mac, msg.ephemeral_key)])

    def decrypt_at_rest(self, blob: str) -> str:
        """Open a blob produced by encrypt_at_rest."""
        dec = v.PkDecryption.from_key(self._at_rest_key())
        ct, mac, eph = (base64.b64decode(p) for p in json.loads(blob))
        return dec.decrypt(v.Message(ct, mac, eph)).decode()

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

    def send(self, to: str, text: str, group: dict | None = None,
             mid: str | None = None) -> str:
        """Encrypt and send a message to a peer user ID. The ciphertext is
        kept in a local outbox until the peer acknowledges decrypting it.

        `group` tags the message as group mail: a {"id", "name", "members"}
        dict carried inside the encrypted payload (group chat is client-side
        fan-out — the caller sends one pairwise-encrypted copy per member, and
        this dict is how receivers thread the copies and learn the roster).
        `mid` overrides the per-copy message id's shared thread id: every copy
        gets its own wire id (acks and the outbox stay strictly pairwise) while
        payload["mid"] is identical across copies.

        Returns the message id (see docs/STANDARD.md) -- the same id the
        recipient sees, so the two sides can be correlated."""
        with self._locked():
            wire_id = uuid.uuid4().hex
            payload = {"id": wire_id, "kind": "msg", "text": text,
                       "name": self.name}
            if group is not None:
                payload["group"] = group
                payload["mid"] = mid or wire_id
            self._send_envelope(to, payload, record_outbox=True)
            return wire_id

    def leave_group(self, to: str, group_id: str) -> str:
        """Tell one member, over the normal encrypted channel, that this user
        left the group -- their client removes us from its roster so no more
        copies are fanned out our way (bandwidth, not secrecy: stragglers who
        still send get refused via the negative-ack path)."""
        with self._locked():
            mid = uuid.uuid4().hex
            self._send_envelope(to, {"id": mid, "kind": "group_leave",
                                     "group_id": group_id},
                                record_outbox=True)
            return mid

    def share(self, to: str, card: dict) -> str:
        """Encrypt and send a contact card to a peer user ID, introducing a
        third user. Like send(), the ciphertext is kept in the local outbox
        until the peer acknowledges decrypting it.

        `card` is a Contact object (see docs/STANDARD.md): the introduced
        user's "fingerprint" plus a recommended "name" (nickname), and the
        "identity_key"/"signing_key" when the sharer has them. The card is
        not a secret -- the recipient re-checks the keys against the
        fingerprint on import, so a tampered card is refused, not trusted.

        Returns the message id (see docs/STANDARD.md) -- the same id the
        recipient sees, so the two sides can be correlated."""
        with self._locked():
            mid = uuid.uuid4().hex
            payload = {"id": mid, "kind": "contact", "name": self.name,
                       "card": card}
            self._send_envelope(to, payload, record_outbox=True)
            return mid

    def _send_envelope(self, to: str, payload: dict, record_outbox: bool):
        sessions = self._load_sessions(to)
        session = sessions[0] if sessions else None   # the freshest one
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
            "SELECT id, peer, mtype, body FROM outbox WHERE ts<=?",
            time.time() - older_than)
        sent = 0
        for oid, peer, mtype, body in rows:
            res = self._call("send_message",
                             {"to": peer, "mtype": mtype, "body": body})
            if isinstance(res, dict) and res.get("refused"):
                # the recipient negative-acked this exact ciphertext on the
                # relay; verify their signature (don't take the relay's word)
                # before dropping it from the outbox so we stop resending it
                if self._verify_nack(peer, body, res.get("sig")):
                    self._exec("DELETE FROM outbox WHERE id=?", oid)
                    # The peer refused ciphertext we produced: either they
                    # block us, or they could not decrypt it (wedged/crossed
                    # sessions). Drop our sessions with them so the next send
                    # starts a fresh one instead of re-wedging.
                    self._exec("DELETE FROM sessions WHERE peer=?", peer)
                continue
            sent += 1
        return sent

    def _send_nack(self, ciphertext_hash: str):
        """Record on the relay that we refuse the message whose ciphertext
        hashes to `ciphertext_hash` — a signed negative ack. Keyed by the hash,
        so it needs no session and no decryption of the refused message. The
        relay then rejects that ciphertext's resends and hands our signature to
        the sender as proof, so even a sender that never calls receive stops
        resending it. Best-effort."""
        acct = self._load_account()
        sig = acct.sign(
            f"nack|{self.fingerprint()}|{ciphertext_hash}".encode()).to_base64()
        try:
            self._call("nack", {"hash": ciphertext_hash, "sig": sig})
        except Exception:
            pass  # relay unreachable / rate-limited: a later receive re-nacks

    def _verify_nack(self, peer: str, body: str, sig: str | None) -> bool:
        """Verify a refusal the relay returned for our `body` sent to `peer`:
        the signature must be `peer`'s over 'nack|<peer>|<hash>'. Returns True
        only on a valid signature, so a hostile relay cannot forge a refusal to
        make us abandon a message (it could only drop it, which it always can)."""
        if not sig:
            return False
        h = hashlib.sha256(body.encode()).hexdigest()
        try:
            keys = self._call("get_keys", {"peer": peer})
            self._verify_identity(peer, keys["identity_key"],
                                  keys["signing_key"])
            v.Ed25519PublicKey.from_base64(keys["signing_key"]).verify_signature(
                f"nack|{peer}|{h}".encode(),
                v.Ed25519Signature.from_base64(sig))
            return True
        except Exception:
            return False

    def receive(self, peer: str | None = None) -> list[dict]:
        """Fetch and decrypt pending messages, acknowledging each to its
        sender. Returns a list of dicts (see docs/STANDARD.md): a chat message
        is {"id", "from", "name", "text"}; a contact shared with `retalk share`
        is {"id", "from", "name", "kind": "contact", "card": {...}}.

        With `peer` (a user id) set, only that sender's messages are fetched;
        everyone else's stays in the server mailbox for a later receive."""
        out = []
        with self._locked():
            inbox = (self._call("read_messages", {"peer": peer}) if peer
                     else self._call("read_messages"))
            for m in inbox:
                sender = m["from"]
                body_hash = hashlib.sha256(m["body"].encode()).hexdigest()
                # Drop blocked or (in peers-only mode) unknown senders BEFORE
                # any decryption or session work, so a hostile/unknown sender
                # can never make us consume a one-time key with a pre-key
                # message. Record a signed negative-ack on the relay (keyed by
                # the ciphertext hash, no decryption) so the sender's resends
                # are refused at the relay even if it never calls receive.
                if sender in self.blocked or (
                        self.receive_policy == "peers-only"
                        and sender not in self.known):
                    self._send_nack(body_hash)
                    continue
                if m["mtype"] not in (0, 1):
                    continue  # not an Olm message (stray/obsolete type) — ignore
                anymsg = v.AnyOlmMessage.from_parts(m["mtype"], base64.b64decode(m["body"]))
                try:
                    if m["mtype"] == 0:
                        prekey = anymsg.to_pre_key()
                        session = next(
                            (s for s in self._load_sessions(sender)
                             if s.session_matches(prekey)), None)
                        if session is not None:
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
                            # create_inbound_session consumed a one-time key.
                            # The new session is ADDED next to any existing
                            # ones (never overwrites): both sides may have
                            # initiated at once, and the older session must
                            # survive for the mail still in flight on it.
                            self._save_account(acct)
                    else:
                        # a normal message names no session: try each stored
                        # one for this sender (there can be several)
                        session = plaintext = None
                        for s in self._load_sessions(sender):
                            try:
                                plaintext = s.decrypt(anymsg)
                                session = s
                                break
                            except Exception:
                                continue
                        if plaintext is None:
                            raise RuntimeError(
                                f"message from {sender} matches none of the "
                                "stored sessions")
                except PinMismatchError:
                    raise
                except Exception:
                    # the ratchet refuses re-used message keys, so a re-sent
                    # copy of something we already decrypted fails here:
                    # re-ack it (the first ack may have been lost) and drop it
                    dup_id = self._fetchone(
                        "SELECT msg_id FROM processed WHERE hash=?", body_hash)
                    if dup_id is not None:
                        self._send_envelope(
                            sender, {"id": dup_id, "kind": "ack"},
                            record_outbox=False)
                        continue
                    # Undecryptable and not a resend of anything we processed:
                    # ciphertext we can never read (wedged pre-fix sessions, a
                    # reset store, or tampering). Refuse it with a signed nack
                    # — the sender drops it AND resets their sessions with us,
                    # so their next send starts fresh — and keep receiving
                    # instead of crashing the whole poll.
                    self._send_nack(body_hash)
                    print(f"[retalk] refused an undecryptable message from "
                          f"{self.names.get(sender) or sender} (it matches no "
                          "stored session); the sender was told to start a "
                          "fresh session", file=sys.stderr)
                    continue
                self._save_session(sender, session)
                data = json.loads(plaintext.decode())
                g = data.get("group") if isinstance(data.get("group"), dict) \
                    else None
                if g and g.get("id") in self.left_groups:
                    # a room this user LEFT: refuse instead of ack, so the
                    # sender's outbox drops it and stops resending
                    self._send_nack(body_hash)
                    continue
                if data["kind"] == "ack":
                    self._exec("DELETE FROM outbox WHERE id=?", data["id"])
                    continue
                self._exec("INSERT OR IGNORE INTO processed(hash, msg_id) VALUES(?,?)",
                           body_hash, data["id"])
                self._send_envelope(
                    sender, {"id": data["id"], "kind": "ack"}, record_outbox=False)
                name = self.names.get(sender) or (
                    f"~{data['name']}" if data.get("name") else "")
                if data.get("kind") == "group_leave":
                    # the sender left a group: a control record, not chat --
                    # the caller removes them from its local roster
                    out.append({"id": data["id"], "from": sender, "name": name,
                                "kind": "group_leave",
                                "group_id": data.get("group_id") or ""})
                elif data.get("kind") == "contact":
                    # a shared contact card (`retalk share`): a distinct record
                    # so a consumer never mistakes a card for a chat message
                    out.append({"id": data["id"], "from": sender, "name": name,
                                "kind": "contact", "card": data.get("card", {})})
                else:
                    rec = {"id": data["id"], "from": sender,
                           "name": name, "text": data["text"]}
                    if isinstance(data.get("group"), dict):
                        # group mail: carry the envelope's roster through so
                        # the caller can thread it and update its local view
                        rec["group"] = data["group"]
                        rec["mid"] = data.get("mid") or data["id"]
                    out.append(rec)
        return out
