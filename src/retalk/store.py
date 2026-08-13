"""The identity store's shared tables: peers, groups, tombstones, messages.

One implementation used by BOTH layers - `User` methods (the library) and the
CLI's commands - so the schema lives in exactly one place and neither side can
drift from the other. Everything here is a plain function over a SQLite path:
no keys, no passphrase, no network. That neutrality is load-bearing: the CLI
must read contacts and rosters without unlocking an identity (`retalk group
list`, the global contacts.db), which a `User` constructor cannot do.

Message bodies are the only sealed content; callers pass them already
encrypted (User.encrypt_at_rest) and decrypt on the way out.
"""

from __future__ import annotations

import json
import sqlite3
import time


def sql(db, query: str, *params) -> list:
    conn = sqlite3.connect(str(db))
    try:
        with conn:
            return conn.execute(query, params).fetchall()
    finally:
        conn.close()


# ---------- peers (the address book) ----------

def ensure_peers(db):
    """Create/migrate the peers table; returns nothing."""
    info = sql(db, "PRAGMA table_info(peers)")
    if info:                                   # migrate an existing table
        cols = [r[1] for r in info]
        if "id" in cols and "fingerprint" not in cols:
            sql(db, "ALTER TABLE peers RENAME COLUMN id TO fingerprint")
        if "pin" in cols and "identity_key" not in cols:
            sql(db, "ALTER TABLE peers RENAME COLUMN pin TO identity_key")
        if "signing_key" not in cols:
            try:
                sql(db, "ALTER TABLE peers ADD COLUMN signing_key TEXT")
            except sqlite3.OperationalError:
                pass
        # re-key by fingerprint if the table is still keyed by name (old schema)
        info = sql(db, "PRAGMA table_info(peers)")
        if [r[1] for r in info if r[5]] == ["name"]:
            sql(db, "ALTER TABLE peers RENAME TO _peers_old")
            sql(db, "CREATE TABLE peers(fingerprint TEXT PRIMARY "
                    "KEY, name TEXT, identity_key TEXT, "
                    "signing_key TEXT)")
            sql(db, "INSERT OR IGNORE INTO peers("
                    "fingerprint, name, identity_key, signing_key) "
                    "SELECT fingerprint, name, identity_key, signing_key "
                    "FROM _peers_old")
            sql(db, "DROP TABLE _peers_old")
    sql(db, "CREATE TABLE IF NOT EXISTS peers("
            "fingerprint TEXT PRIMARY KEY, name TEXT, "
            "identity_key TEXT, signing_key TEXT)")


def saved_peers(db) -> dict:
    """{fingerprint: (name, identity_key, signing_key)} for saved peers.
    name is None for a peer added by fingerprint alone; the keys stay None
    until verify records them, so "verified" == both keys present."""
    ensure_peers(db)
    return {fp: (name, ik, sk) for fp, name, ik, sk in
            sql(db, "SELECT fingerprint, name, identity_key, signing_key "
                    "FROM peers")}


def upsert_peer(db, fp: str, name: str | None = None):
    """Save a peer; a later name wins, a missing one keeps what is there."""
    ensure_peers(db)
    sql(db, "INSERT INTO peers(fingerprint, name) VALUES(?,?) "
            "ON CONFLICT(fingerprint) DO UPDATE SET "
            "name=COALESCE(excluded.name, peers.name)", fp, name)


def record_peer_keys(db, fp: str, identity_key: str, signing_key: str):
    """Pin a peer's verified public keys (caller has checked the hash)."""
    ensure_peers(db)
    sql(db, "INSERT INTO peers(fingerprint, identity_key, signing_key) "
            "VALUES(?,?,?) ON CONFLICT(fingerprint) DO UPDATE SET "
            "identity_key=excluded.identity_key, "
            "signing_key=excluded.signing_key", fp, identity_key, signing_key)


def delete_peer(db, fp: str):
    ensure_peers(db)
    sql(db, "DELETE FROM peers WHERE fingerprint=?", fp)


# ---------- groups (rosters + leave tombstones) ----------

def ensure_groups(db):
    sql(db, "CREATE TABLE IF NOT EXISTS groups("
            "gid TEXT PRIMARY KEY, name TEXT, members TEXT, ts REAL)")


def load_groups(db) -> dict:
    """{gid: (name, [member fingerprints])} for this identity's groups."""
    ensure_groups(db)
    out = {}
    for gid, name, members in sql(db, "SELECT gid, name, members FROM groups"):
        try:
            out[gid] = (name, json.loads(members or "[]"))
        except ValueError:
            out[gid] = (name, [])
    return out


def group_by_ref(db, ref: str):
    """Resolve a group by local name or gid -> (gid, name, members) or None."""
    for gid, (name, members) in load_groups(db).items():
        if ref == gid or ref == name:
            return gid, name, members
    return None


def save_group(db, gid: str, name: str, members: list):
    """Save a roster. Cooperative membership: an incoming envelope's roster
    replaces the local one (last writer wins) - group chat has no admin
    protocol, only what peers tell each other."""
    ensure_groups(db)
    sql(db, "INSERT INTO groups(gid, name, members, ts) VALUES(?,?,?,?) "
            "ON CONFLICT(gid) DO UPDATE SET name=excluded.name, "
            "members=excluded.members, ts=excluded.ts",
        gid, name, json.dumps(sorted(set(members))), time.time())


def delete_group(db, gid: str):
    ensure_groups(db)
    sql(db, "DELETE FROM groups WHERE gid=?", gid)


def ensure_left(db):
    sql(db, "CREATE TABLE IF NOT EXISTS left_groups("
            "gid TEXT PRIMARY KEY, name TEXT, ts REAL)")


def left_groups(db) -> dict:
    """{gid: name} of groups this user LEFT: their mail is refused (signed
    nack, like a block) and they never re-materialize until the tombstone is
    cleared. Local state, so it survives forgetful members and relay resets."""
    ensure_left(db)
    return dict(sql(db, "SELECT gid, name FROM left_groups"))


def add_left(db, gid: str, name: str):
    ensure_left(db)
    sql(db, "INSERT OR REPLACE INTO left_groups(gid, name, ts) VALUES(?,?,?)",
        gid, name, time.time())


def clear_left(db, ref: str):
    """Drop a tombstone by gid or by the name it was stored under."""
    ensure_left(db)
    sql(db, "DELETE FROM left_groups WHERE gid=? OR name=?", ref, ref)


# ---------- saved messages (sealed bodies) ----------

def ensure_messages(db):
    sql(db, "CREATE TABLE IF NOT EXISTS messages("
            "msg_id TEXT PRIMARY KEY, from_fp TEXT, from_name TEXT, "
            "peer_fp TEXT, direction TEXT, body TEXT, ts REAL, "
            "gid TEXT, gname TEXT)")
    cols = [r[1] for r in sql(db, "PRAGMA table_info(messages)")]
    if "peer_fp" not in cols:          # migrate an older received-only table
        sql(db, "ALTER TABLE messages ADD COLUMN peer_fp TEXT")
        sql(db, "ALTER TABLE messages ADD COLUMN direction TEXT")
        sql(db, "UPDATE messages SET peer_fp=from_fp, direction='in' "
                "WHERE peer_fp IS NULL")
    if "gid" not in cols:              # pre-group-chat table: add group tags
        sql(db, "ALTER TABLE messages ADD COLUMN gid TEXT")
        sql(db, "ALTER TABLE messages ADD COLUMN gname TEXT")


def save_message_row(db, msg_id: str, from_fp: str, from_name: str,
                     peer_fp: str, direction: str, sealed_body: str,
                     group: dict | None = None):
    """Insert one saved message; the body arrives already sealed at rest.
    OR IGNORE keys duplicates out (a group fan-out saves ONE row, keyed by
    the shared thread id)."""
    ensure_messages(db)
    g = group if isinstance(group, dict) else {}
    sql(db, "INSERT OR IGNORE INTO messages(msg_id, from_fp, from_name, "
            "peer_fp, direction, body, ts, gid, gname) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
        msg_id or "", from_fp, from_name, peer_fp, direction, sealed_body,
        time.time(), g.get("id"), g.get("name"))


def message_rows(db, peer_fp: str | None = None,
                 gid: str | None = None) -> list:
    """Saved rows oldest first, optionally filtered to one peer or one group.
    Bodies come back still sealed; the caller decrypts."""
    ensure_messages(db)
    where, params = "", []
    if peer_fp:
        where, params = "WHERE peer_fp=?", [peer_fp]
    elif gid:
        where, params = "WHERE gid=?", [gid]
    return sql(db, "SELECT msg_id, from_fp, from_name, direction, body, "
                   f"gid, gname FROM messages {where} ORDER BY ts, rowid",
               *params)


# ---------- invite codes ----------

def ensure_invites(db):
    sql(db, "CREATE TABLE IF NOT EXISTS invite_codes("
            "code TEXT PRIMARY KEY, kind TEXT, peer TEXT, created REAL, "
            "expires REAL, uses INT DEFAULT 0, used_by TEXT, "
            "revoked INT DEFAULT 0)")


def mint_invite(db, peer: str | None = None, permanent: bool = False,
                expires_days: float | None = None) -> dict:
    """Mint a code. Single-use by default, expiring in 7 days; permanent
    codes are multi-use and live until revoked. expires_days overrides the
    default (0 or negative = never expires)."""
    import secrets
    if expires_days is None:
        expires = None if permanent else time.time() + 7 * 86400
    elif expires_days <= 0:
        expires = None
    else:
        expires = time.time() + expires_days * 86400
    # token_urlsafe draws from base64url, whose alphabet includes '-'. A code
    # that starts with one is unusable on the command line: argparse reads
    # `invite revoke -Xy...` and `--code -Xy...` as option flags and exits 2.
    # Redrawing costs about one call in 64 and leaves the entropy intact.
    while True:
        code = secrets.token_urlsafe(16)
        if not code.startswith("-"):
            break
    kind = "permanent" if permanent else "single"
    ensure_invites(db)
    sql(db, "INSERT INTO invite_codes(code, kind, peer, created, expires, "
            "uses, used_by, revoked) VALUES(?,?,?,?,?,0,'[]',0)",
        code, kind, peer, time.time(), expires)
    return {"code": code, "kind": kind, "expires": expires, "peer": peer}


def load_invites(db) -> list:
    """Every minted code, oldest first, as the spec's dicts."""
    ensure_invites(db)
    out = []
    for (code, kind, peer, created, expires, uses, used_by,
         revoked) in sql(db, "SELECT code, kind, peer, created, expires, "
                             "uses, used_by, revoked FROM invite_codes "
                             "ORDER BY created"):
        active = (not revoked
                  and (expires is None or time.time() <= expires)
                  and (kind == "permanent" or uses == 0))
        out.append({"code": code, "kind": kind, "peer": peer,
                    "created": created, "expires": expires, "uses": uses,
                    "used_by": json.loads(used_by or "[]"),
                    "revoked": bool(revoked), "active": active})
    return out


def get_invite(db, code: str):
    ensure_invites(db)
    rows = sql(db, "SELECT code, kind, peer, created, expires, uses, "
                   "used_by, revoked FROM invite_codes WHERE code=?", code)
    return rows[0] if rows else None


def revoke_invite(db, code: str) -> bool:
    ensure_invites(db)
    before = get_invite(db, code)
    if before is None:
        return False
    sql(db, "UPDATE invite_codes SET revoked=1 WHERE code=?", code)
    return True


def use_invite(db, code: str, by_fp: str) -> str:
    """Consume/record one use of a live code by `by_fp`. Returns "ok",
    "duplicate" (this fp already used it - idempotent re-delivery), or a
    rejection reason: "unknown-code", "revoked", "expired", "consumed".
    The compare-and-swap on single-use codes is guarded by the caller
    holding the identity's file lock."""
    row = get_invite(db, code)
    if row is None:
        return "unknown-code"
    _code, kind, _peer, _created, expires, uses, used_by, revoked = row
    used = json.loads(used_by or "[]")
    if by_fp in used:
        return "duplicate"
    if revoked:
        return "revoked"
    if expires is not None and time.time() > expires:
        return "expired"
    if kind == "single" and uses > 0:
        return "consumed"
    used.append(by_fp)
    sql(db, "UPDATE invite_codes SET uses=uses+1, used_by=? WHERE code=?",
        json.dumps(used), code)
    return "ok"
