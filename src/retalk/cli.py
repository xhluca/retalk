"""retalk command-line interface.

An identity lives in a folder (created by `retalk init`) containing
store.db: keys encrypted at rest, sessions, saved peers, outbox.

Which user every command acts as, in order:
  --dir DIR  >  --user/-u NAME  >  RETALK_USER env  >  error (never guessed).
Only `init` ever creates an identity; every other command refuses loudly
when the selected user has none.

The passphrase comes from --passphrase or RETALK_PASSPHRASE; there is no
interactive prompt. --no-passphrase creates or opens an identity with
no passphrase (keys then protected only by file permissions).
The relay URL comes from --relay, RETALK_RELAY, or the value saved at
init. Identity banners go to stderr so stdout stays clean for --json.
"""

from __future__ import annotations

import argparse
import getpass
import importlib.resources
import json
import os
import re
import shutil
import sqlite3
import sys
import textwrap
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from .user import User, fingerprint

STORE_FILE = "store.db"
ID_RE = re.compile(r"^[0-9a-f]{32}$")


def _data_home() -> Path:
    return Path(os.environ.get("RETALK_HOME", Path.home() / ".retalk"))


def _config() -> dict:
    """Owner-wide defaults from `~/.retalk/config.json` (a JSON object), applied
    to every identity as the LAST fallback. Empty when missing or malformed.
    RETALK_HOME relocates it with the rest of the store."""
    try:
        cfg = json.loads((_data_home() / "config.json").read_text())
        return cfg if isinstance(cfg, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_config(cfg: dict):
    _data_home().mkdir(parents=True, exist_ok=True)
    p = _data_home() / "config.json"
    p.write_text(json.dumps(cfg, indent=2) + "\n")
    try:
        p.chmod(0o600)
    except OSError:
        pass


def _default_relay() -> str:
    """Owner-wide default relay URL (the "relay" key of config.json). The last
    fallback after --relay, RETALK_RELAY, and the per-identity saved relay."""
    return _config().get("relay") or ""


def _packaged_config() -> str:
    """The default config.json shipped inside the wheel. `init` copies it to
    ~/.retalk/config.json on first run; after that the user's copy wins, so a
    new default in a later version only affects fresh installs."""
    try:
        return (importlib.resources.files("retalk") / "config.json").read_text()
    except (FileNotFoundError, ModuleNotFoundError, OSError, TypeError):
        return ""


def _ensure_config() -> None:
    """Seed ~/.retalk/config.json from the packaged default when the user has no
    config yet. Called by `init`; existing configs are left untouched."""
    p = _data_home() / "config.json"
    if p.exists():
        return
    text = _packaged_config()
    if not text:
        return
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        p.chmod(0o600)
    except OSError:
        pass


def _local_home() -> Path:
    """Project-local store: `.retalk/` at the git root, else the current dir.
    Mirrors agent-talk's local scope. Used only when auto-naming a new identity
    (see `_next_default_user`), never for `--user` resolution."""
    cwd = Path.cwd()
    for d in (cwd, *cwd.parents):
        if (d / ".git").exists():
            return d / ".retalk"
    return cwd / ".retalk"


def _next_default_user() -> str:
    """Name for `retalk init` when no user is given: the OS login user plus the
    next free numeric suffix (e.g. alice-1, alice-2). Scans existing identities
    in BOTH the global (~/.retalk) and project-local (.retalk) stores so repeated
    inits never reuse a number. Kept separate to stay self-contained."""
    try:
        base = getpass.getuser()
    except Exception:
        base = "user"
    pat = re.compile(rf"^{re.escape(base)}-(\d+)$")
    highest, seen = 0, set()
    for home in (_data_home(), _local_home()):
        rp = home.resolve()
        if rp in seen or not home.is_dir():
            continue
        seen.add(rp)
        for child in home.iterdir():
            m = pat.match(child.name)
            if m and (child / STORE_FILE).exists():   # only real identities count
                highest = max(highest, int(m.group(1)))
    return f"{base}-{highest + 1}"


def _pick_signer() -> Path | None:
    """Pick a local identity to SIGN an authenticated relay request (the get_keys
    behind `verify`) when none is selected -- used when verifying a GLOBAL contact
    with no --user. The signer never changes the result: get_keys just needs
    *some* registered caller. So prefer one we can open with no passphrase, and
    otherwise only auto-pick when there is exactly one identity (never silently
    choose among several). Returns the identity dir, or None."""
    ids, seen = [], set()
    for home in (_data_home(), _local_home()):
        if not home.is_dir():
            continue
        rp = home.resolve()
        if rp in seen:
            continue
        seen.add(rp)
        for child in sorted(home.iterdir()):
            if (child / STORE_FILE).exists():
                ids.append(child)
    for d in ids:                                  # prefer a no-passphrase identity
        if _meta(d / STORE_FILE, "no_passphrase") == "1":
            return d
    return ids[0] if len(ids) == 1 else None


def _die(msg: str, code: int = 2):
    print(f"[retalk] {msg}", file=sys.stderr)
    sys.exit(code)


def _style(text: str, code: str) -> str:
    """Wrap text in an ANSI SGR code, but only when stderr is a TTY -- so piped
    or redirected output stays clean (and copying yields the raw text)."""
    return f"\033[{code}m{text}\033[0m" if sys.stderr.isatty() else text


def _resolve_store(args, creating: bool = False) -> Path:
    if getattr(args, "dir", None):                 # --dir DIR (explicit path)
        d = Path(args.dir)
    elif getattr(args, "user", None):              # --user / -u NAME
        d = _data_home() / args.user
    elif os.environ.get("RETALK_USER"):            # RETALK_USER env
        d = _data_home() / os.environ["RETALK_USER"]
    else:
        _die("no user selected: pass --user NAME (-u NAME), set RETALK_USER, "
             "or pass --dir DIR")
    if not creating and not (d / STORE_FILE).exists():
        _die(f"no identity at {d} — create one with `retalk init`")
    return d


# Identities made with --no-passphrase are pickled under this fixed,
# public key. It is not a secret; it just lets vodozemac's pickle round-trip
# when the user opts out of a real passphrase. Such a store is protected only
# by its file permissions.
NO_PASSPHRASE = "\0retalk:disabled-passphrase"


def _resolve_passphrase(args, store_db: Path | None = None,
                        creating: bool = False) -> tuple[str, bool]:
    """Return (passphrase, disabled) without ever prompting.

    A store created with --no-passphrase records that choice, so later
    commands reopen it with no passphrase automatically. Otherwise the
    passphrase must come from --passphrase or RETALK_PASSPHRASE; a missing one
    is a loud error, never a prompt, so agents never block on human input."""
    if (not creating and store_db is not None
            and _meta(store_db, "no_passphrase") == "1"):
        return NO_PASSPHRASE, True
    if getattr(args, "no_passphrase", False):
        if creating:
            return NO_PASSPHRASE, True
        _die("this identity is passphrase-protected: pass --passphrase or set "
             "RETALK_PASSPHRASE (it was not created with --no-passphrase)")
    s = getattr(args, "passphrase", None) or os.environ.get("RETALK_PASSPHRASE")
    if s:
        return s, False
    # Show the user's ACTUAL command with the missing piece filled in (rendered
    # like the other colored bash blocks), not just the name of a flag.
    ran = "retalk " + " ".join(sys.argv[1:])
    lines = [
        "# rerun with the passphrase inline:",
        f'{ran} -p "<YOUR-PASSPHRASE>"',
        "# or set it once for this shell, then rerun:",
        'export RETALK_PASSPHRASE="<YOUR-PASSPHRASE>"',
        ran,
    ]
    if creating:
        lines += [
            "# or create it with no passphrase -- unsafe, keys stored unencrypted:",
            f"{ran} --no-passphrase",
        ]
    _die("no passphrase provided" +
         ("" if creating else " (this identity's keys are encrypted with one)")
         + ":\n" + _bash_block(lines))


def _store_sql(store_db: Path, query: str, *params) -> list:
    conn = sqlite3.connect(store_db)
    try:
        with conn:
            return conn.execute(query, params).fetchall()
    finally:
        conn.close()


def _meta(store_db: Path, key: str) -> str | None:
    rows = _store_sql(store_db, "SELECT v FROM meta WHERE k=?", key)
    return rows[0][0] if rows else None


def _saved_peers(store_db: Path) -> dict:
    """Return {fingerprint: (name, identity_key, signing_key)} for saved peers.

    A peer is keyed by its fingerprint; `name` is an optional local label (None
    when added by fingerprint alone). identity_key and signing_key stay None
    until `retalk verify` records them, so a peer is "verified" exactly when
    both keys are present."""
    info = _store_sql(store_db, "PRAGMA table_info(peers)")
    if info:                                   # migrate an existing table
        cols = [r[1] for r in info]
        if "id" in cols and "fingerprint" not in cols:
            _store_sql(store_db, "ALTER TABLE peers RENAME COLUMN id TO fingerprint")
        if "pin" in cols and "identity_key" not in cols:
            _store_sql(store_db,
                       "ALTER TABLE peers RENAME COLUMN pin TO identity_key")
        if "signing_key" not in cols:
            try:
                _store_sql(store_db, "ALTER TABLE peers ADD COLUMN signing_key TEXT")
            except sqlite3.OperationalError:
                pass
        # re-key by fingerprint if the table is still keyed by name (old schema)
        info = _store_sql(store_db, "PRAGMA table_info(peers)")
        if [r[1] for r in info if r[5]] == ["name"]:
            _store_sql(store_db, "ALTER TABLE peers RENAME TO _peers_old")
            _store_sql(store_db, "CREATE TABLE peers(fingerprint TEXT PRIMARY "
                                 "KEY, name TEXT, identity_key TEXT, "
                                 "signing_key TEXT)")
            _store_sql(store_db, "INSERT OR IGNORE INTO peers("
                       "fingerprint, name, identity_key, signing_key) "
                       "SELECT fingerprint, name, identity_key, signing_key "
                       "FROM _peers_old")
            _store_sql(store_db, "DROP TABLE _peers_old")
    _store_sql(store_db, "CREATE TABLE IF NOT EXISTS peers("
                         "fingerprint TEXT PRIMARY KEY, name TEXT, "
                         "identity_key TEXT, signing_key TEXT)")
    return {fp: (name, ik, sk) for fp, name, ik, sk in
            _store_sql(store_db, "SELECT fingerprint, name, identity_key, "
                                 "signing_key FROM peers")}


def _global_contacts_db() -> Path:
    """The owner-wide contact list shared by every identity: a peers table at
    ~/.retalk/contacts.db (RETALK_HOME relocates it). `add` writes here when no
    identity is selected (or with --global)."""
    return _data_home() / "contacts.db"


def _effective_peers(store_db: Path) -> dict:
    """The contacts an identity sees: the global list overlaid with this
    identity's own. The identity's entries override global on the same
    fingerprint OR the same local name; returns {fingerprint: (name, ik, sk)}."""
    glob = _saved_peers(_global_contacts_db())
    user = _saved_peers(store_db)
    user_names = {nm for (nm, _i, _s) in user.values() if nm}
    merged = {fp: v for fp, v in glob.items()
              if fp not in user and (v[0] is None or v[0] not in user_names)}
    merged.update(user)
    return merged


def _contact_db(store_db: Path, fp: str) -> Path | None:
    """Which store actually holds the contact `fp` -- the identity's own store
    if present there, else the global list, else None. Lets `verify`/`remove`
    act on the right list."""
    if fp in _saved_peers(store_db):
        return store_db
    if fp in _saved_peers(_global_contacts_db()):
        return _global_contacts_db()
    return None


def _blocked_set(store_db: Path) -> set:
    _store_sql(store_db,
               "CREATE TABLE IF NOT EXISTS blocked(fingerprint TEXT PRIMARY KEY)")
    return {fp for (fp,) in
            _store_sql(store_db, "SELECT fingerprint FROM blocked")}


# Columns of a staged shared contact, in select order. The card fields mirror
# a Contact (docs/STANDARD.md); from_fp/from_name record who introduced it.
_INBOX_COLS = ("fingerprint", "name", "identity_key", "signing_key",
               "from_fp", "from_name", "msg_id", "ts")


def _received_contacts(store_db: Path) -> list[dict]:
    """The contact-inbox: cards received via `retalk share` and saved by
    `retalk receive`, awaiting `retalk import --inbox`. One row per contact
    (keyed by fingerprint, newest share wins), sorted by recommended name."""
    _store_sql(store_db, "CREATE TABLE IF NOT EXISTS received_contacts("
               "fingerprint TEXT PRIMARY KEY, name TEXT, identity_key TEXT, "
               "signing_key TEXT, from_fp TEXT, from_name TEXT, msg_id TEXT, "
               "ts REAL)")
    rows = _store_sql(store_db, f"SELECT {', '.join(_INBOX_COLS)} "
                                "FROM received_contacts ORDER BY name")
    return [dict(zip(_INBOX_COLS, r)) for r in rows]


def _stage_contact(store_db: Path, rec: dict):
    """Save one received contact record (`receive`) into the inbox, replacing
    any earlier card for the same fingerprint. Ignores a malformed card."""
    card = rec.get("card") or {}
    fp = card.get("fingerprint", "")
    if not ID_RE.match(fp):
        return
    _received_contacts(store_db)  # ensure the table exists
    _store_sql(store_db,
               "INSERT INTO received_contacts("
               "fingerprint, name, identity_key, signing_key, from_fp, "
               "from_name, msg_id, ts) VALUES(?,?,?,?,?,?,?,?) "
               "ON CONFLICT(fingerprint) DO UPDATE SET name=excluded.name, "
               "identity_key=excluded.identity_key, "
               "signing_key=excluded.signing_key, from_fp=excluded.from_fp, "
               "from_name=excluded.from_name, msg_id=excluded.msg_id, "
               "ts=excluded.ts",
               fp, card.get("name") or "", card.get("identity_key") or "",
               card.get("signing_key") or "", rec.get("from") or "",
               rec.get("name") or "", rec.get("id") or "", time.time())


def _save_messages_on(args) -> bool:
    """Whether to persist message bodies for `retalk history`. Off by default --
    retalk keeps no message log unless you opt in, either with --save or
    by setting RETALK_SAVE_MESSAGE to a truthy value (1/true/t/yes/y/on). The flag
    forces it on; otherwise the env var decides (anything else, including
    false/no/n/f or unset, means off)."""
    if getattr(args, "save_messages", False):
        return True
    return os.environ.get("RETALK_SAVE_MESSAGE", "").strip().lower() in (
        "1", "true", "t", "yes", "y", "on")


def _warn_unsealed_save(store_db: Path):
    """Warn when saving messages on a --no-passphrase identity: the at-rest key is
    a public constant, so the bodies are guarded only by file permissions."""
    if _meta(store_db, "no_passphrase") == "1":
        print("retalk: warning: saving messages on a --no-passphrase identity "
              "stores message bodies with no real protection (its store key is "
              "a public constant); the folder's file permissions are the only "
              "guard", file=sys.stderr)


def _ensure_messages(store_db: Path):
    _store_sql(store_db, "CREATE TABLE IF NOT EXISTS messages("
               "msg_id TEXT PRIMARY KEY, from_fp TEXT, from_name TEXT, "
               "peer_fp TEXT, direction TEXT, body TEXT, ts REAL, "
               "gid TEXT, gname TEXT)")
    cols = [r[1] for r in _store_sql(store_db, "PRAGMA table_info(messages)")]
    if "peer_fp" not in cols:        # migrate an older received-only table
        _store_sql(store_db, "ALTER TABLE messages ADD COLUMN peer_fp TEXT")
        _store_sql(store_db, "ALTER TABLE messages ADD COLUMN direction TEXT")
        _store_sql(store_db, "UPDATE messages SET peer_fp=from_fp, direction='in' "
                             "WHERE peer_fp IS NULL")   # old rows were all received
    if "gid" not in cols:            # pre-group-chat table: add the group tags
        _store_sql(store_db, "ALTER TABLE messages ADD COLUMN gid TEXT")
        _store_sql(store_db, "ALTER TABLE messages ADD COLUMN gname TEXT")


def _save_message(store_db: Path, u, rec: dict):
    """Persist one INCOMING chat message (`receive --save`) with its body
    sealed at rest by the identity's key (see User.encrypt_at_rest)."""
    _ensure_messages(store_db)
    sender = rec.get("from") or ""
    g = rec.get("group") if isinstance(rec.get("group"), dict) else {}
    _store_sql(store_db,
               "INSERT OR IGNORE INTO messages(msg_id, from_fp, from_name, "
               "peer_fp, direction, body, ts, gid, gname) "
               "VALUES(?,?,?,?,?,?,?,?,?)",
               rec.get("id") or "", sender, rec.get("name") or "",
               sender, "in", u.encrypt_at_rest(rec.get("text") or ""),
               time.time(), g.get("id"), g.get("name"))


def _save_sent(store_db: Path, u, msg_id: str, to_fp: str, text: str,
               group: dict | None = None):
    """Persist one OUTGOING chat message (`send --save`), body sealed at
    rest, so `history` shows both sides of the conversation. A group send
    saves ONE row (keyed by the shared thread id), not one per copy."""
    _ensure_messages(store_db)
    g = group or {}
    _store_sql(store_db,
               "INSERT OR IGNORE INTO messages(msg_id, from_fp, from_name, "
               "peer_fp, direction, body, ts, gid, gname) "
               "VALUES(?,?,?,?,?,?,?,?,?)",
               msg_id or "", u.fingerprint(), u.name or "", to_fp or "",
               "out", u.encrypt_at_rest(text or ""), time.time(),
               g.get("id"), g.get("name"))


# ---------- groups (client-side fan-out) ----------

def _ensure_groups(store_db: Path):
    _store_sql(store_db, "CREATE TABLE IF NOT EXISTS groups("
               "gid TEXT PRIMARY KEY, name TEXT, members TEXT, ts REAL)")


def _groups(store_db: Path) -> dict:
    """{gid: (name, [member fingerprints])} for this identity's groups."""
    _ensure_groups(store_db)
    out = {}
    for gid, name, members in _store_sql(
            store_db, "SELECT gid, name, members FROM groups"):
        try:
            out[gid] = (name, json.loads(members or "[]"))
        except ValueError:
            out[gid] = (name, [])
    return out


def _group_by_name(store_db: Path, ref: str):
    """Resolve a group by local name or gid -> (gid, name, members) or None."""
    for gid, (name, members) in _groups(store_db).items():
        if ref == gid or ref == name:
            return gid, name, members
    return None


def _group_upsert(store_db: Path, gid: str, name: str, members: list):
    """Save a group roster. Cooperative membership: an incoming envelope's
    roster replaces the local one (last writer wins) — group chat has no
    admin protocol, only what peers tell each other."""
    _ensure_groups(store_db)
    _store_sql(store_db,
               "INSERT INTO groups(gid, name, members, ts) VALUES(?,?,?,?) "
               "ON CONFLICT(gid) DO UPDATE SET name=excluded.name, "
               "members=excluded.members, ts=excluded.ts",
               gid, name, json.dumps(sorted(set(members))), time.time())


def _ensure_left(store_db: Path):
    _store_sql(store_db, "CREATE TABLE IF NOT EXISTS left_groups("
               "gid TEXT PRIMARY KEY, name TEXT, ts REAL)")


def _left_groups(store_db: Path) -> dict:
    """{gid: name} of groups this user LEFT. A left group's mail is refused
    (signed nack, like a block) and it never re-materializes -- until
    `retalk group join` clears the tombstone. Local state, so it survives
    members forgetting and relay resets alike."""
    _ensure_left(store_db)
    return dict(_store_sql(store_db, "SELECT gid, name FROM left_groups"))


def _apply_group_leave(store_db: Path, m: dict):
    """Process a group_leave control record: drop the sender from that
    group's roster so no more copies are fanned out their way."""
    gl = _groups(store_db).get(m.get("group_id") or "")
    if gl:
        _group_upsert(store_db, m["group_id"], gl[0],
                      [fp for fp in gl[1] if fp != m.get("from")])


def _group_cap(args, store_db: Path) -> int:
    """The relay's advisory max group size (roster incl. yourself), from GET
    /info. Cached in the identity store; 100 when no relay ever answered."""
    server = (getattr(args, "relay", None) or os.environ.get("RETALK_RELAY")
              or _meta(store_db, "server_url") or _default_relay())
    if server:
        try:
            with urllib.request.urlopen(
                    server.rstrip("/") + "/info", timeout=4) as r:
                cap = int(json.loads(r.read().decode())
                          .get("max_group_size", 100))
            _store_sql(store_db, "INSERT INTO meta(k, v) VALUES('group_cap',?)"
                       " ON CONFLICT(k) DO UPDATE SET v=excluded.v", str(cap))
            return cap
        except Exception:
            pass                       # offline: fall back to the cached value
    cached = _meta(store_db, "group_cap")
    return int(cached) if cached else 100


def _group_materialize(store_db: Path, g: dict):
    """Adopt a group arriving inside a message envelope. Group NAMES are local
    handles (like peer names) and must stay unambiguous: a foreign group whose
    name is already taken by a DIFFERENT local group gets a numeric suffix
    (team -> team-2), and a known group never steals another group's name —
    otherwise `send --group NAME` would pick one of two rooms at random."""
    gid = g.get("id")
    if not gid:
        return
    if gid in _left_groups(store_db):   # left rooms never come back on their own
        return
    members = [fp for fp in g.get("members", []) if ID_RE.match(str(fp))]
    cached = _meta(store_db, "group_cap")
    if len(members) > (int(cached) if cached else 100):
        return                          # oversized foreign roster: don't adopt
    name = g.get("name") or gid[:8]
    groups = _groups(store_db)
    taken = {nm for other, (nm, _m) in groups.items() if other != gid}
    if gid in groups:
        name = groups[gid][0]           # the local handle is the user's own:
                                        # envelopes update rosters, never names
    else:
        base, n = name, 1
        while name in taken:
            n += 1
            name = f"{base}-{n}"
    _group_upsert(store_db, gid, name, members)


def _open_user(args, need_server: bool = True, banner: bool = True) -> User:
    d = _resolve_store(args)
    store_db = d / STORE_FILE
    secret, _ = _resolve_passphrase(args, store_db=store_db)
    server = (getattr(args, "relay", None) or os.environ.get("RETALK_RELAY")
              or _meta(store_db, "server_url") or _default_relay())
    if need_server and not server:
        _die("no relay URL: pass --relay, set RETALK_RELAY, or save one "
             "at init time")
    peers = _effective_peers(store_db)
    identity_keys = {fp: ik for fp, (name, ik, _sk) in peers.items() if ik}
    names = {fp: name for fp, (name, _ik, _sk) in peers.items() if name}
    known = set(peers)
    blocked = _blocked_set(store_db)
    left = set(_left_groups(store_db))
    # --peers-only this run, or the setting persisted by an earlier flag
    policy = ("peers-only"
              if (getattr(args, "peers_only", False)
                  or _meta(store_db, "receive_policy") == "peers-only")
              else "open")
    api_key = (getattr(args, "api_key", None) or os.environ.get("RETALK_API_KEY")
               or _meta(store_db, "api_key"))
    try:
        u = User(server, secret, name=_meta(store_db, "name") or "",
                 store=str(store_db), identity_keys=identity_keys, names=names,
                 blocked=blocked, receive_policy=policy, known=known,
                 api_key=api_key, left_groups=left)
    except Exception:
        _die(f"could not unlock the identity at {d} (wrong passphrase?)")
    if banner:
        print(f"using {u.name or 'user'} ({u.fingerprint()}) from {d}",
              file=sys.stderr)
    return u


def _resolve_peer(peers: dict, arg: str) -> str | None:
    """Resolve a peer reference (a saved local name or a 32-hex fingerprint) to
    a fingerprint, or None. `peers` is {fingerprint: (name, ik, sk)}."""
    if arg in peers:                        # already a saved fingerprint
        return arg
    for fp, (name, _ik, _sk) in peers.items():
        if name and name == arg:            # matched a saved local name
            return fp
    return arg if ID_RE.match(arg) else None  # an unsaved fingerprint


def _peer_to_id(peer: str, store_db: Path) -> str:
    fp = _resolve_peer(_effective_peers(store_db), peer)
    if fp:
        return fp
    _die(f"unknown peer '{peer}': `retalk add {peer}` first, "
         "or pass a 32-hex user id")


def _build_card(store_db: Path, contact: str, as_name: str | None) -> dict:
    """Build a Contact card (see docs/STANDARD.md) for `contact` -- a saved
    peer name or a raw 32-hex fingerprint -- for `contacts --show` or `share`.

    The recommended nickname is `as_name` if given, else the saved peer name,
    else "". The identity_key/signing_key are filled in only when the contact
    is a verified saved peer; otherwise they stay "" and the card is shared
    unverified (the recipient verifies on first contact, as always)."""
    peers = _effective_peers(store_db)            # {fingerprint: (name, ik, sk)}
    fp = _resolve_peer(peers, contact)
    if fp is None:
        _die(f"unknown contact '{contact}': save it with "
             f"`retalk add {contact}`, or pass a 32-hex user id")
    if fp in peers:                           # a saved peer
        saved_name, ik, sk = peers[fp]
        name = as_name or saved_name or ""
    else:                                     # an unsaved fingerprint
        name, ik, sk = (as_name or ""), None, None
    return {"fingerprint": fp, "name": name,
            "identity_key": ik or "", "signing_key": sk or "",
            "verified": bool(ik and sk)}


# ---------- commands ----------

def cmd_init(args):
    # Resolve the passphrase FIRST: a missing one must fail before we announce a
    # name, seed config, or create any directory -- otherwise a bare `init` with
    # no passphrase leaves a stray empty identity dir.
    secret, disabled = _resolve_passphrase(args, creating=True)
    _ensure_config()   # seed ~/.retalk/config.json from the packaged default
    # No selector? Auto-name the new identity <login>-<n> (init only).
    if not args.dir and not args.user and not os.environ.get("RETALK_USER"):
        args.user = _next_default_user()
        print('No user specified, defaulting to automatically generated '
              f'"{args.user}".', file=sys.stderr)
    d = _resolve_store(args, creating=True)
    if (d / STORE_FILE).exists():
        _die(f"an identity already exists at {d}")
    d.mkdir(parents=True, exist_ok=True)
    server = args.relay or os.environ.get("RETALK_RELAY") or _default_relay()
    # default the display name to the chosen user name (--user / RETALK_USER),
    # so `init --user alice` labels messages 'alice' without repeating it;
    # an identity selected only by --dir has no user name, so stays unnamed.
    display = (args.display_name or args.user
               or os.environ.get("RETALK_USER") or "")
    u = User(server, secret, name=display, store=str(d / STORE_FILE))
    u._meta_set("created_at", repr(time.time()))   # lets `retalk id --last` find it
    if disabled:
        u._meta_set("no_passphrase", "1")
    if display:
        u._meta_set("name", display)
    if server:
        u._meta_set("server_url", server)
    if args.api_key:
        u._meta_set("api_key", args.api_key)
    # private keys live here; keep them owner-only whether or not encrypted
    try:
        (d / STORE_FILE).chmod(0o600)
        d.chmod(0o700)
    except OSError:
        pass

    # Publish keys to the relay so peers can reach you (unless --no-register).
    # Best-effort: a failure never blocks init, but it warns LOUDLY — an
    # unregistered identity cannot be messaged until its keys are published.
    if not getattr(args, "no_register", False):
        if args.user and not args.dir:
            reg = f"retalk register -u {args.user}"
        elif args.dir:
            reg = f"retalk register --dir {args.dir}"
        else:
            reg = "retalk register"          # RETALK_USER selects the identity
        if server:
            try:
                u.sync(resend=False)
                print(_style(f"\n✓ Registered on {server} — peers can message "
                             "you.", "1;32"), file=sys.stderr)
            except Exception as e:
                print(_style(
                    f"\n⚠ NOT registered: the relay at {server} could not be "
                    f"reached ({e}).\n"
                    "  Peers cannot message you until your keys are published. "
                    "Once the relay\n"
                    f"  is reachable, run `{reg}` (any send/receive publishes "
                    "them too).", "1;31"), file=sys.stderr)
        else:
            print(_style(
                "\n⚠ NOT registered: no relay is configured, so your keys were "
                "not published\n"
                "  and peers cannot message you. Set a relay, then register:\n"
                "    retalk config --relay \"<url>\"\n"
                f"    {reg}", "1;31"), file=sys.stderr)

    home = str(Path.home())
    shown = str(d).replace(home, "~", 1) if str(d).startswith(home) else str(d)
    err = sys.stderr
    if disabled:
        print(_style(
            "\n⚠ Keys are stored UNENCRYPTED — anyone who can read this folder "
            "can impersonate you.\n"
            "  Use --passphrase (or RETALK_PASSPHRASE) for any identity whose "
            "privacy matters.", "1;31"), file=err)
    print(f"\nName:        {display or d.name}", file=err)
    print(f"Path:        {shown}", file=err)
    print(f"Fingerprint: {u.fingerprint()}", file=err)
    print("Relay:       "
          + (server or "(none — set one with: retalk config --relay \"<url>\")"),
          file=err)
    # Print BOTH onboarding snippets, labeled, so you can pick the right one:
    #   - invite: you are inviting a peer who is NOT on retalk yet
    #   - reply:  you are responding to an invite someone already sent you
    print("\nTo INVITE a peer who is not on retalk yet, share this:\n"
          + _invite_message(u, None), file=err)
    print("\nOr, if you are REPLYING to an invite someone sent you, "
          "send them this instead:\n"
          + _invite_reply(u, None), file=err)
    # bare id on stdout for scripts/pipes; skipped interactively (shown above)
    if not sys.stdout.isatty():
        print(u.fingerprint())


def cmd_config(args):
    cfg = _config()
    if args.relay is not None:                 # --relay given (maybe empty)
        if args.relay:
            cfg["relay"] = args.relay
        else:
            cfg.pop("relay", None)             # --relay "" clears it
        _write_config(cfg)
    print(json.dumps(cfg, indent=2))


def _self_card(u, as_name):
    """This user's OWN Contact card (see docs/STANDARD.md), plus the `relay` it
    uses -- the shareable form of your own identity ("share a personal user").
    A peer saves it with `retalk import`; the extra `relay` field tells them
    where to reach you and is ignored by clients that do not use it."""
    card = {"fingerprint": u.fingerprint(), "name": as_name or u.name or "",
            "identity_key": u.identity_key(), "signing_key": u.signing_key(),
            "verified": True}
    relay = u.server_url or _default_relay()
    if relay:
        card["relay"] = relay
    return card


def _bash_block(lines):
    """Render shell lines as a colored ```bash code block: dim fence, green
    comments, cyan commands. Color applies only when stderr is a TTY (via
    _style), so pipes, copies, and markdown renderers get a plain block."""
    out = [_style("```bash", "2")]
    for ln in lines:
        out.append(_style(ln, "32" if ln.lstrip().startswith("#") else "36"))
    out.append(_style("```", "2"))
    return "\n".join(out)


def _invite_message(u, as_name):
    """Render this user's card as a copy-paste shell snippet that onboards a
    peer: install retalk, point at the relay, create their identity, and add
    you. `#` comments + commands, colored like bash in a terminal."""
    c = _self_card(u, as_name)
    name = c["name"] or "me"
    relay = c.get("relay") or '"<relay-url>"'   # quoted: <> would redirect in a shell
    # NOTE: keep every command line comment-free and every comment on its own
    # line with no ' ( ) ; -- stock macOS zsh has interactive comments OFF, so
    # a trailing # becomes real arguments and an apostrophe swallows the paste.
    return _bash_block([
        "# Message me over retalk, an end-to-end-encrypted messaging CLI.",
        "# 1. Install retalk if not installed yet -- or: uv tool install retalk",
        "pip install -U retalk",
        "# 2. Create your identity. init also prints a reply block to send me.",
        "#    To name the identity, add: -u <your-username>",
        f"retalk init --relay {relay} --passphrase \"<PRIVATE-PASSPHRASE>\"",
        "# 3. Add me as a contact. For a user-specific contact, add: -u <your-username>",
        f"retalk add {c['fingerprint']} --peer {name} --verify",
        "# 4. Send me the reply block that step 2 printed, so I can add you back",
    ])


def _invite_reply(u, as_name):
    """The other half of `--invite-message`: a copy-paste reply for when YOU
    received an invite and set yourself up -- it hands the inviter your
    fingerprint so they can add you back (they already shared the relay)."""
    c = _self_card(u, as_name)
    name = c["name"] or "me"
    return _bash_block([
        "# Got your invite for retalk.",
        "# Add me back. For a user-specific contact, add: --user <your-name>",
        f"retalk add {c['fingerprint']} --peer {name} --verify",
        "# Then we can message each other.",
    ])
def _latest_identity() -> Path | None:
    """The most recently created identity across the global (~/.retalk) and
    project-local (.retalk) stores -- what `retalk id --last` reports right after
    an `init`. Ranks by the `created_at` stamp written at init, falling back to
    the store file's mtime for identities made before that stamp existed."""
    best, best_ts, seen = None, -1.0, set()
    for home in (_data_home(), _local_home()):
        if not home.is_dir():
            continue
        rp = home.resolve()
        if rp in seen:
            continue
        seen.add(rp)
        for child in home.iterdir():
            sdb = child / STORE_FILE
            if not sdb.exists():
                continue
            stamp = _meta(sdb, "created_at")
            try:
                ts = float(stamp) if stamp else sdb.stat().st_mtime
            except (ValueError, OSError):
                ts = sdb.stat().st_mtime
            if ts > best_ts:
                best, best_ts = child, ts
    return best


def cmd_id(args):
    if getattr(args, "last", False):
        latest = _latest_identity()
        if latest is None:
            _die("no identity yet — create one with `retalk init`")
        args.dir = str(latest)        # the most recently created identity
    u = _open_user(args, need_server=False, banner=False)
    if getattr(args, "invite_reply", False):
        print(_invite_reply(u, getattr(args, "as_name", None)))
    elif getattr(args, "invite_message", False):
        print(_invite_message(u, getattr(args, "as_name", None)))
    elif getattr(args, "card", False):                 # human-readable card
        c = _self_card(u, getattr(args, "as_name", None))
        print(f"Name:         {c['name'] or '(unnamed)'}")
        print(f"Fingerprint:  {c['fingerprint']}")
        if c.get("relay"):
            print(f"Relay:        {c['relay']}")
        print(f"Verified:     {'yes' if c.get('verified') else 'no'}")
        print(f"Identity key: {c['identity_key']}")
        print(f"Signing key:  {c['signing_key']}")
    elif args.json:                                    # full Contact card as JSON
        print(json.dumps(_self_card(u, getattr(args, "as_name", None))))
    else:
        print(u.fingerprint())


def _suggest_free_name(taken: set, name: str) -> str:
    """Suggest a free local name near `name` when it's taken: bob -> bob-1,
    bob-1 -> bob-2, and so on."""
    m = re.match(r"^(.*)-(\d+)$", name)
    base, n = (m.group(1), int(m.group(2))) if m else (name, 0)
    while True:
        n += 1
        if f"{base}-{n}" not in taken:
            return f"{base}-{n}"


def cmd_add(args):
    fp = args.fingerprint
    if not ID_RE.match(fp):
        _die("fingerprint must be 32 hex characters")
    name = args.peer
    if name and ID_RE.match(name):
        _die("--peer looks like a user id — give a human name")
    # Target list: the GLOBAL list (shared by every identity) unless an identity
    # is selected via --user/--dir/RETALK_USER. --global forces global and can't
    # be combined with an explicit --user/--dir.
    explicit_user = bool(getattr(args, "dir", None) or getattr(args, "user", None))
    if getattr(args, "glob", False):
        if explicit_user:
            _die("--global and --user/--dir target different lists — pick one")
        store_db = _global_contacts_db()
        where = "the global contacts"
    elif explicit_user or os.environ.get("RETALK_USER"):
        store_db = _resolve_store(args) / STORE_FILE
        where = "your contacts"
    else:
        store_db = _global_contacts_db()
        where = "the global contacts"
    store_db.parent.mkdir(parents=True, exist_ok=True)
    peers = _saved_peers(store_db)            # {fingerprint: (name, ik, sk)}
    # collision: a *different* peer already uses this local name
    if name:
        clash = next((f for f, (nm, _i, _s) in peers.items()
                      if nm == name and f != fp), None)
        if clash and not getattr(args, "override", False):
            alt = _suggest_free_name({nm for (nm, _i, _s) in peers.values() if nm},
                                     name)
            _die(f"a contact named '{name}' already exists (-> {clash}). "
                 f"Pick another name (e.g. '{alt}'), or pass --override to "
                 "replace it")
    had = fp in peers
    # keyed by fingerprint; --override frees the name from any other peer.
    # re-adding resets recorded keys, since they are bound to the fingerprint.
    if name and getattr(args, "override", False):
        _store_sql(store_db, "UPDATE peers SET name=NULL "
                             "WHERE name=? AND fingerprint!=?", name, fp)
    _store_sql(store_db,
               "INSERT INTO peers(fingerprint, name, identity_key, signing_key) "
               "VALUES(?,?,NULL,NULL) ON CONFLICT(fingerprint) DO UPDATE SET "
               "name=excluded.name, identity_key=NULL, signing_key=NULL",
               fp, name)
    ref = name or fp
    print(f"{'Updated' if had else 'Added'} contact "
          f"{(repr(name) + ' ') if name else ''}({fp}) in {where}.",
          file=sys.stderr)
    if getattr(args, "verify", False):
        # verify right away: fetch + pin the two keys (the INSERT above left them
        # NULL). Records into the same list the contact was just added to.
        _record_keys(args, store_db, fp, name)
        return
    print("Next:", file=sys.stderr)
    print(f"  retalk verify {ref}            — check their keys against the relay",
          file=sys.stderr)
    print(f'  retalk send --peer {ref} "hi"  — send them a message',
          file=sys.stderr)
    print( "  retalk contacts              — see all saved peers", file=sys.stderr)


def cmd_contacts(args):
    # Works without an identity: then it shows/manages the GLOBAL list; with an
    # identity it shows the merged view (global + that identity's own).
    user_sel = bool(getattr(args, "dir", None) or getattr(args, "user", None)
                    or os.environ.get("RETALK_USER"))
    store_db = (_resolve_store(args) / STORE_FILE
                if user_sel else _global_contacts_db())
    view = _effective_peers(store_db) if user_sel else _saved_peers(store_db)
    # --remove NAME-OR-ID: delete a contact (the inverse of `add`) from whichever
    # list holds it (this identity's own, else the global list).
    if args.remove is not None:
        if args.show is not None:
            _die("pass --show to view a contact or --remove to delete one, "
                 "not both")
        fp = _resolve_peer(view, args.remove)
        if fp is None or fp not in view:
            _die(f"no saved contact '{args.remove}' to remove")
        target = (_contact_db(store_db, fp) or store_db) if user_sel else store_db
        nm = _saved_peers(target).get(fp, (None,))[0]
        _store_sql(target, "DELETE FROM peers WHERE fingerprint=?", fp)
        scope = "the global" if target == _global_contacts_db() else "your"
        print(f"removed contact {(repr(nm) + ' ') if nm else ''}({fp}) from "
              f"{scope} contacts", file=sys.stderr)
        return
    # --show NAME-OR-ID: just that one contact. As a Contact card with --json
    # (the shareable form `share` sends and `import` ingests), else a single
    # status row. --as relabels the card's recommended nickname.
    if args.show is not None:
        card = _build_card(store_db, args.show, args.as_name)
        if args.json:
            print(json.dumps(card))
        else:
            status = "verified" if card["verified"] else "unverified"
            print(f"{card['name']}\t{card['fingerprint']}\t{status}")
        return
    for fp, (name, ik, sk) in sorted(view.items(),
                                     key=lambda kv: (kv[1][0] or "~", kv[0])):
        verified = bool(ik and sk)
        if args.json:
            print(json.dumps({"name": name or "", "fingerprint": fp,
                              "identity_key": ik or "", "signing_key": sk or "",
                              "verified": verified}))
        else:
            print(f"{name or '(unnamed)'}\t{fp}\t"
                  f"{'verified' if verified else 'unverified'}")


def _record_keys(args, target, fp, label):
    """Record fp's two public keys into `target` after checking they hash to the
    fingerprint, then print the init-styled result block. Keys come from
    --identity-key/--signing-key if given, else the relay (signed by the selected
    or an auto-picked identity). Shared by `verify` and `add --verify`."""
    name = label or fp
    user_sel = bool(getattr(args, "dir", None) or getattr(args, "user", None)
                    or os.environ.get("RETALK_USER"))
    # remember how the USER selected the identity — the relay-fetch branch may
    # mutate args.dir to an auto-picked signer, which must not leak into the
    # follow-up snippet below
    orig_dir = getattr(args, "dir", None)
    orig_user = getattr(args, "user", None) or os.environ.get("RETALK_USER")
    signed_by = None                            # the identity that signed a fetch
    ik_arg, sk_arg = getattr(args, "identity_key", None), getattr(args, "signing_key", None)
    if ik_arg or sk_arg:
        if not (ik_arg and sk_arg):
            _die("manual verify needs both --identity-key and --signing-key: "
                 "the fingerprint is the hash of the two together")
        ik, sk = ik_arg, sk_arg
        got = fingerprint(ik, sk)
        if got != fp:
            _die(f"PIN MISMATCH: the supplied keys hash to {got}, not {fp} -- "
                 "refusing to record them")
        source = "supplied keys"
    else:
        if not user_sel:
            # get_keys is an authenticated, signed relay call, so fetching needs
            # an identity to sign as. Auto-pick one (any works); the contact still
            # records into its list. Lets `verify`/`add --verify` skip --user.
            signer = _pick_signer()
            if signer is None:
                _die("verifying against the relay needs an identity to sign the "
                     "request, and none could be auto-picked: create one with "
                     "`retalk init`, pass --user NAME (-u NAME) to choose which "
                     "signs, or supply the keys with --identity-key/--signing-key")
            args.dir = str(signer)   # sign as this identity; contact stays global
        u = _open_user(args, banner=False)  # fetch needs the relay + passphrase
        signed_by = u.name or _resolve_store(args).name
        try:
            keys = u._call("get_keys", {"peer": fp})
        except Exception as e:
            _die(f"could not fetch {name}'s keys from the relay: {e}")
        ik, sk = keys["identity_key"], keys["signing_key"]
        got = fingerprint(ik, sk)
        if got != fp:
            _die(f"PIN MISMATCH: the relay served keys hashing to {got}, not "
                 f"{fp} -- possible MITM, refusing to record them")
        source = "the relay"

    _store_sql(target, "UPDATE peers SET identity_key=?, signing_key=? "
                       "WHERE fingerprint=?", ik, sk, fp)
    where = ("the global contacts" if target == _global_contacts_db()
             else f"{target.parent.name}'s contacts")
    err = sys.stderr
    print(_style(f"\n✓ Verified {label or fp}", "1;32"), file=err)
    print(f"\nName:        {label or '(unnamed)'}", file=err)
    print(f"Fingerprint: {fp}", file=err)
    print(f"Keys:        from {source}", file=err)
    print(f"Saved to:    {where}", file=err)
    if signed_by:
        print(f"Signed by:   {signed_by}", file=err)
    # follow with a copy-paste block for actually talking to them. Command
    # lines stay comment-free: stock macOS zsh has interactive comments OFF,
    # so a trailing # would turn into real arguments.
    ref = label or fp
    sel = f" --dir {orig_dir}" if orig_dir else ""
    lines = ["# message them:"]
    if not sel:
        lines.append("# RETALK_USER picks the identity that sends:")
        lines.append(f"export RETALK_USER={orig_user}" if orig_user
                     else 'export RETALK_USER="<your-username>"')
    if not os.environ.get("RETALK_PASSPHRASE"):
        lines += ["# and its passphrase, if it has one:",
                  'export RETALK_PASSPHRASE="<YOUR-PASSPHRASE>"']
    lines += [
        f'retalk send --peer {ref} "hello"',
        f"retalk receive --peer {ref} --follow",
    ]
    if sel:
        lines[-2] += sel
        lines[-1] += sel
    lines.append("# receive --follow reads replies live -- ctrl-c to stop")
    print("\n" + _bash_block(lines), file=err)


def cmd_verify(args):
    # Works without an identity: then it verifies a contact in the GLOBAL list.
    # With an identity the merged view is searched and the contact is recorded
    # back into whichever list holds it (this identity's own, else the global).
    user_sel = bool(getattr(args, "dir", None) or getattr(args, "user", None)
                    or os.environ.get("RETALK_USER"))
    store_db = (_resolve_store(args) / STORE_FILE
                if user_sel else _global_contacts_db())
    peers = _effective_peers(store_db) if user_sel else _saved_peers(store_db)
    # the target must already be a saved contact (run `retalk add` first)
    fp = _resolve_peer(peers, args.peer)
    if fp is None or fp not in peers:
        _die(f"no saved contact '{args.peer}': add it first with "
             "`retalk add <fingerprint>`")
    target = (_contact_db(store_db, fp) or store_db) if user_sel else store_db
    _record_keys(args, target, fp, peers[fp][0])


def cmd_share(args):
    store_db = _resolve_store(args) / STORE_FILE
    card = _build_card(store_db, args.contact, args.as_name)
    to = _peer_to_id(args.peer, store_db)
    u = _open_user(args)

    u.sync()                       # keys + resend the unacked outbox along with this one
    mid = u.share(to, card)
    print(json.dumps({"id": mid, "to": to, "shared": card["fingerprint"]}))
    label = card["name"] or card["fingerprint"]
    print(f"shared contact '{label}' ({card['fingerprint']}) with {args.peer}",
          file=sys.stderr)


def _save_card(store_db: Path, card: dict, as_name: str | None) -> tuple:
    """Validate a Contact card and save it as a local peer (like `add`, plus a
    checked `verify` when the card carries keys). Returns (name, fingerprint,
    verified). Raises ValueError(message) on a bad card -- callers decide
    whether that aborts (single import) or just skips one (--inbox)."""
    if not isinstance(card, dict):
        raise ValueError("card must be a JSON object "
                         "(see `retalk contacts --show`)")
    fp = card.get("fingerprint", "")
    if not ID_RE.match(fp):
        raise ValueError("card has no valid fingerprint (expected 32 hex "
                         "characters)")
    name = as_name or card.get("name") or ""
    if not name:
        raise ValueError("card has no recommended nickname -- pass `--as NAME` "
                         "to choose one")
    if ID_RE.match(name):
        raise ValueError("nickname looks like a user id -- give it a human "
                         "name with `--as`")
    ik, sk = card.get("identity_key") or "", card.get("signing_key") or ""
    if ik or sk:
        if not (ik and sk):
            raise ValueError("card has only one key: a verified card needs both "
                             "identity_key and signing_key, or neither")
        got = fingerprint(ik, sk)
        if got != fp:
            raise ValueError(f"PIN MISMATCH: the card's keys hash to {got}, not "
                             f"{fp} -- refusing a contact whose keys do not "
                             "match its id")
    _saved_peers(store_db)  # ensure the table exists
    # save by fingerprint (like `add`); the name is reassigned from any other
    # contact, and re-importing resets the keys
    _store_sql(store_db, "UPDATE peers SET name=NULL "
                         "WHERE name=? AND fingerprint!=?", name, fp)
    _store_sql(store_db,
               "INSERT INTO peers(fingerprint, name, identity_key, signing_key) "
               "VALUES(?,?,NULL,NULL) ON CONFLICT(fingerprint) DO UPDATE SET "
               "name=excluded.name, identity_key=NULL, signing_key=NULL", fp, name)
    if ik and sk:           # record the keys (like a checked `verify`)
        _store_sql(store_db, "UPDATE peers SET identity_key=?, signing_key=? "
                             "WHERE fingerprint=?", ik, sk, fp)
    return name, fp, bool(ik and sk)


def _list_inbox(store_db: Path, as_json: bool):
    """Show the contact-inbox without importing anything."""
    for row in _received_contacts(store_db):
        verified = bool(row["identity_key"] and row["signing_key"])
        if as_json:
            print(json.dumps({**row, "verified": verified}))
        else:
            via = row["from_name"] or row["from_fp"] or "?"
            print(f"{row['name']}\t{row['fingerprint']}\t"
                  f"{'verified' if verified else 'unverified'}\tfrom {via}")


def _import_inbox(store_db: Path, selector: str | None, as_name: str | None):
    """Promote staged contacts (saved by `receive`) into the saved peers, then
    delete the imported rows from the inbox -- a move. With `selector` (a staged
    name or fingerprint) only that contact is imported; otherwise all are. A
    card refused (PIN MISMATCH) is reported and left in the inbox."""
    rows = _received_contacts(store_db)
    if selector is not None:
        rows = [r for r in rows
                if selector in (r["name"], r["fingerprint"])]
        if not rows:
            _die(f"no staged contact matching '{selector}' "
                 "(see `retalk import --inbox --list`)")
    if as_name and len(rows) != 1:
        _die("--as needs exactly one contact: name the staged contact to import")
    if not rows:
        print("import --inbox: inbox empty", file=sys.stderr)
        return
    imported = refused = 0
    for r in rows:
        card = {"fingerprint": r["fingerprint"], "name": r["name"],
                "identity_key": r["identity_key"], "signing_key": r["signing_key"]}
        try:
            name, fp, verified = _save_card(store_db, card, as_name)
        except ValueError as e:
            print(f"retalk: kept staged (not imported): {e}", file=sys.stderr)
            refused += 1
            continue
        _store_sql(store_db, "DELETE FROM received_contacts WHERE fingerprint=?",
                   r["fingerprint"])
        imported += 1
        print(f"imported contact '{name}' ({fp}) "
              f"[{'verified' if verified else 'unverified'}]", file=sys.stderr)
    print(f"import --inbox: {imported} imported, {refused} refused",
          file=sys.stderr)
    if refused:
        sys.exit(2)


def cmd_import(args):
    store_db = _resolve_store(args) / STORE_FILE
    if args.inbox:
        if args.list:
            if args.as_name:
                _die("--as has no meaning with --list (nothing is imported)")
            _list_inbox(store_db, args.json)
            return
        _import_inbox(store_db, args.card, args.as_name)
        return
    if args.list:
        _die("--list only applies to --inbox")
    raw = args.card
    if raw is None or raw == "-":
        raw = sys.stdin.read()
    try:
        card = json.loads(raw)
    except json.JSONDecodeError as e:
        _die(f"card is not valid JSON: {e}")
    try:
        name, fp, verified = _save_card(store_db, card, args.as_name)
    except ValueError as e:
        _die(str(e))
    print(f"imported contact '{name}' ({fp}) "
          f"[{'verified' if verified else 'unverified'}]", file=sys.stderr)


def cmd_block(args):
    d = _resolve_store(args)
    store_db = d / STORE_FILE
    if args.list:
        if args.peer is not None or args.remove:
            _die("give a peer (to block, or --remove to unblock), or --list to "
                 "show the block list -- not both")
        names = {fp: name for fp, (name, _ik, _sk)
                 in _effective_peers(store_db).items()}
        for fp in sorted(_blocked_set(store_db)):
            if args.json:
                print(json.dumps({"fingerprint": fp, "name": names.get(fp, "")}))
            else:
                name = names.get(fp)
                print(f"{fp}\t{name}" if name else fp)
        return
    if args.peer is None:
        _die("block needs a peer (to block, or with --remove to unblock), "
             "or --list to show the block list")
    fp = _peer_to_id(args.peer, store_db)
    _blocked_set(store_db)  # ensure the table exists
    if args.remove:
        # the inverse of a plain block -- formerly `retalk unblock`
        _store_sql(store_db, "DELETE FROM blocked WHERE fingerprint=?", fp)
        print(f"unblocked {args.peer} ({fp})", file=sys.stderr)
    else:
        _store_sql(store_db,
                   "INSERT OR IGNORE INTO blocked(fingerprint) VALUES(?)", fp)
        print(f"blocked {args.peer} ({fp})", file=sys.stderr)


def cmd_group(args):
    store_db = _resolve_store(args) / STORE_FILE
    act = args.action
    mstr = getattr(args, "members_flag", None) or getattr(args, "members", None)

    def resolve_members(refs):
        """Member refs (saved names or raw 32-hex ids) -> fingerprints."""
        peers = _effective_peers(store_db)
        out = []
        for ref in refs:
            fp = _resolve_peer(peers, ref)
            if fp is None:
                _die(f"unknown member '{ref}': use a saved contact name or a "
                     "32-hex fingerprint")
            out.append(fp)
        return out

    if act == "create":
        if not args.name:
            _die("group create needs a NAME")
        if ID_RE.match(args.name):
            _die("group name looks like a fingerprint — pick a human name")
        if _group_by_name(store_db, args.name):
            _die(f"a group named '{args.name}' already exists")
        members = resolve_members(mstr.split(",") if mstr else [])
        if not members:
            _die("a group needs at least one member: --members NAME_OR_ID,...")
        cap = _group_cap(args, store_db)
        if len(set(members)) + 1 > cap:          # the roster counts you too
            _die(f"group too large: {len(set(members)) + 1} users, and this "
                 f"relay allows {cap} (its GET /info max_group_size)")
        gid = uuid.uuid4().hex
        _group_upsert(store_db, gid, args.name, members)
        print(json.dumps({"group_id": gid, "name": args.name,
                          "members": sorted(set(members))}))
        print(f"created group '{args.name}' with {len(set(members))} member(s). "
              f'Send with: retalk send --group {args.name} "hello"',
              file=sys.stderr)
        return

    if act == "list":
        for gid, (name, members) in sorted(_groups(store_db).items(),
                                           key=lambda kv: kv[1][0] or ""):
            if args.json:
                print(json.dumps({"group_id": gid, "name": name,
                                  "members": members}))
            else:
                print(f"{name}\t{gid}\t{len(members)} member(s)")
        return

    if act == "join":
        # clear a leave-tombstone: nothing else — the room reappears with the
        # first message after a member adds this user back
        ref = args.name or ""
        for gid, nm in _left_groups(store_db).items():
            if ref == gid or ref == nm:
                _store_sql(store_db, "DELETE FROM left_groups WHERE gid=?",
                           gid)
                print(f"rejoined '{nm}': ask a member to add you back — the "
                      "room reappears with their next group message",
                      file=sys.stderr)
                return
        _die(f"'{ref}' is not a group you left — see `retalk group list`")

    # every other action names an existing group
    g = _group_by_name(store_db, args.name or "")
    if g is None:
        _die(f"no group '{args.name}' — see `retalk group list`")
    gid, gname, members = g

    if act == "members":
        names = {fp: nm for fp, (nm, _i, _s) in
                 _effective_peers(store_db).items()}
        for fp in members:
            print(f"{names.get(fp) or '(unnamed)'}\t{fp}")
    elif act == "add":
        added = resolve_members(mstr.split(",") if mstr else [])
        if not added:
            _die("group add needs members: retalk group add NAME PEER[,PEER...]")
        cap = _group_cap(args, store_db)
        if len(set(members) | set(added)) + 1 > cap:
            _die(f"group too large: {len(set(members) | set(added)) + 1} "
                 f"users, and this relay allows {cap} (its GET /info "
                 "max_group_size)")
        _group_upsert(store_db, gid, gname, members + added)
        print(f"added {len(set(added) - set(members))} member(s) to '{gname}' "
              "— the new roster reaches everyone on your next group send",
              file=sys.stderr)
    elif act == "remove":
        dropped = set(resolve_members(mstr.split(",") if mstr else []))
        kept = [fp for fp in members if fp not in dropped]
        if kept == members:
            _die("none of those are members — see `retalk group members "
                 f"{gname}`")
        _group_upsert(store_db, gid, gname, kept)
        print(f"removed {len(members) - len(kept)} member(s) from '{gname}' "
              "— cooperative membership: they stop getting YOUR copies now, "
              "and everyone else's after your roster reaches them",
              file=sys.stderr)
    elif act == "rename":
        new = mstr
        if not new:
            _die("group rename needs the new name: retalk group rename OLD NEW")
        if ID_RE.match(new):
            _die("group name looks like a fingerprint — pick a human name")
        if any(nm == new for other, (nm, _m) in _groups(store_db).items()
               if other != gid):
            _die(f"a group named '{new}' already exists")
        _group_upsert(store_db, gid, new, members)
        print(f"renamed group '{gname}' -> '{new}' (your local label only — "
              "the group id stays the same and peers keep their own names)",
              file=sys.stderr)
    elif act == "leave":
        # 1. tell every member over the relay so they stop fanning copies our
        #    way (bandwidth); best-effort — stragglers get refused instead
        u = _open_user(args, need_server=False, banner=False)
        me = u.fingerprint()
        others = [fp for fp in members if fp != me]
        notified = 0
        for fp in others:
            try:
                u.leave_group(fp, gid)
                notified += 1
            except Exception:
                pass
        # 2. tombstone: this room's mail is refused from now on (like a
        #    block, and just as durable — local state, so members forgetting
        #    or a relay reset cannot bring it back)
        _ensure_left(store_db)
        _store_sql(store_db, "INSERT INTO left_groups(gid, name, ts) "
                   "VALUES(?,?,?) ON CONFLICT(gid) DO UPDATE SET "
                   "name=excluded.name, ts=excluded.ts",
                   gid, gname, time.time())
        _store_sql(store_db, "DELETE FROM groups WHERE gid=?", gid)
        print(f"left '{gname}': told {notified}/{len(others)} member(s); "
              "anyone who still sends gets refused automatically. Rejoin "
              f"later with `retalk group join {gname}`", file=sys.stderr)
    elif act == "delete":
        _store_sql(store_db, "DELETE FROM groups WHERE gid=?", gid)
        print(f"deleted group '{gname}' locally (peers keep their own copy)",
              file=sys.stderr)


def cmd_send(args):
    group_ref = getattr(args, "group", None)
    if group_ref and args.peer:
        _die("give --peer or --group, not both")
    if not group_ref and not args.peer:
        _die("send needs a recipient: --peer PEER, or --group NAME")
    u = _open_user(args)
    store_db = _resolve_store(args) / STORE_FILE
    save = _save_messages_on(args)
    if save:
        _warn_unsealed_save(store_db)

    u.sync()                       # keys + resend the unacked outbox along with this one

    if group_ref:                  # fan-out: one pairwise-encrypted copy per member
        g = _group_by_name(store_db, group_ref)
        if g is None:
            _die(f"no group '{group_ref}' — create one with "
                 "`retalk group create NAME --members ...`")
        gid, gname, members = g
        me = u.fingerprint()
        roster = sorted(set(members) | {me})   # envelope roster includes self
        envelope = {"id": gid, "name": gname, "members": roster}
        mid = uuid.uuid4().hex                 # shared thread id across copies
        sent, failed = [], []
        for fp in roster:
            if fp == me:
                continue
            try:
                u.send(fp, args.text, group=envelope, mid=mid)
                sent.append(fp)
            except Exception as e:             # one dead member never blocks the rest
                failed.append((fp, str(e)))
        if save:
            _save_sent(store_db, u, mid, gid, args.text,
                       group={"id": gid, "name": gname})
        print(json.dumps({"id": mid, "group": gname, "group_id": gid,
                          "sent": len(sent), "failed": len(failed)}))
        print(f"sent to group '{gname}' ({len(sent)}/{len(sent) + len(failed)} "
              "members)", file=sys.stderr)
        for fp, err in failed:
            print(f"  ✗ {fp}: {err}", file=sys.stderr)
        if failed:
            sys.exit(2)
        return

    to = _peer_to_id(args.peer, store_db)
    mid = u.send(to, args.text)
    if save:                       # keep our side of the conversation for `history`
        _save_sent(store_db, u, mid, to, args.text)
    print(json.dumps({"id": mid, "to": to}))
    print(f"sent to {args.peer}", file=sys.stderr)


def cmd_receive(args):
    if args.peer and args.all:
        _die("give --peer or --all, not both")
    if not args.peer and not args.all:
        _die("receive needs a target: --peer PEER for one sender, or --all "
             "for every sender")
    u = _open_user(args)
    store_db = _resolve_store(args) / STORE_FILE
    to = None if args.all else _peer_to_id(args.peer, store_db)

    if args.all and not getattr(args, "peers_only", False):
        print(_style(
            "\n⚠ receive --all reads and ACKs mail from EVERY sender — including "
            "ones you never added, each consuming a one-time key.\n"
            "  Prefer --peer <name> for a saved contact, or add --peers-only to "
            "drop strangers.", "1;31"), file=sys.stderr)

    save = _save_messages_on(args)
    if save:
        _warn_unsealed_save(store_db)

    def handle(batch):
        for m in batch:                      # standard message / contact objects
            if args.save_contacts and m.get("kind") == "contact":
                _stage_contact(store_db, m)  # to the inbox for `import --inbox`
                print(json.dumps(m), flush=True)
                continue
            if m.get("kind") == "group_leave":
                # the sender left that room: drop them from the roster so no
                # more copies are fanned out their way
                _apply_group_leave(store_db, m)
                print(json.dumps(m), flush=True)
                continue
            g = m.get("group") if isinstance(m.get("group"), dict) else None
            if g:
                # cooperative membership: adopt the sender's roster (and name)
                # — this also materializes a group you were just added to
                _group_materialize(store_db, g)
            if save and "text" in m:
                _save_message(store_db, u, m)  # sealed copy for `retalk history`
            if g:                            # printed shape: flat group tags
                m = dict(m, group=g.get("name") or "",
                         group_id=g.get("id") or "")
                m.pop("mid", None)  # library-level thread id, not CLI shape
            print(json.dumps(m), flush=True)

    try:
        u.sync(resend=False)          # reachable + fresh keys; reading never resends
        handle(u.receive(to))
        if not args.follow:
            return
        last_sync = time.monotonic()
        while True:
            time.sleep(2)
            handle(u.receive(to))
            if time.monotonic() - last_sync > 60:
                u.sync(resend=False)  # key upkeep only; resends belong to send / `retalk sync`
                last_sync = time.monotonic()
    except KeyboardInterrupt:
        pass


def cmd_history(args):
    u = _open_user(args, need_server=False, banner=False)
    store_db = _resolve_store(args) / STORE_FILE
    _ensure_messages(store_db)
    if args.peer and getattr(args, "group", None):
        _die("give --peer or --group, not both")
    # filter by the OTHER party (peer_fp) or by group, so a conversation shows
    # both the messages you received and the ones you sent.
    if getattr(args, "group", None):
        g = _group_by_name(store_db, args.group)
        if g is None:
            _die(f"no group '{args.group}' — see `retalk group list`")
        where, params = "WHERE gid=? ", [g[0]]
    elif args.peer:
        where, params = "WHERE peer_fp=? ", [_peer_to_id(args.peer, store_db)]
    else:
        where, params = "", []
    rows = _store_sql(store_db,
                      "SELECT msg_id, from_fp, from_name, direction, body, "
                      f"gid, gname FROM messages {where}ORDER BY ts", *params)
    # prefer the current saved-peer name; fall back to the label stored at receive
    names = {fp: nm for fp, (nm, _ik, _sk) in _effective_peers(store_db).items()}
    self_name = u.name or "me"
    for msg_id, from_fp, from_name, direction, body, gid, gname in rows:
        name = self_name if direction == "out" else (names.get(from_fp)
                                                      or from_name)
        rec = {"id": msg_id, "from": from_fp, "name": name,
               "direction": direction or "in",
               "text": u.decrypt_at_rest(body)}
        if gid:
            rec["group"], rec["group_id"] = gname or "", gid
        print(json.dumps(rec), flush=True)


def cmd_show(args):
    """Render a saved conversation as a chat: time + username per message,
    both directions interleaved. `show USER PEER` is the two-party view;
    `show USER --group NAME` renders the whole room, one color per sender.
    Reads only what was saved (send/receive --save); --follow keeps it live by
    polling the relay (saving like `receive --save`) and rendering any new
    saved rows — including ones another terminal writes."""
    args.user = args.show_user            # the positional selects the identity
    args.dir = None
    group_ref = getattr(args, "group", None)
    if group_ref and args.show_peer:
        _die("give PEER or --group, not both")
    if not group_ref and not args.show_peer:
        _die("show needs a conversation: a PEER, or --group NAME")
    store_db = _resolve_store(args) / STORE_FILE
    _ensure_messages(store_db)
    peers = _effective_peers(store_db)
    names = {f: nm for f, (nm, _i, _s) in peers.items() if nm}

    if group_ref:
        g = _group_by_name(store_db, group_ref)
        if g is None:
            _die(f"no group '{group_ref}' — see `retalk group list`")
        gid, gname, members = g
        where, key = "gid=?", gid
        other_label, sub = gname, f"{len(members)} member(s) · {gid}"
        follow_fps = members
    else:
        fp = _resolve_peer(peers, args.show_peer)
        if fp is None:
            _die(f"no saved contact '{args.show_peer}' — add them first with "
                 "`retalk add <fingerprint>`")
        nm = peers[fp][0] if fp in peers else None
        other_label = nm or (args.show_peer if not ID_RE.match(args.show_peer)
                             else fp[:12] + "…")
        where, key, sub = "peer_fp=?", fp, fp
        follow_fps = [fp]
    me = _meta(store_db, "name") or args.show_user
    my_fp = None
    # --follow talks to the relay; a plain show never does
    u = _open_user(args, need_server=bool(args.follow), banner=False)
    my_fp = u.fingerprint()
    follow_fps = [f for f in follow_fps if f != my_fp]

    tty = sys.stdout.isatty()

    def st(t, c):     # like _style, but for stdout (where the chat renders)
        return f"\033[{c}m{t}\033[0m" if tty else t

    # chat layout: peer bubbles on the left, yours on the right — like any
    # messenger. Colors and italics only on a TTY; the layout itself always.
    width = min(shutil.get_terminal_size((80, 24)).columns, 100)
    bubble = max(24, min(56, width - 16))

    title = f" 💬 {st(me, '1;36')} ⇄ {st(other_label, '1;33')} "
    bare = f" 💬 {me} ⇄ {other_label} "
    side = max(2, (width - len(bare) - 1) // 2)     # emoji ≈ 2 columns
    print(st("─" * side, "2") + title + st("─" * side, "2"))
    print(st(sub.center(width), "2"))
    state = {"rowid": 0, "day": None}
    # per-sender look in a group: cycle marker + color by first appearance
    palette = [("🔵", "1;33"), ("🟣", "1;35"), ("🟡", "1;32"),
               ("🟠", "1;34"), ("🔴", "1;31"), ("🟤", "1;36")]
    looks = {}

    def look(sender_fp):
        if sender_fp not in looks:
            looks[sender_fp] = palette[len(looks) % len(palette)]
        return looks[sender_fp]

    def render_new():
        rows = _store_sql(store_db,
                          "SELECT rowid, direction, body, ts, from_fp, "
                          f"from_name FROM messages WHERE {where} AND rowid>? "
                          "ORDER BY ts, rowid", key, state["rowid"])
        for rowid, direction, body, ts, from_fp, from_name in rows:
            state["rowid"] = max(state["rowid"], rowid)
            t = time.localtime(ts or 0)
            day = time.strftime("%Y-%m-%d", t)
            if day != state["day"]:
                print("\n" + st(f"·· 📅 {day} ··".center(width), "2"))
                state["day"] = day
            hhmm = time.strftime("%H:%M", t)
            lines = textwrap.wrap(u.decrypt_at_rest(body), bubble) or [""]
            print()
            if direction == "out":       # you: right-aligned, cyan
                head = f"{hhmm} · {me} 🟢"
                pad = " " * max(0, width - len(head) - 1)
                print(pad + st(hhmm, "2;3") + st(" · ", "2")
                      + st(me, "1;36") + " 🟢")
                for ln in lines:
                    print(" " * max(0, width - len(ln)) + st(ln, "36"))
            else:                        # a peer: left-aligned, own look
                mark, color = (look(from_fp) if group_ref
                               else ("🔵", "1;33"))
                who = (names.get(from_fp) or from_name
                       or (from_fp or "")[:12] + "…") if group_ref \
                    else other_label
                print(f"{mark} " + st(who, color) + st(" · ", "2")
                      + st(hhmm, "2;3"))
                for ln in lines:
                    print("   " + ln)
            sys.stdout.flush()

    render_new()
    if not getattr(args, "follow", False):
        if state["rowid"] == 0:
            print(st("\n(no saved messages — save them with `--save` on send/"
                     "receive, or RETALK_SAVE_MESSAGE=1)", "2"))
        return
    print(st("\n· listening for new messages — ctrl-c to stop ·"
             .center(width), "2;3"), file=sys.stderr)
    try:
        last_sync = time.monotonic()
        while True:
            for sender in follow_fps:     # every roster member in a group
                for m in u.receive(sender):
                    if m.get("kind") == "group_leave":
                        _apply_group_leave(store_db, m)
                        continue
                    if "text" in m:
                        g = (m.get("group")
                             if isinstance(m.get("group"), dict) else None)
                        if g:
                            _group_materialize(store_db, g)
                        _save_message(store_db, u, m)
            render_new()
            time.sleep(2)
            if time.monotonic() - last_sync > 60:
                u.sync(resend=False)      # key upkeep, like receive --follow
                last_sync = time.monotonic()
    except KeyboardInterrupt:
        pass


def cmd_sync(args):
    u = _open_user(args)
    summary = u.sync()                # full pass: keys + flush outbox
    print(json.dumps(summary))        # structured result on stdout
    done = [k for k in ("republished", "replenished", "fallback_rotated")
            if summary[k]]
    if summary["resent"]:
        done.append(f"resent={summary['resent']}")
    print("synced" + (f" ({', '.join(done)})" if done else " (up to date)"),
          file=sys.stderr)


def cmd_register(args):
    u = _open_user(args)
    summary = u.sync(resend=False)        # publish keys + OTKs, no outbox resend
    print(json.dumps(summary))
    done = [k for k in ("republished", "replenished", "fallback_rotated")
            if summary[k]]
    print(f"registered {u.name or u.fingerprint()} on {u.server_url}"
          + (f" ({', '.join(done)})" if done else " (already current)"),
          file=sys.stderr)


def main():
    common = argparse.ArgumentParser(add_help=False)
    raw = argparse.RawDescriptionHelpFormatter

    common = argparse.ArgumentParser(add_help=False)
    g = common.add_argument_group("identity selection (shared by every command)")
    g.add_argument("--dir", metavar="DIR",
                   help="use the identity in directory DIR "
                        "(created earlier by `retalk init --dir DIR`)")
    g.add_argument("-u", "--user", metavar="NAME",
                   help="act as the user named NAME, stored under "
                        "~/.retalk/NAME/. Overrides RETALK_USER")
    g.add_argument("-r", "--relay", metavar="URL",
                   help="relay URL for this invocation; overrides the "
                        "RETALK_RELAY env var and the URL saved at init")
    g.add_argument("--api-key", metavar="KEY",
                   help="relay access key, if the relay requires one; sent as "
                        "an Authorization: Bearer header. Overrides "
                        "RETALK_API_KEY and the value saved at init")
    g.add_argument("-p", "--passphrase", metavar="SECRET",
                   help="passphrase that unlocks this identity's keys; "
                        "overrides RETALK_PASSPHRASE. NOTE: a value passed "
                        "here is visible in the process list and shell "
                        "history -- prefer RETALK_PASSPHRASE for real secrets")
    g.add_argument("-np", "--no-passphrase", action="store_true",
                   help="use no passphrase. On `init` this stores keys "
                        "unencrypted at rest (protected only by file "
                        "permissions); later commands detect it and need none")

    p = argparse.ArgumentParser(
        prog="retalk",
        formatter_class=raw,
        description="""\
End-to-end-encrypted messages between users, relayed by a server that is
never trusted: it stores only public keys and ciphertext, and every
request to it is signed with your key (no accounts, no tokens, no
registration). A "user" is anything with a keypair and a mailbox — an AI
agent, a service, or you.

Your USER ID is a 32-hex fingerprint of your public keys. It is both your
address and your peers' proof of your keys: share it over any channel the
server does not control (chat, email, in person).""",
        epilog="""\
which user every command acts as (first match wins):
  1. --dir DIR           an explicit identity directory
  2. --user / -u NAME    the user named NAME (~/.retalk/NAME/)
  3. RETALK_USER env     same as --user, as an environment variable
  4. otherwise: error — retalk never guesses which user you mean.
Only `retalk init` ever creates an identity; other commands fail loudly when
the selected user has none.

passphrase (required unless the identity was made with --no-passphrase):
  pass --passphrase SECRET, or set RETALK_PASSPHRASE (preferred -- it is not
  visible in the process list). There is no interactive prompt, so commands
  never block waiting on a human.

environment variables:
  RETALK_USER        which user to act as (alternative to --user / -u)
  RETALK_PASSPHRASE  unlocks your keys (alternative to --passphrase)
  RETALK_RELAY       relay to talk to (init can save one per identity instead)
  RETALK_API_KEY     relay access key, if the relay requires one (init can save it)
  RETALK_HOME        where named identities are stored (default ~/.retalk/)

output conventions:
  stdout carries results (ids, messages, --json lines); everything else —
  banners, progress, errors — goes to stderr, so pipes stay clean. Every
  command that acts prints `using <name> (<id>) from <dir>` to stderr
  so you always know which identity acted. Exit codes: 0 ok, 2 usage or
  refusal (no identity, wrong passphrase, unknown peer).

quickstart (your peer runs the same steps on their machine):
  retalk init --user alice --passphrase "<YOUR-PASSPHRASE>"
  # exports: which user to act as + its passphrase -- or pass -u/-p per command
  export RETALK_USER=alice
  export RETALK_PASSPHRASE="<YOUR-PASSPHRASE>"
  retalk add "<bobs-user-id>" --peer bob --verify
  retalk send --peer bob "hello"
  # drop --follow to read just once
  retalk receive --peer bob --follow
  # with no --relay, init uses the public test relay -- no uptime guarantee.
  # use your own via init --relay URL, or: retalk config --relay URL

run `retalk <command> --help` for the full story of each command.""")
    sub = p.add_subparsers(dest="command", required=True,
                           metavar="{init,register,id,add,group,contacts,share,import,verify,block,sync,send,receive,history,show,config}")

    sp = sub.add_parser(
        "init", parents=[common], formatter_class=raw,
        help="create a new identity (the only command that ever does)",
        description="""\
Create a new identity: generate an encryption keypair, encrypt it with a
secret you choose, and store it in a folder of your choosing. Prints the
new USER ID on stdout — share it with peers out-of-band; it is both your
address and the fingerprint they verify you by.

The location is mandatory: --user NAME (stored under
~/.retalk/NAME/) or --dir DIR (an explicit path). The folder will
contain store.db — keys (encrypted), sessions, saved peers, and the
outbox of not-yet-acknowledged messages. Back it up to keep the identity;
delete it to destroy the identity.

Provide the passphrase with --passphrase or the RETALK_PASSPHRASE env var --
there is no prompt. It encrypts your private keys at rest and is required by
every later command, so it cannot be recovered: losing it means losing this
identity and all its conversations. Use --no-passphrase instead to
create an identity with no passphrase (keys then rely on file permissions).

init is offline — it does not contact the server. Keys are published
automatically the first time you send or receive.""",
        epilog="""\
examples:
  retalk init --user alice --passphrase s3cret   encrypted user 'alice'
  retalk init --dir ./alice --no-passphrase   identity in ./alice/
  retalk init --user bot --no-passphrase \\
              --relay https://srv.example.com     agent user, no prompt""")
    sp.add_argument("--display-name", metavar="NAME",
                    help="display name attached to your messages; peers see "
                         "it marked '~NAME' because it is not verified — "
                         "only their locally saved peer name for you is. "
                         "Defaults to the --user / RETALK_USER name")
    sp.add_argument("--no-register", action="store_true",
                    help="don't publish keys to the relay after creating the "
                         "identity (stay offline; keys publish on first "
                         "send/receive, or run `retalk register` later)")
    sp.set_defaults(fn=cmd_init)

    sp = sub.add_parser(
        "id", parents=[common], formatter_class=raw,
        help="print my user id",
        description="""\
Print this identity's USER ID (32 hex chars) on stdout.

The ID is the sha256 fingerprint of your public keys, which makes it
self-verifying: a peer who knows your ID can detect any attempt by the
server to hand out substitute keys for you. Sharing it is therefore
sharing your address and your key fingerprint in one string. It contains
no secret — it is safe to post publicly.

Needs your secret (to open the store) but never contacts the server.

--card prints your OWN Contact card (your address + keys + relay) as JSON for a
peer to `retalk import`; --invite-message renders that card as a copy-paste
message that walks a new peer through installing retalk, setting the relay, and
adding you. `--invite-reply` is the other half -- a paste-back that gives the
inviter your fingerprint so they can add you.""",
        epilog="""\
examples:
  retalk id                    id of the default identity
  retalk id --dir ./alice      id of a project-local identity
  retalk id --card             your own Contact card, human-readable
  retalk id --json             that same card as JSON (the shareable form)
  retalk id --json | retalk import --dir ./bob   hand yourself to another identity
  retalk id --invite-message   a copy-paste invite to onboard a peer out-of-band
  retalk id --invite-message --as bob   suggest the name the peer saves you as
  retalk id --invite-reply     reply to an invite -- hand your id to whoever invited you""")
    sp.add_argument("--json", action="store_true",
                    help="emit your OWN Contact card as JSON (fingerprint, name, "
                         "identity_key, signing_key, verified, relay) -- the "
                         "shareable form of your identity; a peer saves it with "
                         "`retalk import`")
    sp.add_argument("--card", action="store_true",
                    help="print your OWN Contact card in a human-readable form "
                         "(use --json to pipe it to `retalk import`)")
    sp.add_argument("--invite-message", dest="invite_message",
                    action="store_true",
                    help="render your card as a copy-paste invite (install + "
                         "relay + add-me steps) to onboard a peer out-of-band")
    sp.add_argument("--invite-reply", dest="invite_reply", action="store_true",
                    help="render a copy-paste REPLY to an invite: hand the "
                         "inviter your fingerprint so they can add you back")
    sp.add_argument("--as", dest="as_name", metavar="NAME",
                    help="with --card/--invite-message/--invite-reply: the "
                         "nickname you suggest the peer save you under (default: "
                         "your display name)")
    sp.add_argument("--last", action="store_true",
                    help="use the most recently created identity (the one `retalk "
                         "init` just made), instead of naming it with --user/--dir")
    sp.set_defaults(fn=cmd_id)

    sp = sub.add_parser(
        "add", parents=[common], formatter_class=raw,
        help="save a peer's user id, optionally under a local name",
        description="""\
Save a peer's USER ID (a 32-hex fingerprint) as a contact. Optionally label it
with --peer, so `send bob ...` works and incoming messages from that ID display
as 'bob' instead of an unverified '~name'. Without --peer the contact has no
local label — refer to it by fingerprint, or by the peer's own '~name'. The
name is yours alone — it never travels over the network and the peer never
learns it.

Get the peer's ID out-of-band (they run `retalk id`). If --peer is already taken
by another contact, `add` errors and suggests a free one; pass --override to
reassign it. No secret needed and no server contact — this only writes your
local peers table.""",
        epilog="""\
examples:
  retalk add f1041c25c87351d8550b31cc6b13ab04
  retalk add f1041c25c87351d8550b31cc6b13ab04 --peer bob

This saves an incomplete contact -- just the fingerprint (and name). The peer's
keys are fetched and verified automatically the first time you message them;
run `retalk verify <name-or-fingerprint>` to do that explicitly now (see
`retalk verify --help`).""")
    sp.add_argument("fingerprint", help="the peer's 32-hex fingerprint (user id)")
    sp.add_argument("--peer", metavar="PEER",
                    help="optional local label for this peer (e.g. 'bob'); "
                         "default: none — refer to them by fingerprint or ~name")
    sp.add_argument("--override", action="store_true",
                    help="reassign --peer from another contact that already has "
                         "it (default: error if the name is taken)")
    sp.add_argument("--global", dest="glob", action="store_true",
                    help="save to the owner-wide global contact list shared by "
                         "every identity (the default when no identity is "
                         "selected); cannot be combined with --user/--dir")
    sp.add_argument("--verify", action="store_true",
                    help="immediately verify the new contact: fetch their two "
                         "keys from the relay and pin them (same as running "
                         "`retalk verify` right after)")
    sp.set_defaults(fn=cmd_add)

    sp = sub.add_parser(
        "verify", parents=[common], formatter_class=raw,
        help="record a saved peer's keys (explicit first contact)",
        description="""\
Record a saved peer's public keys, turning an incomplete contact (name +
fingerprint, from `retalk add`) into a verified one. This makes EXPLICIT the
key exchange that otherwise happens implicitly the first time you send to or
receive from that peer.

By default the keys are fetched from the relay. Pass --identity-key and
--signing-key together to supply them manually instead (e.g. obtained
out-of-band). Either way they are checked against the saved fingerprint: if
they do not hash to it, verify refuses with PIN MISMATCH and records nothing.

On success the identity_key and signing_key are stored locally (shown by
`retalk contacts`), and the identity key becomes a pin checked on every later
exchange. Verifying is optional -- send and receive still work on the
fingerprint alone, verifying keys on the fly. The peer must already exist
(`retalk add`); fetching from the relay also needs your passphrase.""",
        epilog="""\
examples:
  retalk verify bob                    fetch bob's keys from the relay, record them
  retalk verify bob \\
         --identity-key K --signing-key S    record keys you already hold
  retalk verify f1041c25c87351d8550b31cc6b13ab04   target by raw fingerprint""")
    sp.add_argument("peer", help="a saved peer name or 32-hex fingerprint; "
                                 "must already exist via `retalk add`")
    sp.add_argument("--identity-key", metavar="KEY",
                    help="record this base64 identity key instead of fetching "
                         "from the relay (requires --signing-key)")
    sp.add_argument("--signing-key", metavar="KEY",
                    help="record this base64 signing key instead of fetching "
                         "from the relay (requires --identity-key)")
    sp.set_defaults(fn=cmd_verify)

    sp = sub.add_parser(
        "contacts", parents=[common], formatter_class=raw,
        help="list saved peers; --show one as a Contact card, --remove one",
        description="""\
List the peers you have saved with `retalk add`, one per line as
NAME<tab>FINGERPRINT<tab>STATUS (verified or unverified), sorted by name. These
local names never leave your machine, and the peer never learns them.

A peer is "verified" once its keys have been recorded with `retalk verify`;
until then it is an incomplete contact (just name + fingerprint). With --json
each line is a Contact object (see docs/STANDARD.md): {"name", "fingerprint",
"identity_key", "signing_key", "verified"}, where the key fields are "" until
the peer is verified.

Pass --show NAME-OR-ID to print just one contact instead of the whole list:
its status row by default, or -- with --json -- its full Contact card, the
shareable form `retalk share` sends over the relay and `retalk import` ingests.
You can hand that card over any out-of-band channel (paste it, pipe it) and have
the other side import it. --show also accepts a raw 32-hex user id you have not
saved, emitting a minimal (unverified) card; --as relabels the recommended
nickname the recipient sees.

Pass --remove NAME-OR-ID to delete a saved peer (the inverse of `retalk add`);
a fingerprint drops every name pinned to it. Removing nothing is an error.

No passphrase and no server contact -- this only reads/writes your local peers
table. Prints nothing when you have saved no peers.""",
        epilog="""\
examples:  (each assumes a selected user: RETALK_USER set, or add -u NAME / --dir DIR)
  retalk contacts                  list saved peers as NAME<tab>FINGERPRINT<tab>STATUS
  retalk contacts --json           one Contact object (see docs/STANDARD.md) per line
  retalk contacts --json | jq .    pretty-print every contact
  retalk contacts --show bob       bob's status row (name, id, verified?)
  retalk contacts --show bob --json          bob's full Contact card, one JSON line
  retalk contacts --show bob --json --as bobby   recommend the nickname 'bobby'
  retalk contacts --show bob --json | retalk import --dir ./carol   copy bob over
  retalk contacts --remove bob     forget the saved peer 'bob'""")
    sp.add_argument("--json", action="store_true",
                    help="emit Contact objects (see docs/STANDARD.md: name, "
                         "fingerprint, identity_key, signing_key, verified) "
                         "instead of status rows; with --show, the full card")
    sp.add_argument("--show", metavar="CONTACT",
                    help="print just this contact (a saved peer name or a "
                         "32-hex user id) instead of the whole list; add --json "
                         "for its shareable Contact card")
    sp.add_argument("--remove", metavar="CONTACT",
                    help="delete this saved peer (a name or 32-hex user id) "
                         "from your contacts; the inverse of `retalk add`")
    sp.add_argument("--as", dest="as_name", metavar="NAME",
                    help="with --show: recommended nickname to put in the card "
                         "(default: the saved peer name)")
    sp.set_defaults(fn=cmd_contacts)

    sp = sub.add_parser(
        "share", parents=[common], formatter_class=raw,
        help="send a saved contact to a peer (an introduction)",
        description="""\
Introduce one of your contacts to a peer: build that contact's Contact card
(the same JSON `retalk contacts --show CONTACT --json` prints) and send it,
encrypted, to the recipient over the relay. The recipient sees it in `retalk
receive` as a contact record and saves it with `retalk import`, under the
nickname you recommend.

`--peer` is the recipient: a saved peer name (from `retalk add`) or a raw
32-hex user id. The positional CONTACT is the contact you are sharing, likewise
a saved peer name or a raw user id; `--as NAME` overrides the recommended
nickname (default: the contact's saved name). The card carries the contact's
keys only if you have verified them; either way the recipient re-checks the
keys against the fingerprint, so a tampered card is refused, never trusted.

Like `send`, delivery is tracked: the card stays in your outbox until the
recipient's client acknowledges it. Prints a JSON receipt on stdout --
{"id", "to", "shared"} -- where `shared` is the shared contact's fingerprint.""",
        epilog="""\
examples:
  retalk share --peer carol bob              introduce bob to carol
  retalk share --peer carol bob --as bobby   recommend the nickname 'bobby'
  retalk share --peer carol f1041c25c87351d8550b31cc6b13ab04 --as dave""")
    sp.add_argument("--peer", metavar="PEER", required=True,
                    help="recipient of the introduction: a saved peer name "
                         "(from `retalk add`) or a raw 32-hex user id")
    sp.add_argument("contact",
                    help="the contact to share: a saved peer name or a 32-hex "
                         "user id")
    sp.add_argument("--as", dest="as_name", metavar="NAME",
                    help="recommended nickname to put in the card "
                         "(default: the contact's saved name)")
    sp.set_defaults(fn=cmd_share)

    sp = sub.add_parser(
        "import", parents=[common], formatter_class=raw,
        help="save a contact from a shared Contact card",
        description="""\
Save a contact from a Contact card -- the JSON that `retalk contacts --show
CONTACT --json` prints and `retalk share` sends (the `card` object of a received
contact record). The card
is saved as a peer under its recommended nickname, exactly as if you had run
`retalk add` (and `retalk verify`, when the card carries keys).

The card comes from the CARD argument, or from stdin when CARD is omitted or
"-". The nickname is the card's `name`, or `--as NAME` to choose your own
(required when the card has no name). If the card includes keys, they must hash
to its fingerprint -- otherwise import refuses with PIN MISMATCH and saves
nothing; a card with no keys is saved as an unverified contact (verified on
first contact).

With --inbox, import draws instead from the contact-inbox: the cards that
`retalk receive` saved when peers shared contacts with you (`retalk share`).
Plain `import --inbox` promotes every staged contact into your saved peers and
removes it from the inbox (a move); `import --inbox NAME-OR-ID` imports just the
one matching a staged name or fingerprint; `import --inbox --list` shows the
inbox without importing anything. A staged card that fails its key check is
reported and left in the inbox. The same PIN-MISMATCH rule applies.

No passphrase and no server contact -- this only reads/writes local tables.""",
        epilog="""\
examples:
  retalk import '{"fingerprint":"f104...","name":"bob","identity_key":"..","signing_key":".."}'
  retalk import --as bobby '<card json>'     save it under a nickname of your own
  retalk import --inbox --list               show contacts peers shared with you
  retalk import --inbox                       save all of them as peers
  retalk import --inbox bob --as bobby        save just "bob", under your own name""")
    sp.add_argument("card", nargs="?",
                    help="without --inbox: the Contact card as a JSON string "
                         "(omit or '-' to read stdin). With --inbox: an optional "
                         "staged name or fingerprint to import just that one")
    sp.add_argument("--as", dest="as_name", metavar="NAME",
                    help="nickname to save the contact under "
                         "(default: the card's recommended name)")
    sp.add_argument("--inbox", action="store_true",
                    help="import from the contact-inbox (cards `receive` saved) "
                         "rather than from a CARD")
    sp.add_argument("--list", action="store_true",
                    help="with --inbox: list the staged contacts and import "
                         "nothing")
    sp.add_argument("--json", action="store_true",
                    help="with --inbox --list: emit one JSON object per staged "
                         "contact")
    sp.set_defaults(fn=cmd_import)

    sp = sub.add_parser(
        "block", parents=[common], formatter_class=raw,
        help="silently drop a sender's messages (--remove to undo, --list them)",
        description="""\
Block a sender: their incoming messages are dropped during `receive` before
any decryption happens, so a blocked sender can never even consume one of your
one-time keys. The block is local to this identity's store and is never sent to
the server or the peer; their mail simply stays on the server, unread.

Name the sender by a saved peer name (from `retalk add`) or a raw 32-hex user
id. Pass --remove with the same name/id to take a sender back off the block list
(so `receive` delivers their messages again); removing one that is not blocked
is a no-op. Pass --list (instead of a peer) to print the current block list, one
per line with the saved peer name if any; --json emits one object per line.""",
        epilog="""\
examples:
  retalk block bob                              block a saved peer
  retalk block f1041c25c87351d8550b31cc6b13ab04   block by raw id
  retalk block --remove bob                     unblock a sender
  retalk block --list                           show the block list
  retalk block --list --json     one {"fingerprint","name"} object per line""")
    sp.add_argument("peer", nargs="?",
                    help="saved peer name or 32-hex user id to block (or, with "
                         "--remove, to unblock); omit with --list")
    sp.add_argument("--remove", action="store_true",
                    help="remove the named sender from the block list instead "
                         "of adding one")
    sp.add_argument("--list", action="store_true",
                    help="list blocked senders instead of blocking one")
    sp.add_argument("--json", action="store_true",
                    help="with --list: emit one JSON object per blocked sender")
    sp.set_defaults(fn=cmd_block)

    sp = sub.add_parser(
        "sync", parents=[common], formatter_class=raw,
        help="reconcile this identity with the relay (keys + outbox)",
        description="""\
Run one reconciliation pass against the relay — the same upkeep `send` does
and `receive` does (minus resending): (re)publish your keys if the relay has
forgotten them, replenish one-time keys, rotate the fallback key if stale,
and re-send any unacknowledged outbox messages.

Reading (`receive`) never resends; sending and `sync` do. So run `sync` from
cron or a timer for a mostly-listening client, to retry stuck outgoing
messages without relying on the next `send`.""",
        epilog="""\
examples:
  retalk sync                 reconcile keys + flush the outbox
  */5 * * * * retalk sync     retry pending sends every 5 minutes (cron)""")
    sp.set_defaults(fn=cmd_sync)

    sp = sub.add_parser(
        "register", parents=[common], formatter_class=raw,
        help="publish this identity's keys to the relay (make it reachable)",
        description="""\
Publish your keys to the relay so peers can reach you: (re)publish your public
keys, replenish one-time keys, and rotate the fallback if stale. `retalk init`
does this automatically unless you pass --no-register; run `register` to (re)do
it explicitly, e.g. after switching relays. Like `sync`, but it never resends
the outbox.""",
        epilog="""\
examples:
  retalk register             publish your keys to the relay""")
    sp.set_defaults(fn=cmd_register)

    sp = sub.add_parser(
        "send", parents=[common], formatter_class=raw,
        help="encrypt and send one message",
        description="""\
Encrypt TEXT for one peer and hand the ciphertext to the server, then
exit. The server (and anyone watching it) sees only the ciphertext and
the metadata sender/recipient/time/size — never the content.

The `--peer` value is a name saved with `retalk add`, or a raw 32-hex id. The
first message to a new peer performs the key handshake automatically
(claiming one of the peer's one-time keys from the server); if the
server's served keys do not match the peer's ID fingerprint or the keys you
recorded with `retalk verify`, the send refuses with PIN MISMATCH instead of
encrypting an impostor key.

Delivery is tracked: the message stays in your local outbox until the
peer's client acknowledges decrypting it (acks arrive during your next
`receive`). Each `send` also re-uploads any still-unacknowledged outbox
mail (and `retalk sync` does the same), so nothing is lost if the server
dies or is swapped; a recipient who already has a copy just re-acks it. On
first contact with a server your public keys are published automatically.

Prints a JSON receipt on stdout -- {"id", "to"} (see docs/STANDARD.md); the
id matches the one the recipient will see.""",
        epilog="""\
examples:
  retalk send --peer bob "hello"
  retalk send --peer f1041c25c87351d8550b31cc6b13ab04 "hi, stranger"
  retalk send --group team "standup in 5"
  retalk send --peer bob "psst" --dir ./alice --relay http://127.0.0.1:8766""")
    sp.add_argument("--peer", metavar="PEER",
                    help="recipient: a saved peer name (from `retalk add`) "
                         "or a raw 32-hex user id")
    sp.add_argument("--group", metavar="NAME",
                    help="send to a group instead: one pairwise-encrypted copy "
                         "per member (see `retalk group --help`); cannot be "
                         "combined with --peer")
    sp.add_argument("text", help="the message plaintext (quote it)")
    sp.add_argument("--save", dest="save_messages", action="store_true",
                    help="also keep a sealed local copy of THIS sent message, so "
                         "`retalk history` shows both sides of the conversation. "
                         "Off by default; RETALK_SAVE_MESSAGE=1 turns it on for "
                         "every command")
    sp.set_defaults(fn=cmd_send)

    sp = sub.add_parser(
        "receive", parents=[common], formatter_class=raw,
        help="decrypt pending messages",
        description="""\
Fetch pending messages from the server, decrypt them, and print each as one
JSON object per line (NDJSON) on stdout -- see docs/STANDARD.md for the fields
({"id", "from", "name", "text"}). A contact shared with `retalk share` arrives
as a contact record instead ({"id", "from", "name", "kind": "contact", "card":
{...}}); it is also saved to the contact-inbox (unless --no-save-contacts) for
`retalk import --inbox`. Each decrypted message is acknowledged back to its
sender (encrypted, like everything else).

Say whose messages to read: pass --peer PEER (a saved name or 32-hex user id)
to read just that sender -- this is the recommended default, and leaves
everyone else's mail in the mailbox for a later receive. --all instead drains
*every* sender at once, including strangers you never added (each spends a
one-time key), so use it deliberately; add --peers-only to drop strangers.

Without --follow: drain the mailbox once and exit (good for cron and
scripts). With --follow: poll every 2 seconds until interrupted, and once
a minute run key maintenance — replenish one-time keys on the server and
rotate the fallback key daily. Reading never resends your outbox; `send`
and `retalk sync` do that.

Messages the server already handed over are never served again, so pipe
--json output somewhere durable if you need a log.

Two filters drop senders before any decryption (so they never make you
consume a one-time key): a blocked sender (`retalk block`) is always dropped,
and with --peers-only only saved peers (`retalk add`) are accepted.""",
        epilog="""\
examples:
  retalk receive --peer bob            read only messages from bob (recommended)
  retalk receive --peer bob --follow   live tail of bob + key upkeep
  retalk receive --all --peers-only    read all saved contacts at once, drop strangers
  retalk receive --peer bob | jq .text      pipe the JSON lines to jq
  retalk receive --peer bob ; retalk import --inbox --list   read, then see staged contacts

each line is a JSON message object (see docs/STANDARD.md): "id", "from",
"name", "text" -- or a contact record with "kind":"contact" and "card".
Contacts peers share are also saved to the contact-inbox (see
`retalk import --inbox`); pass --no-save-contacts to skip that.""")
    sp.add_argument("--peer", metavar="PEER",
                    help="read only this peer's messages (a saved peer name "
                         "or a 32-hex user id); the recommended default")
    sp.add_argument("--all", action="store_true",
                    help="read messages from every sender (the whole mailbox) "
                         "instead of targeting one peer. This drains and acks "
                         "*every* sender at once, including strangers (each "
                         "spends a one-time key), so prefer --peer; pair with "
                         "--peers-only to drop strangers")
    sp.add_argument("--follow", action="store_true",
                    help="keep polling every 2s and maintain keys every "
                         "60s until ctrl-c")
    sp.add_argument("--peers-only", action="store_true",
                    help="accept mail only from saved peers (`retalk add`); "
                         "messages from unknown senders are dropped before "
                         "any decryption, so they never consume a one-time "
                         "key. Blocked senders (`retalk block`) are always "
                         "dropped regardless of this flag")
    sp.add_argument("--no-save-contacts", dest="save_contacts",
                    action="store_false",
                    help="do not save contacts that peers share with you "
                         "(`retalk share`) to the contact-inbox; by default they "
                         "are staged there for `retalk import --inbox`")
    sp.add_argument("--save", dest="save_messages", action="store_true",
                    help="also keep a local copy of each RECEIVED chat message, "
                         "sealed with this identity's key, for `retalk history`. "
                         "Off by default (retalk keeps no message log otherwise); "
                         "RETALK_SAVE_MESSAGE=1 turns it on for every command. On "
                         "a --no-passphrase identity the seal is not real "
                         "encryption -- the store key is public")
    sp.set_defaults(fn=cmd_receive, save_contacts=True)

    sp = sub.add_parser(
        "history", parents=[common], formatter_class=raw,
        help="replay messages saved by `send`/`receive --save`",
        description="""\
Print the messages this identity has saved (with `send --save` and
`receive --save`), oldest first, as one JSON object per line (NDJSON):
the Message shape `receive` emits plus a `direction` field --
{"id", "from", "name", "direction", "text"}, where direction is "in" (received)
or "out" (sent). Both sides of a conversation are interleaved by time. Each body
is decrypted from its at-rest seal on the way out, so this needs the identity's
passphrase but never the relay.

retalk keeps no message log unless you opt in -- per command with
--save, or for every command with RETALK_SAVE_MESSAGE=1. With `--peer`,
only the conversation with that peer is shown (both directions).""",
        epilog="""\
examples:
  retalk history                 every saved message, oldest first
  retalk history --peer bob      the whole conversation with bob (sent + received)
  retalk history | jq -r .text   just the text of each""")
    sp.add_argument("--peer", metavar="PEER",
                    help="show only the conversation with this peer, both "
                         "directions (a saved peer name or a 32-hex user id)")
    sp.add_argument("--group", metavar="NAME",
                    help="show only this group's messages (see "
                         "`retalk group list`); cannot be combined with --peer")
    sp.set_defaults(fn=cmd_history)

    sp = sub.add_parser(
        "config", formatter_class=raw,
        help="show or set owner-wide defaults (e.g. the default relay)",
        description="""\
Read or write owner-wide defaults in ~/.retalk/config.json (a JSON object).
These apply to every identity as the LAST fallback: a --relay flag, RETALK_RELAY,
and a relay saved in an identity all override them. With no flags, print the
current config. RETALK_HOME relocates the file with the rest of the store.""",
        epilog="""\
examples:
  retalk config                                    show owner-wide config
  retalk config --relay https://relay.example.com  set the default relay
  retalk config --relay ""                         clear the default relay""")
    sp.add_argument("-r", "--relay", metavar="URL",
                    help="set the owner-wide default relay URL; pass an empty "
                         "string to clear it")
    sp.set_defaults(fn=cmd_config)

    sp = sub.add_parser(
        "show", parents=[common], formatter_class=raw,
        help="render the saved conversation with a peer as a chat",
        description="""\
Render the conversation between USER and PEER as a chat — a time and username
per message, both directions interleaved, dated. It reads only the messages
that were SAVED (send/receive --save, or RETALK_SAVE_MESSAGE=1): retalk keeps
no log unless you opt in, so `show` displays exactly what was kept.

With --follow the chat stays live: it polls the relay for PEER's new mail
(saving each message like `receive --save` does) and renders new saved rows —
including ones another terminal writes — until ctrl-c. A plain `show` never
contacts the relay.""",
        epilog="""\
examples:
  retalk show alice bob
  retalk show alice bob --follow
  retalk show alice --group team --follow""")
    sp.add_argument("show_user", metavar="USER",
                    help="the identity whose saved conversation to render")
    sp.add_argument("show_peer", metavar="PEER", nargs="?",
                    help="the other party: a saved peer name or 32-hex id")
    sp.add_argument("--group", metavar="NAME",
                    help="render this group's room instead of a two-party "
                         "chat: every sender gets their own color; --follow "
                         "polls every member for new mail")
    sp.add_argument("--follow", action="store_true",
                    help="keep polling for new messages and render them as "
                         "they arrive (ctrl-c to stop)")
    sp.set_defaults(fn=cmd_show)

    sp = sub.add_parser(
        "group", parents=[common], formatter_class=raw,
        help="manage groups (client-side fan-out group chat)",
        description="""\
Group chat, retalk style: a group is a LOCAL roster of fingerprints, and
`retalk send --group NAME` encrypts one pairwise copy per member — the relay
never learns the roster (it just sees N ordinary messages). Each copy carries
the roster inside the encrypted envelope, so receivers materialize the group
automatically, can reply to everyone, and adopt roster changes (cooperative
membership: the last sender's roster wins; there are no admins).""",
        epilog="""\
examples:
  retalk group create team --members bob,carol
  retalk group list
  retalk group members team
  retalk group add team dave
  retalk group remove team carol
  retalk group rename team work-team
  retalk group leave team
  retalk group join team
  retalk group delete team
  retalk send --group team "standup in 5"
  retalk show alice --group team --follow""")
    sp.add_argument("action", metavar="ACTION",
                    choices=["create", "list", "members", "add", "remove",
                             "rename", "leave", "join", "delete"],
                    help="one of: create, list, members, add, remove, "
                         "rename, leave, join, delete")
    sp.add_argument("name", metavar="NAME", nargs="?",
                    help="the group's local name (every action except list)")
    sp.add_argument("members", metavar="MEMBERS", nargs="?",
                    help="comma-separated saved contact names or 32-hex ids "
                         "(for add/remove; create also accepts --members)")
    sp.add_argument("--members", dest="members_flag", metavar="LIST",
                    help="comma-separated members, e.g. --members bob,carol")
    sp.add_argument("--json", action="store_true",
                    help="with list: one JSON object per group")
    sp.set_defaults(fn=cmd_group)

    args = p.parse_args()
    try:
        args.fn(args)
    except urllib.error.URLError as e:
        # The relay could not be reached at all (DNS failure, connection
        # refused, timeout, TLS). HTTP-level errors are already turned into
        # clean messages by the relay layer; without this, an unreachable
        # relay dumps a raw traceback at the user.
        _die("could not reach the relay: "
             f"{getattr(e, 'reason', None) or e}\n"
             "  - check the relay URL (--relay, RETALK_RELAY, or the one saved at init)\n"
             "  - check your network\n"
             "  - nothing is lost: queued sends stay in the outbox and go out on\n"
             "    the next successful command (e.g. `retalk sync`)")
    except (ConnectionError, TimeoutError) as e:
        _die(f"connection to the relay failed: {e} — retry (e.g. `retalk sync`) "
             "once the relay is reachable")
    except RuntimeError as e:
        # relay-layer errors arrive as RuntimeError with a ready-made message
        # (e.g. "server error from claim_key: unknown peer or no published
        # keys"); print it cleanly instead of dumping a traceback.
        _die(str(e))


if __name__ == "__main__":
    main()
