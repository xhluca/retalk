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
import sqlite3
import sys
import time
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


def _die(msg: str, code: int = 2):
    print(f"retalk: {msg}", file=sys.stderr)
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
    _die("no passphrase: pass --passphrase SECRET, set RETALK_PASSPHRASE, or "
         "use --no-passphrase for an identity with no passphrase")


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
    """Return {name: (fingerprint, identity_key, signing_key)} for saved peers.

    A peer added with `retalk add` has only name + fingerprint; identity_key
    and signing_key stay NULL until `retalk verify` records them, so a peer is
    "verified" exactly when both keys are present."""
    _store_sql(store_db, "CREATE TABLE IF NOT EXISTS peers("
                         "name TEXT PRIMARY KEY, fingerprint TEXT, "
                         "identity_key TEXT, signing_key TEXT)")
    # migrate older stores that named these columns id / pin
    cols = [r[1] for r in _store_sql(store_db, "PRAGMA table_info(peers)")]
    if "id" in cols and "fingerprint" not in cols:
        _store_sql(store_db, "ALTER TABLE peers RENAME COLUMN id TO fingerprint")
    if "pin" in cols and "identity_key" not in cols:
        _store_sql(store_db,
                   "ALTER TABLE peers RENAME COLUMN pin TO identity_key")
    if "signing_key" not in cols:  # pre-verify stores lack the cached signing key
        try:
            _store_sql(store_db, "ALTER TABLE peers ADD COLUMN signing_key TEXT")
        except sqlite3.OperationalError:
            pass  # already present (added concurrently)
    return {name: (fp, ik, sk) for name, fp, ik, sk in
            _store_sql(store_db, "SELECT name, fingerprint, identity_key, "
                                 "signing_key FROM peers")}


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


def _ensure_messages(store_db: Path):
    _store_sql(store_db, "CREATE TABLE IF NOT EXISTS messages("
               "msg_id TEXT PRIMARY KEY, from_fp TEXT, from_name TEXT, "
               "body TEXT, ts REAL)")


def _save_message(store_db: Path, u, rec: dict):
    """Persist one chat message (`receive --save-messages`) with its body
    sealed at rest by the identity's key (see User.encrypt_at_rest)."""
    _ensure_messages(store_db)
    _store_sql(store_db,
               "INSERT OR IGNORE INTO messages(msg_id, from_fp, from_name, "
               "body, ts) VALUES(?,?,?,?,?)",
               rec.get("id") or "", rec.get("from") or "",
               rec.get("name") or "", u.encrypt_at_rest(rec.get("text") or ""),
               time.time())


def _open_user(args, need_server: bool = True, banner: bool = True) -> User:
    d = _resolve_store(args)
    store_db = d / STORE_FILE
    secret, _ = _resolve_passphrase(args, store_db=store_db)
    server = (getattr(args, "relay", None) or os.environ.get("RETALK_RELAY")
              or _meta(store_db, "server_url") or _default_relay())
    if need_server and not server:
        _die("no relay URL: pass --relay, set RETALK_RELAY, or save one "
             "at init time")
    peers = _saved_peers(store_db)
    identity_keys = {fp: ik for _, (fp, ik, _sk) in peers.items() if ik}
    names = {fp: name for name, (fp, _ik, _sk) in peers.items()}
    known = {fp for _, (fp, _ik, _sk) in peers.items()}
    blocked = _blocked_set(store_db)
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
                 api_key=api_key)
    except Exception:
        _die(f"could not unlock the identity at {d} (wrong passphrase?)")
    if banner:
        print(f"using {u.name or 'user'} ({u.fingerprint()}) from {d}",
              file=sys.stderr)
    return u


def _peer_to_id(peer: str, store_db: Path) -> str:
    peers = _saved_peers(store_db)
    if peer in peers:
        return peers[peer][0]
    if ID_RE.match(peer):
        return peer
    _die(f"unknown peer '{peer}': `retalk add {peer} <user-id>` first, "
         "or pass a 32-hex user id")


def _build_card(store_db: Path, contact: str, as_name: str | None) -> dict:
    """Build a Contact card (see docs/STANDARD.md) for `contact` -- a saved
    peer name or a raw 32-hex fingerprint -- for `contacts --show` or `share`.

    The recommended nickname is `as_name` if given, else the saved peer name,
    else "". The identity_key/signing_key are filled in only when the contact
    is a verified saved peer; otherwise they stay "" and the card is shared
    unverified (the recipient verifies on first contact, as always)."""
    peers = _saved_peers(store_db)
    if contact in peers:                      # a saved peer name
        fp, ik, sk = peers[contact]
        name = as_name or contact
    elif ID_RE.match(contact):                # a raw fingerprint
        match = [(n, ik, sk) for n, (pfp, ik, sk) in peers.items()
                 if pfp == contact]
        if match:                             # ...that is also a saved peer
            saved_name, ik, sk = match[0]
            name = as_name or saved_name
        else:                                 # ...not saved: keys unknown
            name, ik, sk = (as_name or ""), None, None
        fp = contact
    else:
        _die(f"unknown contact '{contact}': save it with "
             f"`retalk add {contact} <user-id>`, or pass a 32-hex user id")
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
    # Best-effort: a failure never blocks init (keys also publish lazily on the
    # first send/receive).
    if server and not getattr(args, "no_register", False):
        try:
            u.sync(resend=False)
        except Exception as e:
            print(_style(f"\n(not registered on {server}: {e} — your keys will "
                         "publish on first send/receive)", "2"), file=sys.stderr)

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
          + (server or "(none — set one with: retalk config --relay <url>)"),
          file=err)
    print("\nShare the following message with your peer so they can add you:\n"
          + _style(_invite_message(u, None), "2"), file=err)
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


def _invite_message(u, as_name):
    """Render this user's card as a copy-paste shell snippet that onboards a
    peer: install retalk, create their identity, point at the relay, and add
    you. Plain `#` comments + commands, so the whole block pastes into a shell
    and runs -- no quoting prefixes to strip out."""
    c = _self_card(u, as_name)
    name = c["name"] or "me"
    relay = c.get("relay") or "<relay-url>"
    return "\n".join([
        "```bash",
        "# Let's talk over retalk (CLI-based messaging).",
        "# 1. Install retalk:",
        "pipx install retalk                  # or: uv tool install retalk",
        "# 2. Point at our relay:",
        f"export RETALK_RELAY={relay}",
        "# 3. Create your identity:",
        "retalk init --passphrase <YOUR-PRIVATE-PASSPHRASE>",
        "# 4. Add me as a contact:",
        f"retalk add {name} {c['fingerprint']}",
        "# 5. Send me YOUR fingerprint back (shown by retalk init above) so I can add you.",
        "```",
    ])


def cmd_id(args):
    u = _open_user(args, need_server=False, banner=False)
    if getattr(args, "invite_message", False):
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
    d = _resolve_store(args)
    if not ID_RE.match(args.fingerprint):
        _die("fingerprint must be 32 hex characters")
    if ID_RE.match(args.name):
        _die("peer name looks like a user id — give it a human name")
    store_db = d / STORE_FILE
    existing = _saved_peers(store_db)         # ensure the table + current peers
    replacing = args.name in existing
    if replacing and not getattr(args, "override", False):
        alt = _suggest_free_name(set(existing), args.name)
        _die(f"a contact named '{args.name}' already exists "
             f"(-> {existing[args.name][0]}). Pick another name (e.g. '{alt}'), "
             f"or pass --override to replace it")
    # store name + fingerprint only; keys are recorded later by `retalk verify`.
    # --override resets any recorded keys, since the fingerprint may have changed
    # and the old keys would no longer match it.
    _store_sql(store_db,
               "INSERT INTO peers(name, fingerprint, identity_key, signing_key) "
               "VALUES(?,?,NULL,NULL) ON CONFLICT(name) DO UPDATE SET "
               "fingerprint=excluded.fingerprint, "
               "identity_key=NULL, signing_key=NULL",
               args.name, args.fingerprint)
    n = args.name
    print(f"{'Replaced' if replacing else 'Added'} '{n}' in your contacts "
          f"({args.fingerprint}).", file=sys.stderr)
    print("Next:", file=sys.stderr)
    print(f"  retalk verify {n}            — check their keys against the relay",
          file=sys.stderr)
    print(f'  retalk send --peer {n} "hi"  — send them a message', file=sys.stderr)
    print( "  retalk contacts              — see all saved peers", file=sys.stderr)


def cmd_contacts(args):
    d = _resolve_store(args)
    store_db = d / STORE_FILE
    # --remove NAME-OR-ID: delete a saved peer (the inverse of `add`). Resolve
    # by saved name, or by fingerprint (dropping every name pinned to it).
    if args.remove is not None:
        if args.show is not None:
            _die("pass --show to view a contact or --remove to delete one, "
                 "not both")
        peers = _saved_peers(store_db)
        target = args.remove
        names = ([target] if target in peers else
                 [n for n, (fp, _ik, _sk) in peers.items() if fp == target])
        if not names:
            _die(f"no saved contact '{target}' to remove")
        for n in names:
            _store_sql(store_db, "DELETE FROM peers WHERE name=?", n)
        print(f"removed contact '{names[0]}' ({peers[names[0]][0]})",
              file=sys.stderr)
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
    for name, (fp, ik, sk) in sorted(_saved_peers(store_db).items()):
        verified = bool(ik and sk)
        if args.json:
            print(json.dumps({"name": name, "fingerprint": fp,
                              "identity_key": ik or "", "signing_key": sk or "",
                              "verified": verified}))
        else:
            print(f"{name}\t{fp}\t{'verified' if verified else 'unverified'}")


def cmd_verify(args):
    d = _resolve_store(args)
    store_db = d / STORE_FILE
    peers = _saved_peers(store_db)
    # the target must already be a saved contact (run `retalk add` first)
    if args.peer in peers:
        name, fp = args.peer, peers[args.peer][0]
    else:
        match = [n for n, (pfp, _ik, _sk) in peers.items() if pfp == args.peer]
        if not match:
            _die(f"no saved contact '{args.peer}': add it first with "
                 "`retalk add <name> <fingerprint>`")
        name, fp = match[0], args.peer

    if args.identity_key or args.signing_key:
        if not (args.identity_key and args.signing_key):
            _die("manual verify needs both --identity-key and --signing-key: "
                 "the fingerprint is the hash of the two together")
        ik, sk = args.identity_key, args.signing_key
        got = fingerprint(ik, sk)
        if got != fp:
            _die(f"PIN MISMATCH: the supplied keys hash to {got}, not {fp} -- "
                 "refusing to record them")
        source = "supplied keys"
    else:
        u = _open_user(args)  # fetching needs the relay and the passphrase
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

    _store_sql(store_db, "UPDATE peers SET identity_key=?, signing_key=? "
                         "WHERE fingerprint=?", ik, sk, fp)
    print(f"verified {name} ({fp}) from {source}", file=sys.stderr)


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
    # save name + fingerprint (like `add`); re-adding a name resets its keys
    _store_sql(store_db,
               "INSERT INTO peers(name, fingerprint, identity_key, signing_key) "
               "VALUES(?,?,NULL,NULL) ON CONFLICT(name) DO UPDATE SET "
               "fingerprint=excluded.fingerprint, "
               "identity_key=NULL, signing_key=NULL", name, fp)
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
        names = {fp: name for name, (fp, _ik, _sk)
                 in _saved_peers(store_db).items()}
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


def cmd_send(args):
    u = _open_user(args)
    to = _peer_to_id(args.peer, _resolve_store(args) / STORE_FILE)

    u.sync()                       # keys + resend the unacked outbox along with this one
    mid = u.send(to, args.text)
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

    if args.save_messages and _meta(store_db, "no_passphrase") == "1":
        print("retalk: warning: --save-messages on a --no-passphrase identity "
              "stores message bodies with no real protection (its store key is "
              "a public constant); the folder's file permissions are the only "
              "guard", file=sys.stderr)

    def handle(batch):
        for m in batch:                      # standard message / contact objects
            if args.save_contacts and m.get("kind") == "contact":
                _stage_contact(store_db, m)  # to the inbox for `import --inbox`
            elif args.save_messages and "text" in m:
                _save_message(store_db, u, m)  # sealed copy for `retalk history`
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
    peer_fp = _peer_to_id(args.peer, store_db) if args.peer else None
    where = "WHERE from_fp=? " if peer_fp else ""
    rows = _store_sql(store_db,
                      "SELECT msg_id, from_fp, from_name, body FROM messages "
                      f"{where}ORDER BY ts", *([peer_fp] if peer_fp else []))
    # prefer the current saved-peer name; fall back to the label stored at receive
    names = {fp: name for name, (fp, _ik, _sk) in _saved_peers(store_db).items()}
    for msg_id, from_fp, from_name, body in rows:
        print(json.dumps({"id": msg_id, "from": from_fp,
                          "name": names.get(from_fp) or from_name,
                          "text": u.decrypt_at_rest(body)}), flush=True)


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
    g.add_argument("--relay", metavar="URL",
                   help="relay URL for this invocation; overrides the "
                        "RETALK_RELAY env var and the URL saved at init")
    g.add_argument("--api-key", metavar="KEY",
                   help="relay access key, if the relay requires one; sent as "
                        "an Authorization: Bearer header. Overrides "
                        "RETALK_API_KEY and the value saved at init")
    g.add_argument("--passphrase", metavar="SECRET",
                   help="passphrase that unlocks this identity's keys; "
                        "overrides RETALK_PASSPHRASE. NOTE: a value passed "
                        "here is visible in the process list and shell "
                        "history -- prefer RETALK_PASSPHRASE for real secrets")
    g.add_argument("--no-passphrase", action="store_true",
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

quickstart:
  retalk init --user alice --relay https://server.example.com
  export RETALK_USER=alice           # so later commands know which user
  retalk add bob <bob's user id>
  retalk send --peer bob "hello"
  retalk send -u alice --peer bob "hello"    # or name the user inline (no env var)
  retalk receive --peer bob --follow

run `retalk <command> --help` for the full story of each command.""")
    sub = p.add_subparsers(dest="command", required=True,
                           metavar="{init,register,id,add,contacts,share,import,verify,block,sync,send,receive,history}")

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
adding you.""",
        epilog="""\
examples:
  retalk id                    id of the default identity
  retalk id --dir ./alice      id of a project-local identity
  retalk id --card             your own Contact card, human-readable
  retalk id --json             that same card as JSON (the shareable form)
  retalk id --json | retalk import --dir ./bob   hand yourself to another identity
  retalk id --invite-message   a copy-paste invite to onboard a peer out-of-band
  retalk id --invite-message --as bob   suggest the name the peer saves you as""")
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
    sp.add_argument("--as", dest="as_name", metavar="NAME",
                    help="with --card/--invite-message: the nickname you suggest "
                         "the peer save you under (default: your display name)")
    sp.set_defaults(fn=cmd_id)

    sp = sub.add_parser(
        "add", parents=[common], formatter_class=raw,
        help="save a peer's user id under a local name",
        description="""\
Save a peer's USER ID under a short local name, so `send bob ...` works
and incoming messages from that ID display as 'bob' instead of an
unverified '~name'. The name is yours alone — it never travels over
the network and the peer never learns it.

Get the peer's ID out-of-band (they run `retalk id`). If the name is already
taken, `add` errors and suggests a free one; pass `--override` to replace the
existing contact. No secret needed and no server contact — this only writes
your local peers table.""",
        epilog="""\
examples:
  retalk add bob f1041c25c87351d8550b31cc6b13ab04

This saves an incomplete contact -- just the name and fingerprint. The peer's
keys are fetched and verified automatically the first time you message them;
run `retalk verify bob` to do that explicitly now and record the keys (see
`retalk verify --help`).""")
    sp.add_argument("name", help="local name for this peer (e.g. 'bob')")
    sp.add_argument("fingerprint", help="the peer's 32-hex fingerprint (user id)")
    sp.add_argument("--override", action="store_true",
                    help="replace an existing contact of the same name "
                         "(default: error if the name is already taken)")
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
  retalk send --peer bob "psst" --dir ./alice --relay http://127.0.0.1:8766""")
    sp.add_argument("--peer", metavar="PEER", required=True,
                    help="recipient: a saved peer name (from `retalk add`) "
                         "or a raw 32-hex user id")
    sp.add_argument("text", help="the message plaintext (quote it)")
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
    sp.add_argument("--save-messages", action="store_true",
                    help="also keep a local copy of each chat message, sealed "
                         "with this identity's key, for `retalk history`. Off by "
                         "default (retalk keeps no message log otherwise). On a "
                         "--no-passphrase identity the seal is not real "
                         "encryption -- the store key is public")
    sp.set_defaults(fn=cmd_receive, save_contacts=True)

    sp = sub.add_parser(
        "history", parents=[common], formatter_class=raw,
        help="replay messages saved by `receive --save-messages`",
        description="""\
Print the messages this identity has saved with `retalk receive
--save-messages`, oldest first, as one JSON object per line (NDJSON) -- the same
Message shape `receive` emits ({"id", "from", "name", "text"}, see
docs/STANDARD.md). Each body is decrypted from its at-rest seal on the way out,
so this needs the identity's passphrase but never the relay.

retalk keeps no message log unless you opt in with `receive --save-messages`;
with `--peer` only that sender's saved messages are shown.""",
        epilog="""\
examples:
  retalk history                 every saved message, oldest first
  retalk history --peer bob      only messages saved from bob
  retalk history | jq -r .text   just the text of each""")
    sp.add_argument("--peer", metavar="PEER",
                    help="show only this sender's saved messages (a saved peer "
                         "name or a 32-hex user id)")
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
    sp.add_argument("--relay", metavar="URL",
                    help="set the owner-wide default relay URL; pass an empty "
                         "string to clear it")
    sp.set_defaults(fn=cmd_config)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
