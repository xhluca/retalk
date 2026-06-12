"""retalk command-line interface.

An identity lives in a folder (created by `retalk init`) containing
store.db: keys encrypted at rest, sessions, saved peers, outbox.

Store resolution for every command, in order:
  -s DIR  >  -u [NAME]  >  STORE env  >  user-level "default" identity
  (if it exists)  >  error.
Only `init` ever creates an identity; every other command refuses loudly
when none exists.

The pickle secret is read from PICKLE_SECRET or prompted (never echoed).
The server URL comes from --server, SERVER_URL, or the value saved at
init. Identity banners go to stderr so stdout stays clean for --json.
"""

import argparse
import getpass
import json
import os
import re
import sqlite3
import sys
import time
from pathlib import Path

from .user import User

STORE_FILE = "store.db"
ID_RE = re.compile(r"^[0-9a-f]{32}$")


def _data_home() -> Path:
    return Path(os.environ.get("XDG_DATA_HOME",
                               Path.home() / ".local" / "share")) / "retalk"


def _die(msg: str, code: int = 2):
    print(f"retalk: {msg}", file=sys.stderr)
    sys.exit(code)


def _resolve_store(args, creating: bool = False) -> Path:
    if getattr(args, "dir", None):
        d = Path(args.dir)
    elif args.user_level is not None:
        d = _data_home() / args.user_level
    elif not creating and os.environ.get("STORE"):
        d = Path(os.environ["STORE"])
    elif not creating and (_data_home() / "default" / STORE_FILE).exists():
        d = _data_home() / "default"
    elif creating:
        _die("init needs a location: a directory argument or -u [NAME]")
    else:
        _die("no identity specified: use -s DIR, -u [NAME], the STORE env "
             "var, or create one with `retalk init`")
    if not creating and not (d / STORE_FILE).exists():
        _die(f"no identity at {d} — create one with `retalk init {d}`")
    return d


def _secret(confirm: bool = False) -> str:
    s = os.environ.get("PICKLE_SECRET")
    if s:
        return s
    if not sys.stdin.isatty():
        _die("PICKLE_SECRET is not set and there is no terminal to prompt on")
    s = getpass.getpass("pickle secret (unlocks this identity): ")
    if confirm and getpass.getpass("repeat to confirm: ") != s:
        _die("secrets do not match")
    return s


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
    _store_sql(store_db, "CREATE TABLE IF NOT EXISTS peers("
                         "name TEXT PRIMARY KEY, id TEXT, pin TEXT)")
    return {name: (pid, pin) for name, pid, pin in
            _store_sql(store_db, "SELECT name, id, pin FROM peers")}


def _open_user(args, need_server: bool = True, banner: bool = True) -> User:
    d = _resolve_store(args)
    store_db = d / STORE_FILE
    server = (getattr(args, "server", None) or os.environ.get("SERVER_URL")
              or _meta(store_db, "server_url") or "")
    if need_server and not server:
        _die("no server URL: pass --server, set SERVER_URL, or save one "
             "at init time")
    peers = _saved_peers(store_db)
    pins = {pid: pin for _, (pid, pin) in peers.items() if pin}
    names = {pid: name for name, (pid, _) in peers.items()}
    try:
        u = User(server, _secret(), nickname=_meta(store_db, "nickname") or "",
                 store=str(store_db), pins=pins, names=names)
    except Exception:
        _die(f"could not unlock the identity at {d} (wrong secret?)")
    if banner:
        print(f"using {u.nickname or 'user'} ({u.user_id()}) from {d}",
              file=sys.stderr)
    return u


def _ensure_published(u: User):
    """Publish keys once per server (this also creates our mailbox there)."""
    flag = f"published:{u.server_url}"
    if u._meta_get(flag) is None:
        u.publish()
        u._meta_set(flag, str(time.time()))


def _peer_to_id(peer: str, store_db: Path) -> str:
    peers = _saved_peers(store_db)
    if peer in peers:
        return peers[peer][0]
    if ID_RE.match(peer):
        return peer
    _die(f"unknown peer '{peer}': `retalk add {peer} <user-id>` first, "
         "or pass a 32-hex user id")


# ---------- commands ----------

def cmd_init(args):
    if args.directory:
        args.dir = args.directory
    d = _resolve_store(args, creating=True)
    if (d / STORE_FILE).exists():
        _die(f"an identity already exists at {d}")
    d.mkdir(parents=True, exist_ok=True)
    secret = _secret(confirm=True)
    server = args.server or os.environ.get("SERVER_URL") or ""
    u = User(server, secret, nickname=args.nickname or "",
             store=str(d / STORE_FILE))
    if args.nickname:
        u._meta_set("nickname", args.nickname)
    if server:
        u._meta_set("server_url", server)
    print(f"created identity at {d}", file=sys.stderr)
    print("user id (share out-of-band; it is address + pin in one):",
          file=sys.stderr)
    print(u.user_id())


def cmd_id(args):
    u = _open_user(args, need_server=False, banner=False)
    if args.json:
        print(json.dumps({"user_id": u.user_id(),
                          "identity_key": u.identity_key(),
                          "nickname": u.nickname}))
    else:
        print(u.user_id())


def cmd_add(args):
    d = _resolve_store(args)
    if not ID_RE.match(args.user_id):
        _die("user id must be 32 hex characters")
    if ID_RE.match(args.name):
        _die("peer name looks like a user id — give it a human name")
    store_db = d / STORE_FILE
    _saved_peers(store_db)  # ensure the table exists
    _store_sql(store_db,
               "INSERT INTO peers(name, id, pin) VALUES(?,?,?) "
               "ON CONFLICT(name) DO UPDATE SET id=excluded.id, "
               "pin=excluded.pin",
               args.name, args.user_id, args.pin)
    print(f"added {args.name} -> {args.user_id}", file=sys.stderr)


def cmd_send(args):
    u = _open_user(args)
    to = _peer_to_id(args.peer, _resolve_store(args) / STORE_FILE)

    _ensure_published(u)
    u.send(to, args.text)
    print(f"sent to {args.peer}", file=sys.stderr)


def cmd_receive(args):
    u = _open_user(args)

    def emit(batch):
        for sender, name, text in batch:
            if args.json:
                print(json.dumps({"from": sender, "name": name,
                                  "text": text}), flush=True)
            else:
                print(f"{name or sender}: {text}", flush=True)

    try:
        _ensure_published(u)
        emit(u.receive())
        if not args.follow:
            return
        last_maintain = time.monotonic()
        while True:
            time.sleep(2)
            emit(u.receive())
            if time.monotonic() - last_maintain > 60:
                u.maintain()
                last_maintain = time.monotonic()
    except KeyboardInterrupt:
        pass


def main():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-s", "--store", dest="dir", metavar="DIR",
                        help="identity directory")
    common.add_argument("-u", "--user-level", nargs="?", const="default",
                        default=None, metavar="NAME",
                        help="user-level identity in ~/.local/share/retalk/")
    common.add_argument("--server", help="server URL (overrides saved value)")

    p = argparse.ArgumentParser(
        prog="retalk",
        description="end-to-end-encrypted messages between users via an "
                    "untrusted server")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("init", parents=[common],
                        help="create a new identity (the only command that does)")
    sp.add_argument("directory", nargs="?", help="folder to hold the identity")
    sp.add_argument("--nickname", help="display name peers see (unverified)")
    sp.set_defaults(fn=cmd_init)

    sp = sub.add_parser("id", parents=[common], help="print my user id")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(fn=cmd_id)

    sp = sub.add_parser("add", parents=[common],
                        help="save a peer under a local name")
    sp.add_argument("name")
    sp.add_argument("user_id")
    sp.add_argument("--pin", help="peer's full identity key (extra pin on "
                                  "top of the fingerprint id)")
    sp.set_defaults(fn=cmd_add)

    sp = sub.add_parser("send", parents=[common],
                        help="encrypt and send one message")
    sp.add_argument("peer", help="saved peer name or 32-hex user id")
    sp.add_argument("text")
    sp.set_defaults(fn=cmd_send)

    sp = sub.add_parser("receive", parents=[common],
                        help="decrypt pending messages")
    sp.add_argument("--follow", action="store_true",
                    help="keep polling (and maintaining keys) until ctrl-c")
    sp.add_argument("--json", action="store_true",
                    help="one JSON object per message on stdout")
    sp.set_defaults(fn=cmd_receive)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
