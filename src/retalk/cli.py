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
    raw = argparse.RawDescriptionHelpFormatter

    common = argparse.ArgumentParser(add_help=False)
    g = common.add_argument_group("identity selection (shared by every command)")
    g.add_argument("-s", "--store", dest="dir", metavar="DIR",
                   help="use the identity in directory DIR "
                        "(created earlier by `retalk init DIR`)")
    g.add_argument("-u", "--user-level", nargs="?", const="default",
                   default=None, metavar="NAME",
                   help="use the user-level identity NAME, stored under "
                        "~/.local/share/retalk/NAME/ (defaults to 'default' "
                        "when NAME is omitted)")
    g.add_argument("--server", metavar="URL",
                   help="server URL for this invocation; overrides the "
                        "SERVER_URL env var and the URL saved at init")

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
how every command finds your identity (first match wins):
  1. -s DIR              an explicit identity directory
  2. -u [NAME]           a named user-level identity (~/.local/share/retalk/)
  3. STORE env var       same as -s
  4. the user-level identity called 'default', if you created one
  5. otherwise: error.   Only `retalk init` ever creates an identity, so a
                         mistyped path fails loudly instead of silently
                         creating a fresh one.

environment variables:
  PICKLE_SECRET   the secret that unlocks your keys; prompted interactively
                  when unset (use the env var for scripts and daemons)
  SERVER_URL      server to talk to (init can save one per identity instead)
  STORE           identity directory, like -s

output conventions:
  stdout carries results (ids, messages, --json lines); everything else —
  banners, progress, errors — goes to stderr, so pipes stay clean. Every
  command that acts prints `using <nickname> (<id>) from <dir>` to stderr
  so you always know which identity acted. Exit codes: 0 ok, 2 usage or
  refusal (no identity, wrong secret, unknown peer).

quickstart:
  retalk init -u --nickname alice-1 --server https://server.example.com
  retalk add bob <bob's user id>
  retalk send bob "hello"
  retalk receive --follow

run `retalk <command> --help` for the full story of each command.""")
    sub = p.add_subparsers(dest="command", required=True,
                           metavar="{init,id,add,send,receive}")

    sp = sub.add_parser(
        "init", parents=[common], formatter_class=raw,
        help="create a new identity (the only command that ever does)",
        description="""\
Create a new identity: generate an encryption keypair, encrypt it with a
secret you choose, and store it in a folder of your choosing. Prints the
new USER ID on stdout — share it with peers out-of-band; it is both your
address and the fingerprint they verify you by.

The location is mandatory: either a directory argument (project-local) or
-u [NAME] (user-level, under ~/.local/share/retalk/). The folder will
contain store.db — keys (encrypted), sessions, saved peers, and the
outbox of not-yet-acknowledged messages. Back it up to keep the identity;
delete it to destroy the identity.

The secret is prompted twice (or taken from PICKLE_SECRET). It encrypts
your private keys at rest and is required by every later command. It
cannot be recovered: losing it means losing this identity and all its
conversations.

init is offline — it does not contact the server. Keys are published
automatically the first time you send or receive.""",
        epilog="""\
examples:
  retalk init ./alice                          identity in ./alice/
  retalk init -u                               user-level 'default' identity
  retalk init -u work --nickname work-bot \\
              --server https://srv.example.com  named identity, server saved""")
    sp.add_argument("directory", nargs="?",
                    help="folder to hold the identity (alternative to -u)")
    sp.add_argument("--nickname", metavar="NAME",
                    help="display name attached to your messages; peers see "
                         "it marked '~NAME' because it is not verified — "
                         "only their locally saved peer name for you is")
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

Needs your secret (to open the store) but never contacts the server.""",
        epilog="""\
examples:
  retalk id                    id of the default identity
  retalk id -s ./alice         id of a project-local identity
  retalk id --json             {"user_id", "identity_key", "nickname"}""")
    sp.add_argument("--json", action="store_true",
                    help="emit JSON with user_id, identity_key (base64 "
                         "Curve25519 public key), and nickname")
    sp.set_defaults(fn=cmd_id)

    sp = sub.add_parser(
        "add", parents=[common], formatter_class=raw,
        help="save a peer's user id under a local name",
        description="""\
Save a peer's USER ID under a short local name, so `send bob ...` works
and incoming messages from that ID display as 'bob' instead of an
unverified '~nickname'. The name is yours alone — it never travels over
the network and the peer never learns it.

Get the peer's ID out-of-band (they run `retalk id`). Adding an existing
name overwrites it. No secret needed and no server contact — this only
writes your local peers table.""",
        epilog="""\
examples:
  retalk add bob f1041c25c87351d8550b31cc6b13ab04
  retalk add bob <id> --pin "vGY3...="     also pin bob's full identity key

The fingerprint ID already pins the peer's keys; --pin adds an explicit
second check of the full identity key for belt-and-braces.""")
    sp.add_argument("name", help="local name for this peer (e.g. 'bob')")
    sp.add_argument("user_id", help="the peer's 32-hex user id")
    sp.add_argument("--pin", metavar="KEY",
                    help="peer's full base64 identity key, verified against "
                         "everything the server serves for this peer")
    sp.set_defaults(fn=cmd_add)

    sp = sub.add_parser(
        "send", parents=[common], formatter_class=raw,
        help="encrypt and send one message",
        description="""\
Encrypt TEXT for one peer and hand the ciphertext to the server, then
exit. The server (and anyone watching it) sees only the ciphertext and
the metadata sender/recipient/time/size — never the content.

PEER is a name saved with `retalk add`, or a raw 32-hex user id. The
first message to a new peer performs the key handshake automatically
(claiming one of the peer's one-time keys from the server); if the
server's served keys do not match the peer's ID fingerprint or your
saved --pin, the send refuses with PIN MISMATCH instead of encrypting to
an impostor key.

Delivery is tracked: the message stays in your local outbox until the
peer's client acknowledges decrypting it (acks arrive during your next
`receive`). Unacknowledged messages are re-sent automatically by
`receive --follow`, so nothing is lost if the server dies or is swapped.
On first contact with a server your public keys are published
automatically.""",
        epilog="""\
examples:
  retalk send bob "hello"
  retalk send f1041c25c87351d8550b31cc6b13ab04 "hi, stranger"
  retalk send bob "psst" -s ./alice --server http://127.0.0.1:8766""")
    sp.add_argument("peer", help="saved peer name, or a raw 32-hex user id")
    sp.add_argument("text", help="the message plaintext (quote it)")
    sp.set_defaults(fn=cmd_send)

    sp = sub.add_parser(
        "receive", parents=[common], formatter_class=raw,
        help="decrypt pending messages",
        description="""\
Fetch this identity's mailbox from the server, decrypt each message, and
print it — `name: text` per line, where name is your saved peer name for
the sender, or their unverified self-chosen nickname marked '~', or the
bare sender id. Each successfully decrypted message is acknowledged back
to its sender (encrypted, like everything else).

Without --follow: drain the mailbox once and exit (good for cron and
scripts). With --follow: poll every 2 seconds until interrupted, and once
a minute run key maintenance — replenish one-time keys on the server,
rotate the fallback key daily, and re-send any of your own messages that
have gone unacknowledged for 2 minutes.

Messages the server already handed over are never served again, so pipe
--json output somewhere durable if you need a log.""",
        epilog="""\
examples:
  retalk receive                       drain once, human-readable
  retalk receive --follow              live tail + key maintenance
  retalk receive --json | jq .text     script-friendly, one object per line

json fields per message: "from" (sender id), "name" (your peer name,
'~nickname', or ''), "text" (the plaintext).""")
    sp.add_argument("--follow", action="store_true",
                    help="keep polling every 2s and maintain keys every "
                         "60s until ctrl-c")
    sp.add_argument("--json", action="store_true",
                    help="one JSON object per message on stdout "
                         "(banners stay on stderr)")
    sp.set_defaults(fn=cmd_receive)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
