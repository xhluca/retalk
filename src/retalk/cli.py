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

import argparse
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
    _store_sql(store_db, "CREATE TABLE IF NOT EXISTS peers("
                         "name TEXT PRIMARY KEY, fingerprint TEXT, "
                         "identity_key TEXT)")
    # migrate older stores that named these columns id / pin
    cols = [r[1] for r in _store_sql(store_db, "PRAGMA table_info(peers)")]
    if "id" in cols and "fingerprint" not in cols:
        _store_sql(store_db, "ALTER TABLE peers RENAME COLUMN id TO fingerprint")
    if "pin" in cols and "identity_key" not in cols:
        _store_sql(store_db,
                   "ALTER TABLE peers RENAME COLUMN pin TO identity_key")
    return {name: (fp, ik) for name, fp, ik in
            _store_sql(store_db, "SELECT name, fingerprint, identity_key "
                                 "FROM peers")}


def _open_user(args, need_server: bool = True, banner: bool = True) -> User:
    d = _resolve_store(args)
    store_db = d / STORE_FILE
    secret, _ = _resolve_passphrase(args, store_db=store_db)
    server = (getattr(args, "relay", None) or os.environ.get("RETALK_RELAY")
              or _meta(store_db, "server_url") or "")
    if need_server and not server:
        _die("no relay URL: pass --relay, set RETALK_RELAY, or save one "
             "at init time")
    peers = _saved_peers(store_db)
    identity_keys = {fp: ik for _, (fp, ik) in peers.items() if ik}
    names = {fp: name for name, (fp, _) in peers.items()}
    try:
        u = User(server, secret, name=_meta(store_db, "name") or "",
                 store=str(store_db), identity_keys=identity_keys, names=names)
    except Exception:
        _die(f"could not unlock the identity at {d} (wrong passphrase?)")
    if banner:
        print(f"using {u.name or 'user'} ({u.fingerprint()}) from {d}",
              file=sys.stderr)
    return u


def _ensure_published(u: User):
    """Make sure our keys exist on this server before acting.

    Asks the server rather than trusting a local flag, so a wiped or
    replaced server database heals automatically on the next command."""
    if not u._call("count_keys")["has_fallback"]:
        u.publish()


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
    d = _resolve_store(args, creating=True)
    if (d / STORE_FILE).exists():
        _die(f"an identity already exists at {d}")
    d.mkdir(parents=True, exist_ok=True)
    secret, disabled = _resolve_passphrase(args, creating=True)
    server = args.relay or os.environ.get("RETALK_RELAY") or ""
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
    # private keys live here; keep them owner-only whether or not encrypted
    try:
        (d / STORE_FILE).chmod(0o600)
        d.chmod(0o700)
    except OSError:
        pass
    print(f"created identity at {d}", file=sys.stderr)
    print("user id (share out-of-band; it is address + pin in one):",
          file=sys.stderr)
    print(u.fingerprint())


def cmd_id(args):
    u = _open_user(args, need_server=False, banner=False)
    if args.json:
        print(json.dumps({"fingerprint": u.fingerprint(),
                          "identity_key": u.identity_key(),
                          "name": u.name}))
    else:
        print(u.fingerprint())


def cmd_add(args):
    d = _resolve_store(args)
    if not ID_RE.match(args.fingerprint):
        _die("fingerprint must be 32 hex characters")
    if ID_RE.match(args.name):
        _die("peer name looks like a user id — give it a human name")
    store_db = d / STORE_FILE
    _saved_peers(store_db)  # ensure the table exists
    _store_sql(store_db,
               "INSERT INTO peers(name, fingerprint, identity_key) "
               "VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET "
               "fingerprint=excluded.fingerprint, "
               "identity_key=excluded.identity_key",
               args.name, args.fingerprint, args.identity_key)
    print(f"added {args.name} -> {args.fingerprint}", file=sys.stderr)


def cmd_send(args):
    u = _open_user(args)
    to = _peer_to_id(args.peer, _resolve_store(args) / STORE_FILE)

    _ensure_published(u)
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
    to = None if args.all else _peer_to_id(args.peer,
                                           _resolve_store(args) / STORE_FILE)

    def emit(batch):
        for m in batch:                      # standard message objects
            print(json.dumps(m), flush=True)

    try:
        _ensure_published(u)
        emit(u.receive(to))
        if not args.follow:
            return
        last_maintain = time.monotonic()
        while True:
            time.sleep(2)
            emit(u.receive(to))
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
    g.add_argument("--dir", metavar="DIR",
                   help="use the identity in directory DIR "
                        "(created earlier by `retalk init --dir DIR`)")
    g.add_argument("-u", "--user", metavar="NAME",
                   help="act as the user named NAME, stored under "
                        "~/.local/share/retalk/NAME/. Overrides RETALK_USER")
    g.add_argument("--relay", metavar="URL",
                   help="relay URL for this invocation; overrides the "
                        "RETALK_RELAY env var and the URL saved at init")
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
  2. --user / -u NAME    the user named NAME (~/.local/share/retalk/NAME/)
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
  retalk receive --all --follow

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

The location is mandatory: --user NAME (stored under
~/.local/share/retalk/NAME/) or --dir DIR (an explicit path). The folder will
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
  retalk id --dir ./alice      id of a project-local identity
  retalk id --json             {"fingerprint", "identity_key", "name"}""")
    sp.add_argument("--json", action="store_true",
                    help="emit JSON with fingerprint, identity_key (base64 "
                         "Curve25519 public key), and name")
    sp.set_defaults(fn=cmd_id)

    sp = sub.add_parser(
        "add", parents=[common], formatter_class=raw,
        help="save a peer's user id under a local name",
        description="""\
Save a peer's USER ID under a short local name, so `send bob ...` works
and incoming messages from that ID display as 'bob' instead of an
unverified '~name'. The name is yours alone — it never travels over
the network and the peer never learns it.

Get the peer's ID out-of-band (they run `retalk id`). Adding an existing
name overwrites it. No secret needed and no server contact — this only
writes your local peers table.""",
        epilog="""\
examples:
  retalk add bob f1041c25c87351d8550b31cc6b13ab04
  retalk add bob <id> --identity-key "vGY3...="   pin bob's full identity key

The fingerprint ID already pins the peer's keys; --identity-key adds an
explicit second check of the full identity key for belt-and-braces.""")
    sp.add_argument("name", help="local name for this peer (e.g. 'bob')")
    sp.add_argument("fingerprint", help="the peer's 32-hex fingerprint (user id)")
    sp.add_argument("--identity-key", metavar="KEY",
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

The `--peer` value is a name saved with `retalk add`, or a raw 32-hex id. The
first message to a new peer performs the key handshake automatically
(claiming one of the peer's one-time keys from the server); if the
server's served keys do not match the peer's ID fingerprint or your
saved --identity-key, the send refuses with PIN MISMATCH instead of encrypting
an impostor key.

Delivery is tracked: the message stays in your local outbox until the
peer's client acknowledges decrypting it (acks arrive during your next
`receive`). Unacknowledged messages are re-sent automatically by
`receive --follow`, so nothing is lost if the server dies or is swapped.
On first contact with a server your public keys are published
automatically.

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
({"id", "from", "name", "text"}). Each decrypted message is acknowledged back
to its sender (encrypted, like everything else).

Say whose messages to read: pass --peer PEER (a saved name or 32-hex user id)
to read just that sender, or --all to drain every sender. Targeting one peer
leaves everyone else's mail in the mailbox for a later receive.

Without --follow: drain the mailbox once and exit (good for cron and
scripts). With --follow: poll every 2 seconds until interrupted, and once
a minute run key maintenance — replenish one-time keys on the server,
rotate the fallback key daily, and re-send any of your own messages that
have gone unacknowledged for 2 minutes.

Messages the server already handed over are never served again, so pipe
--json output somewhere durable if you need a log.""",
        epilog="""\
examples:
  retalk receive --all                 read every sender, once
  retalk receive --peer bob            read only messages from bob
  retalk receive --all --follow        live tail of all senders + key upkeep
  retalk receive --all | jq .text      pipe the JSON lines to jq

each line is a JSON message object (see docs/STANDARD.md): "id", "from",
"name", "text".""")
    sp.add_argument("--peer", metavar="PEER",
                    help="read only this peer's messages (a saved peer name "
                         "or a 32-hex user id); use --all for every sender")
    sp.add_argument("--all", action="store_true",
                    help="read messages from every sender (the whole mailbox) "
                         "instead of targeting one peer")
    sp.add_argument("--follow", action="store_true",
                    help="keep polling every 2s and maintain keys every "
                         "60s until ctrl-c")
    sp.set_defaults(fn=cmd_receive)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
