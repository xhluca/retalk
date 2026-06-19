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

from .user import User, fingerprint

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
    if args.api_key:
        u._meta_set("api_key", args.api_key)
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
    # store name + fingerprint only; keys are recorded later by `retalk verify`.
    # re-adding a name resets any recorded keys, since the fingerprint may have
    # changed and the old keys would no longer match it.
    _store_sql(store_db,
               "INSERT INTO peers(name, fingerprint, identity_key, signing_key) "
               "VALUES(?,?,NULL,NULL) ON CONFLICT(name) DO UPDATE SET "
               "fingerprint=excluded.fingerprint, "
               "identity_key=NULL, signing_key=NULL",
               args.name, args.fingerprint)
    print(f"added {args.name} -> {args.fingerprint}", file=sys.stderr)


def cmd_contacts(args):
    d = _resolve_store(args)
    store_db = d / STORE_FILE
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


def cmd_block(args):
    d = _resolve_store(args)
    store_db = d / STORE_FILE
    fp = _peer_to_id(args.peer, store_db)
    _blocked_set(store_db)  # ensure the table exists
    _store_sql(store_db, "INSERT OR IGNORE INTO blocked(fingerprint) VALUES(?)", fp)
    print(f"blocked {args.peer} ({fp})", file=sys.stderr)


def cmd_unblock(args):
    d = _resolve_store(args)
    store_db = d / STORE_FILE
    fp = _peer_to_id(args.peer, store_db)
    _blocked_set(store_db)  # ensure the table exists
    _store_sql(store_db, "DELETE FROM blocked WHERE fingerprint=?", fp)
    print(f"unblocked {args.peer} ({fp})", file=sys.stderr)


def cmd_blocked(args):
    d = _resolve_store(args)
    store_db = d / STORE_FILE
    names = {fp: name for name, (fp, _ik, _sk) in _saved_peers(store_db).items()}
    for fp in sorted(_blocked_set(store_db)):
        if args.json:
            print(json.dumps({"fingerprint": fp, "name": names.get(fp, "")}))
        else:
            name = names.get(fp)
            print(f"{fp}\t{name}" if name else fp)


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
    to = None if args.all else _peer_to_id(args.peer,
                                           _resolve_store(args) / STORE_FILE)

    def emit(batch):
        for m in batch:                      # standard message objects
            print(json.dumps(m), flush=True)

    try:
        u.sync(resend=False)          # reachable + fresh keys; reading never resends
        emit(u.receive(to))
        if not args.follow:
            return
        last_sync = time.monotonic()
        while True:
            time.sleep(2)
            emit(u.receive(to))
            if time.monotonic() - last_sync > 60:
                u.sync(resend=False)  # key upkeep only; resends belong to send / `retalk sync`
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
  RETALK_API_KEY     relay access key, if the relay requires one (init can save it)

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
                           metavar="{init,id,add,contacts,verify,block,unblock,blocked,send,receive}")

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

This saves an incomplete contact -- just the name and fingerprint. The peer's
keys are fetched and verified automatically the first time you message them;
run `retalk verify bob` to do that explicitly now and record the keys (see
`retalk verify --help`).""")
    sp.add_argument("name", help="local name for this peer (e.g. 'bob')")
    sp.add_argument("fingerprint", help="the peer's 32-hex fingerprint (user id)")
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
        help="list saved peers (your contacts)",
        description="""\
List the peers you have saved with `retalk add`, one per line as
NAME<tab>FINGERPRINT<tab>STATUS (verified or unverified), sorted by name. These
local names never leave your machine, and the peer never learns them.

A peer is "verified" once its keys have been recorded with `retalk verify`;
until then it is an incomplete contact (just name + fingerprint). With --json
each line is a Contact object (see docs/STANDARD.md): {"name", "fingerprint",
"identity_key", "signing_key", "verified"}, where the key fields are "" until
the peer is verified.

No passphrase and no server contact -- this only reads your local peers
table. Prints nothing when you have saved no peers.""",
        epilog="""\
examples:
  retalk contacts                list saved peers as NAME<tab>FINGERPRINT<tab>STATUS
  retalk contacts --json         one Contact object (see docs/STANDARD.md) per line
  retalk contacts --json | jq .  pretty-print every contact""")
    sp.add_argument("--json", action="store_true",
                    help="emit one Contact object per saved peer (see "
                         "docs/STANDARD.md): name, fingerprint, identity_key, "
                         "signing_key, verified")
    sp.set_defaults(fn=cmd_contacts)

    sp = sub.add_parser(
        "block", parents=[common], formatter_class=raw,
        help="silently drop a sender's incoming messages",
        description="""\
Block a sender: their incoming messages are dropped during `receive` before
any decryption happens, so a blocked sender can never even consume one of your
one-time keys. The block is local to this identity's store and is never sent to
the server or the peer; their mail simply stays on the server, unread.

Name the sender by a saved peer name (from `retalk add`) or a raw 32-hex user
id. Unblock later with `retalk unblock`; list current blocks with
`retalk blocked`.""",
        epilog="""\
examples:
  retalk block bob                              block a saved peer
  retalk block f1041c25c87351d8550b31cc6b13ab04   block by raw id""")
    sp.add_argument("peer", help="saved peer name or 32-hex user id to block")
    sp.set_defaults(fn=cmd_block)

    sp = sub.add_parser(
        "unblock", parents=[common], formatter_class=raw,
        help="stop dropping a previously blocked sender",
        description="""\
Remove a sender from the block list, so `receive` delivers their messages
again. Name them by a saved peer name or a raw 32-hex user id. Unblocking
someone who is not blocked is a no-op.""",
        epilog="""\
examples:
  retalk unblock bob
  retalk unblock f1041c25c87351d8550b31cc6b13ab04""")
    sp.add_argument("peer", help="saved peer name or 32-hex user id to unblock")
    sp.set_defaults(fn=cmd_unblock)

    sp = sub.add_parser(
        "blocked", parents=[common], formatter_class=raw,
        help="list blocked senders",
        description="""\
List the fingerprints currently blocked for this identity, one per line
(with the saved peer name, if any). No server contact.""",
        epilog="""\
examples:
  retalk blocked
  retalk blocked --json     one {"fingerprint","name"} object per line""")
    sp.add_argument("--json", action="store_true",
                    help="emit one JSON object per blocked sender")
    sp.set_defaults(fn=cmd_blocked)

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
({"id", "from", "name", "text"}). Each decrypted message is acknowledged back
to its sender (encrypted, like everything else).

Say whose messages to read: pass --peer PEER (a saved name or 32-hex user id)
to read just that sender, or --all to drain every sender. Targeting one peer
leaves everyone else's mail in the mailbox for a later receive.

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
  retalk receive --all                 read every sender, once
  retalk receive --peer bob            read only messages from bob
  retalk receive --all --follow        live tail of all senders + key upkeep
  retalk receive --all --peers-only    drop mail from senders you never added
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
    sp.add_argument("--peers-only", action="store_true",
                    help="accept mail only from saved peers (`retalk add`); "
                         "messages from unknown senders are dropped before "
                         "any decryption, so they never consume a one-time "
                         "key. Blocked senders (`retalk block`) are always "
                         "dropped regardless of this flag")
    sp.set_defaults(fn=cmd_receive)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
