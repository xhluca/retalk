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


def _build_card(store_db: Path, contact: str, as_name: str | None) -> dict:
    """Build a Contact card (see docs/STANDARD.md) for `contact` -- a saved
    peer name or a raw 32-hex fingerprint -- to `show` or `share`.

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


def cmd_show(args):
    d = _resolve_store(args)
    card = _build_card(d / STORE_FILE, args.contact, args.as_name)
    print(json.dumps(card))


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
        raise ValueError("card must be a JSON object (see `retalk show`)")
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
    store_db = _resolve_store(args) / STORE_FILE
    to = None if args.all else _peer_to_id(args.peer, store_db)

    def handle(batch):
        for m in batch:                      # standard message / contact objects
            if args.save_contacts and m.get("kind") == "contact":
                _stage_contact(store_db, m)  # to the inbox for `import --inbox`
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
                           metavar="{init,id,add,contacts,show,share,import,verify,block,unblock,blocked,send,receive}")

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
        "show", parents=[common], formatter_class=raw,
        help="print one saved peer as a shareable Contact card (JSON)",
        description="""\
Print one contact as a Contact card (JSON, see docs/STANDARD.md) on stdout:
{"fingerprint", "name", "identity_key", "signing_key", "verified"}. This is the
shareable form of a saved peer -- the same object `retalk share` sends over the
relay and `retalk import` ingests, so you can also hand it over any out-of-band
channel (paste it, pipe it) and have the other side import it.

Name the contact by a saved peer name (from `retalk add`) or a raw 32-hex user
id. The card's `name` is the recommended nickname the recipient sees: the saved
peer name, or whatever you pass with `--as`. The identity_key/signing_key are
included only when the contact is verified (`retalk verify`); otherwise they are
"" and the card is unverified -- the recipient verifies it on first contact, as
usual. The keys are not secret, and the fingerprint pins them, so a card is safe
to share in the clear.

No passphrase and no server contact -- this only reads your local peers table.""",
        epilog="""\
examples:
  retalk show bob                  bob's Contact card as one JSON line
  retalk show bob --as bobby       recommend the nickname 'bobby' instead
  retalk show bob | retalk import --dir ./carol   copy bob to another identity""")
    sp.add_argument("contact",
                    help="a saved peer name (from `retalk add`) or a 32-hex "
                         "user id to emit as a Contact card")
    sp.add_argument("--as", dest="as_name", metavar="NAME",
                    help="recommended nickname to put in the card "
                         "(default: the saved peer name)")
    sp.set_defaults(fn=cmd_show)

    sp = sub.add_parser(
        "share", parents=[common], formatter_class=raw,
        help="send a saved contact to a peer (an introduction)",
        description="""\
Introduce one of your contacts to a peer: build that contact's Contact card
(the same JSON `retalk show` prints) and send it, encrypted, to the recipient
over the relay. The recipient sees it in `retalk receive` as a contact record
and saves it with `retalk import`, under the nickname you recommend.

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
Save a contact from a Contact card -- the JSON that `retalk show` prints and
`retalk share` sends (the `card` object of a received contact record). The card
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
({"id", "from", "name", "text"}). A contact shared with `retalk share` arrives
as a contact record instead ({"id", "from", "name", "kind": "contact", "card":
{...}}); it is also saved to the contact-inbox (unless --no-save-contacts) for
`retalk import --inbox`. Each decrypted message is acknowledged back to its
sender (encrypted, like everything else).

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
  retalk receive --all ; retalk import --inbox --list   read, then see staged contacts

each line is a JSON message object (see docs/STANDARD.md): "id", "from",
"name", "text" -- or a contact record with "kind":"contact" and "card".
Contacts peers share are also saved to the contact-inbox (see
`retalk import --inbox`); pass --no-save-contacts to skip that.""")
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
    sp.add_argument("--no-save-contacts", dest="save_contacts",
                    action="store_false",
                    help="do not save contacts that peers share with you "
                         "(`retalk share`) to the contact-inbox; by default they "
                         "are staged there for `retalk import --inbox`")
    sp.set_defaults(fn=cmd_receive, save_contacts=True)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
