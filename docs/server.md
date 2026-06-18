# Server behavior and trust model

The retalk server is a relay. It has two jobs:

1. Hold encrypted messages in recipient mailboxes until clients poll.
2. Serve a public-key directory for users who have published keys.

The server does not encrypt, decrypt, create identities, or decide which keys
to trust. Clients do that.

This page explains what the server stores, what it can see, why requests are
authenticated, and what a hostile server can still do.

## Configuration reference

Every setting has a command-line flag and a matching environment variable; the
flag wins when both are given. This is the canonical list — the deployment
guides below only show these in context.

**`retalk-server`** (the relay):

| flag | env var | default | meaning |
|------|---------|---------|---------|
| `--host` | `RETALK_SERVER_HOST` | `0.0.0.0` | interface to bind (`0.0.0.0` = all, `127.0.0.1` = this machine only) |
| `--port` | `RETALK_SERVER_PORT` | `8766` | TCP port to bind |
| `--audience` | `RETALK_SERVER_AUDIENCE` | `http://HOST:PORT` | public URL clients connect to; request signatures are bound to it, so it must equal each client's relay URL exactly |
| `--db` | `RETALK_SERVER_DB` | `server.db` | SQLite database path |
| `--max-mailbox` | `RETALK_SERVER_MAX_MAILBOX` | `0` (unlimited) | max undelivered messages per recipient; see [Mailbox cap](#mailbox-cap) |
| `--max-mailbox-per-sender` | `RETALK_SERVER_MAX_MAILBOX_PER_SENDER` | `0` (unlimited) | max undelivered messages a single sender may hold in one recipient's mailbox; only applies when `--max-mailbox` is set |

`--host`/`--port` are where the process *listens*; `--audience` is the public
URL clients *reach it at*. They coincide locally, but behind a TLS proxy the
proxy listens publicly and forwards to a local `--host`/`--port`, so
`--audience` must be set to the public `https://` URL.

**`retalk`** (the client):

| flag | env var | meaning |
|------|---------|---------|
| `--relay` | `RETALK_RELAY` | relay URL to talk to (must equal the server's `--audience`); `init` can save one per identity |
| `--user` / `-u` | `RETALK_USER` | which identity to act as (`~/.local/share/retalk/NAME/`) |
| `--dir` | — | use an identity in an explicit directory instead of by user name |
| `--passphrase` | `RETALK_PASSPHRASE` | unlocks the identity's keys at rest |
| `--no-passphrase` | — | open/create an identity with no passphrase (file-permission protected only) |

## Running it on the internet

The server speaks plain HTTP on a local port. To expose it publicly, put it
behind something that terminates TLS and forwards to that port:

- [huggingface.md](server/huggingface.md) — host it for free on a Hugging Face
  Docker Space: a public HTTPS URL with no domain, firewall, or TLS setup.
  Quickest zero-cost option; the free tier has no persistent disk and sleeps
  when idle.
- [cloudflare.md](server/cloudflare.md) — Cloudflare Tunnel, free quick
  tunnels or a stable hostname on your own domain. No firewall changes.
- [gcp.md](server/gcp.md) — running the server on a small Google Cloud
  VM (free-tier sized), with stop/delete and cost notes.

The examples assume the local demo from the README:

- server at `http://127.0.0.1:8766`
- Alice identity in `./alice`
- `RETALK_RELAY=http://127.0.0.1:8766`
- `RETALK_PASSPHRASE=alice-secret`

## Database tables

The schema lives in `src/retalk/server.py`.

`users` stores:

- user ID,
- public identity key,
- public signing key,
- public fallback key.

There are no accounts, passwords, bearer tokens, or private keys.

`otks` stores:

- public one-time prekeys,
- the user that owns each key,
- whether each key has been claimed.

The private halves stay in the user's encrypted local store.

`messages` stores:

- sender ID,
- recipient ID,
- timestamp,
- message type,
- base64 ciphertext.

Rows are deleted as soon as `read_messages` delivers them to the recipient.

`nonces` stores recent request nonces so copied requests cannot be replayed.
Old entries are purged automatically.

## Mailbox cap

By default a recipient's mailbox is unbounded, so an open relay can be filled
by anyone who can reach it — a denial-of-service lever. The mailbox cap bounds
how much undelivered mail a recipient can accumulate.

| flag | env var | default | meaning |
|------|---------|---------|---------|
| `--max-mailbox` | `RETALK_SERVER_MAX_MAILBOX` | `0` (unlimited) | max undelivered messages per recipient |
| `--max-mailbox-per-sender` | `RETALK_SERVER_MAX_MAILBOX_PER_SENDER` | `0` (unlimited) | max undelivered messages one sender may hold in a single recipient's mailbox |

Behavior:

- The default `0` is unlimited, so caps are off unless you set one.
- `send_message` counts a recipient's undelivered messages *before* inserting.
  At or over `--max-mailbox`, the send is **rejected** with HTTP 400 and
  `{"error": "mailbox full: ..."}`. It is **reject-not-evict**: existing mail
  is never dropped to make room.
- `--max-mailbox-per-sender` is a smaller sub-cap on how many of those
  messages may come from one sender, so a single sender cannot fill a mailbox
  and crowd everyone else out. It only takes effect when `--max-mailbox` is
  set, and produces a `mailbox full for sender: ...` error.

A rejection is safe for delivery. The sender keeps every unacknowledged
message in its local outbox and resends later (the same mechanism that
survives a dropped server, see *The server database is disposable*). So
at-least-once delivery survives a "mailbox full" rejection: once the recipient
polls and drains the mailbox, the held-back messages get through on the next
flush.

## What the server sees

The server sees metadata:

- who messages whom,
- when messages are sent and received,
- how often users communicate,
- message sizes,
- public key material.

This is an accepted leak in v1. End-to-end encryption protects message
content, not the social graph.

The server does not see:

- plaintext,
- private keys,
- users' self-chosen display names,
- your local peer names,
- reusable credentials.

It also cannot safely substitute keys. A user ID is the fingerprint of the
user's public keys. Clients recompute that fingerprint for every key lookup
and refuse mismatches with `PIN MISMATCH`.

## The server database is disposable

The durable state that matters lives on clients:

- identities,
- private keys,
- Olm sessions,
- saved peers,
- unacknowledged outgoing messages.

If the server loses its database, clients can recover:

1. The next command notices missing public keys.
2. The client republishes its public keys.
3. Senders re-upload unacknowledged outbox messages.
4. Recipients ignore duplicates they already processed.

The server is useful, but it is not the root of identity or trust.

## Inspect the local demo

While the README demo is running:

```sh
sqlite3 server.db '.tables'
# messages  nonces  otks  users

sqlite3 server.db 'SELECT id, substr(identity_key,1,16) FROM users'
# public keys only

sqlite3 server.db 'SELECT sender, recipient, substr(body,1,32) FROM messages'
# base64 ciphertext; delivered rows disappear
```

## One-time prekeys

One-time prekeys let someone start an encrypted session with you while you
are offline.

The flow:

1. You generate a batch of one-time keypairs.
2. You keep the private halves in your encrypted local store.
3. You upload the public halves to the server.
4. A sender claims one public prekey when starting a new session with you.
5. The sender uses it for the first encrypted handshake message.
6. You later consume the matching private half when receiving that message.

The server stores public halves only. A public prekey lets someone encrypt a
handshake to the owner. It does not let the server read messages or
impersonate the sender.

The worst a hostile server can do with prekeys is deny service: refuse to
serve them, drain them, or serve the fallback key instead. It still cannot
decrypt the resulting messages without private keys.

See [olm.md](olm.md) for the full explanation.

Quick local check:

```python
import vodozemac as v

acct = v.Account()
acct.generate_one_time_keys(2)

print({k: p.to_base64() for k, p in acct.one_time_keys.items()})
# Public halves, safe to upload.

print(acct.pickle(b"0" * 32)[:24], "...")
# Encrypted local account data. Private halves do not leave the account.
```

## Nonces

Every server request is signed. A signature proves the request is genuine,
but an exact copy of a genuine request is also genuine unless the server
detects replay.

That is what nonces are for.

Each request includes a fresh random nonce. The nonce is covered by the
signature, so an attacker cannot replace it. The server remembers recently
seen nonces. If the same nonce appears again, the request is rejected as a
replay.

The table stays small because signatures also include timestamps. Requests
older than about 2.5 minutes are rejected, so nonces only need to be kept for
that short window.

Replay example:

```python
from retalk import User

u = User("http://127.0.0.1:8766", "alice-secret", store="alice/store.db")
wire = {"auth": u._auth_fields("read_messages", {})}

print(u._call_raw("read_messages", wire))
# First copy works.

u._call_raw("read_messages", wire)
# RuntimeError: server error from read_messages: replay detected: nonce already used
```

## Why requests are authenticated

The server cannot read ciphertext, but unauthenticated access would still be
dangerous.

Without authentication:

- Anyone could drain your mailbox by calling `read_messages` as your ID. They
  could not decrypt the messages, but the server would delete them before you
  received them.
- Anyone could submit ciphertext labeled as another sender. Recipients would
  waste keys and CPU on forgeries, and delivery failures would be harder to
  understand.

An unauthenticated request is rejected:

```sh
curl -s -X POST http://127.0.0.1:8766 -d '{"tool":"read_messages","args":{}}'
# {"error": "read_messages() missing 1 required positional argument: 'auth'"}
```

## How authentication works

Every request carries an `auth` object:

- user ID,
- public identity key,
- public signing key,
- timestamp,
- nonce,
- Ed25519 signature.

The signature covers the tool name, this server's public URL, the user ID,
the timestamp, the nonce, and a hash of the request arguments.

The server checks that:

- the public keys hash to the claimed user ID,
- the timestamp is fresh,
- the signature is valid,
- the nonce has not been used before.

There is no registration step. Publishing keys creates the server-side
mailbox. Full details and the exact wire format are in [auth.md](auth.md).

Example auth object:

```python
import json
from retalk import User

u = User("http://127.0.0.1:8766", "alice-secret", store="alice/store.db")
print(json.dumps(u._auth_fields("read_messages", {}), indent=2))
```

Shape:

```json
{
  "fingerprint": "1247d297...",
  "identity_key": "fkF/kOCL...",
  "signing_key": "Kcx2OupV...",
  "timestamp": "1781731882",
  "nonce": "c0ffee...",
  "signature": "mF90aaQz..."
}
```

Nothing in that object is secret. The private signing key is needed to
produce `signature`, but it is not sent.

ID squatting is not useful. To use an ID, the caller must produce signatures
from keys that hash to that ID.

Open access is the default. Anyone who can reach the server can publish keys
and get a mailbox. For a closed deployment, restrict access with a firewall
or reverse-proxy authentication.

## Display names

The server sees no display names.

There are two kinds:

- **Self-chosen name**: stored inside encrypted messages. Recipients can read
  it, but it is unverified, so clients display it as `~name`.
- **Peer name**: your local label for a user ID, created with
  `retalk add bob <id>`. It never leaves your machine and overrides the
  sender's self-chosen name.

Trust IDs and saved peer names, not self-chosen names.

Example:

```sh
retalk receive --all --dir ./bob
# ~alice: hello

retalk add boss "$ALICE_ID" --dir ./bob
retalk receive --all --dir ./bob
# boss: are we still on for tomorrow?
```

## Hostile server behavior

- **Read message bodies:** fails. The server stores ciphertext only.
- **Read private keys:** fails. Private keys never leave clients.
- **Swap public keys to man-in-the-middle a user:** clients detect the
  fingerprint mismatch and refuse with `PIN MISMATCH`.
- **Forge a message from Alice:** fails. Message decryption is bound to
  Alice's identity key.
- **Capture credentials usable elsewhere:** fails. There are no bearer tokens,
  and signatures are bound to this server URL.
- **Replay an old request:** rejected by nonce or timestamp checks.
- **Replay old ciphertext:** rejected by the Olm ratchet. Duplicates are
  re-acked and dropped.
- **Drop or delay messages:** possible. Senders keep unacknowledged ciphertext
  in an outbox and resend later.
- **Lose the database:** recoverable. Clients republish keys and resend
  unacknowledged messages.
- **Drain one-time prekeys:** possible denial-of-service pressure.
  `maintain()` replenishes keys, and fallback keys keep new sessions
  available.
- **Serve fallback keys while withholding one-time keys:** weakens forward
  secrecy for new sessions until fallback rotation. Daily rotation bounds the
  exposure.
- **Watch metadata:** possible and accepted in v1. Padding and cover traffic
  are future work.
