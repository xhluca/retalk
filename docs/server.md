# The server: what it does, what it knows, and why authentication exists

The server is a relay. It does two things: it holds ciphertext in a
**mailbox** until the recipient polls for it, and it serves a **public-key
directory** of the keys users publish. Everything else (encryption,
identity, trust) happens on the clients. This doc covers the server's
mechanics and the reasoning behind them.

The snippets below are runnable. They assume the two-minute demo from the
README: server on `http://127.0.0.1:8766`, an identity in `./alice`,
`SERVER_URL` exported, and `PICKLE_SECRET=alice-secret`.

## What the server stores and sees

It stores four tables (schema in `src/retalk/server.py`):

- `users` — user ID and public keys (identity, signing, fallback). All public
  material; there are no accounts and no credentials.
- `otks` — published one-time prekeys (public halves only) and whether each
  has been claimed.
- `messages` — opaque base64 ciphertext, sender/recipient IDs, timestamps. A
  message is **deleted the moment it's delivered**, so the server only holds
  mail that's still in flight.
- `nonces` — random one-use numbers from recent requests, kept to block
  replays (explained below).

The database is **disposable**. The state that matters lives on the clients:
sessions and contacts in each user's store, unacknowledged mail in senders'
outboxes. If the server loses its disk, clients notice their keys are missing
on the next command, republish them, and re-send anything undelivered, and
the conversation continues.

What it sees is **metadata**: who messages whom, when, how often, and how big
the messages are. This is the design's accepted leak. E2EE protects content,
not the social graph.

What it can't see or do: plaintext (it has no keys), private keys (never
sent), forged content (messages are cryptographically bound to the sender's
identity key), or substituted keys (a user ID *is* the fingerprint of its
public keys, so clients detect any swap and refuse with PIN MISMATCH).

See for yourself. Open the server's database while the demo runs:

```sh
sqlite3 server.db '.tables'
# messages  nonces  otks  users
sqlite3 server.db 'SELECT id, substr(identity_key,1,16) FROM users'
# public keys only — no passwords, no tokens, no names
sqlite3 server.db 'SELECT sender, recipient, substr(body,1,32) FROM messages'
# base64 ciphertext; rows vanish once the recipient receives
```

## One-time keys (the `otks` table)

**What they are.** Each one-time key (OTK) is a small throwaway keypair. Like
any keypair it has two halves: a public half anyone may see and a private
half that stays secret. The `otks` table holds **public halves only**.

**What they do.** They let someone start an encrypted conversation with you
*while you're offline*. A handshake needs fresh input from both sides, but
the recipient might be asleep. So each user pre-makes a batch of OTKs and
parks the public halves at the server. When Alice first messages Bob, she
claims one of Bob's OTKs and finishes the handshake on her own, instantly.
Each OTK is used once and then destroyed, which is what keeps recorded
traffic undecryptable even if long-term keys are stolen later (forward
secrecy). Details: [olm.md](olm.md).

**How they're generated.** Always by the user, never by the server. The
user's machine generates them (100 at a time), keeps the private halves in
its encrypted local store, and uploads only the public halves
(`publish_keys`). When the server reports the pool is low, the client
generates and uploads more (`maintain()`, run automatically by `retalk
receive --follow`). The server only hands back keys that users pre-stocked.

**Why server storage is safe.** A public OTK half lets you do exactly one
thing: encrypt a handshake *to* its owner. That's its purpose, and the server
is free to do it under its own identity like anyone else. It does not let the
server:

- *read* messages sent to the owner (that needs the private half, which never
  left the owner's machine);
- *impersonate the sender* (a message's sender identity comes from the
  sender's private identity key, which the server also lacks; a forged "from
  Alice" message fails decryption on arrival and is discarded);
- *swap in a poisoned OTK whose private half it knows* (the handshake also
  mixes in the recipient's identity key, so the server still can't derive the
  session secret; the handshake just fails).

The worst a hostile server can do with this table is refuse to hand keys out
or drain them, which is denial of service, never reading or forging. That's
the general rule: everything the server stores is public material,
ciphertext, or bookkeeping.

The two halves, in code (`uv run python`):

```python
import vodozemac as v

acct = v.Account()                    # this is what lives on a user's machine
acct.generate_one_time_keys(2)
print({k: p.to_base64() for k, p in acct.one_time_keys.items()})
# {'AAAAAAAAAAE': 'fkF/kOCL...', ...}   <- public halves: uploaded to the server

# the private halves never leave `acct`; the only way out is encrypted:
print(acct.pickle(b"0" * 32)[:24], "...")
# 'P1OFSAID0+ULXj4m...'                 <- what store.db actually contains
```

## Nonces (the `nonces` table)

**The attack this stops.** Every request to the server is signed, and a
signature proves the request is genuine. But a *copy* of a genuine request is
still genuine. Someone who captures one of your requests (say, from a proxy
log on a no-TLS setup) could submit the copy again. For example,
resubmitting your captured `read_messages` would make the server mark your
new mail as already delivered, so you'd never see it.

**How it works.** Each request includes a nonce, a large random number the
client generates fresh every time ("number used once"). The nonce is covered
by the signature, so it can't be swapped out. The server keeps every nonce
it has seen; if the same one arrives again, that's by definition a replayed
copy, and it's rejected ("replay detected").

**Why the table stays small.** Signatures also include a timestamp, and the
server rejects anything older than ~2.5 minutes outright. So a nonce only
needs to be remembered for that window; replays older than the window already
fail the timestamp check. The server deletes expired nonces on every
request, so the table never grows beyond a few minutes of traffic.

Watch a replay get caught (`uv run python`):

```python
from retalk import User

u = User("http://127.0.0.1:8766", "alice-secret", store="alice/store.db")
wire = {"auth": u._auth_fields("read_messages", {})}   # one signed request
print(u._call_raw("read_messages", wire))              # first copy: works -> []
u._call_raw("read_messages", wire)                     # identical copy:
# RuntimeError: server error from read_messages: replay detected: nonce already used
```

## Why calls are authenticated at all

The ciphertext is unreadable, so why authenticate callers? Because the
mailbox needs an owner. Without authentication:

- **Anyone could drain your inbox.** `read_messages` hands over your pending
  mail and deletes it. An attacker claiming your ID would receive your
  (undecryptable) ciphertext, and it would be gone from the server, so *you*
  never see those messages. That's a silent, total denial of service, and the
  attacker harvests your metadata too.
- **The sender label would be a lie.** The server stamps each message with
  the authenticated caller's ID. Without authentication, anyone could send
  junk labeled as someone else; recipients would waste one-time keys and CPU
  failing to decrypt forgeries, and real delivery problems would be
  indistinguishable from spam.

An unauthenticated request is refused at the door:

```sh
curl -s -X POST http://127.0.0.1:8766 -d '{"tool":"read_messages","args":{}}'
# {"error": "read_messages() missing 1 required positional argument: 'auth'"}
```

## How callers are authenticated

Every request is **self-signed**. It carries the caller's public keys, a
timestamp, a one-time random number, and an ed25519 signature binding all of
it (plus the tool name, arguments, and this server's URL) to the caller's
user ID. The server verifies the signature and that the keys hash to the
claimed ID. No accounts, no tokens, no registration, nothing credential-like
stored on either side. Onboarding to a server is just `publish_keys` (which
also creates the mailbox). Full explanation and wire format:
[auth.md](auth.md).

The user ID is the sha256 fingerprint of the user's public keys, so the
binding is enforced twice: the server rejects published keys that don't hash
to the caller's ID, and every *client* re-checks the fingerprint of any keys
the server serves.

What one auth object looks like (`uv run python`):

```python
import json
from retalk import User

u = User("http://127.0.0.1:8766", "alice-secret", store="alice/store.db")
print(json.dumps(u._auth_fields("read_messages", {}), indent=2))
# {
#   "user_id":      "1247d297...",   <- sha256(public keys), 32 hex chars
#   "identity_key": "fkF/kOCL...",   <- public, anyone may see
#   "signing_key":  "Kcx2OupV...",   <- public
#   "ts":           "1781731882",    <- request expires ~2.5 min later
#   "nonce":        "c0ffee...",     <- random, single-use (see above)
#   "sig":          "mF90aaQz..."    <- ed25519 over all of it + the tool + URL
# }
```

Nothing in it is secret. The signature can only be *produced* with the
private key, but anyone may look at the object.

**ID squatting** isn't possible: there's nothing to squat. Using an ID at all
requires producing signatures from keys that hash to it, which only the keys'
owner can do.

**Open access** is the default: anyone who can reach the server can publish
keys and get a mailbox. Firewall the server or add auth at the reverse proxy
for a closed deployment.

## Self-chosen names vs peer names

There are two kinds of display name, and the server sees neither:

- A sender's **self-chosen name** travels *inside the encrypted message*, so
  only recipients can read it. It's unverified text (anyone can call
  themselves `alice-1`), so clients show it with a `~` prefix.
- A **peer name** is the label *you* save locally for a peer ID (`retalk add
  bob <id>`). It never leaves your machine, and it always overrides the
  sender's `~name` in display.

Trust the ID, never the self-chosen name.

```sh
# bob hasn't saved alice -> sees her unverified self-chosen name:
retalk receive -s ./bob
# ~alice: hello

# after saving a peer name, his label wins:
retalk add boss "$ALICE_ID" -s ./bob
retalk receive -s ./bob
# boss: are we still on for tomorrow?
```

## What a hostile server can still do, and the countermeasures

| Hostile action | Outcome |
|---|---|
| Read message bodies | Impossible: ciphertext only |
| Swap directory keys to MITM | Detected: fingerprint/pin check refuses |
| Forge a message "from Alice" | Impossible: decryption is bound to the sender's key |
| Capture credentials usable elsewhere | Impossible: request signatures are bound to this server's URL |
| Drop or delay messages | Detected over time: unacked outbox entries; sender re-sends (possibly via a new server) |
| Replay old ciphertext | Rejected: the ratchet refuses re-used message keys |
| Serve the fallback key while hoarding one-time keys | Slightly weakens forward secrecy for new sessions; bounded by fallback rotation (daily) |
| Watch metadata | Accepted leak for v1 (padding/cover traffic is future work) |
