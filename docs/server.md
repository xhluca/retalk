# The server: what it does, what it knows, and why authentication exists

Architecturally the server is a *message broker* — an intermediary that
only stores and forwards sealed messages between parties, with no part in
producing or reading them. We just call it "the server" throughout. It is
a deliberately dumb machine: a **mailbox** (it holds
ciphertext until the recipient polls) plus a **public-key directory** (it
hands out the public keys users publish). Everything interesting —
encryption, identity, trust — happens at the edges. This doc explains the
server's mechanics and the reasoning behind them.

## What the server stores and sees

Stores (see the schema in `src/retalk/server.py`):

- `users` — user ID, self-chosen name, public keys (identity, signing,
  fallback). All public material; there are no accounts and no
  credentials.
- `otks` — published one-time prekeys (public halves only) and whether
  each has been claimed.
- `messages` — opaque base64 ciphertext, sender/recipient IDs,
  timestamps. A message is **deleted the moment it is delivered**, so the
  server holds only mail in flight.
- `nonces` — random one-use numbers from recent requests, kept to block
  replays (explained below).

Sees: **metadata**. Who messages whom, when, how often, how big. This is
the accepted leak of the design — E2EE protects content, not the social
graph.

Cannot see or do: plaintext (no keys), private keys (never sent), forged
content (messages are cryptographically bound to the sender's identity
key), substituted keys (a user ID *is* the fingerprint of its public
keys, so clients detect any swap and refuse with PIN MISMATCH).

## One-time keys (the `otks` table)

**What they are.** Each one-time key (OTK) is a small throwaway keypair.
Like every keypair it has two halves: a public half anyone may see, and a
private half that must stay secret. The `otks` table holds **public
halves only**.

**What they do.** They let someone start an encrypted conversation with
you *while you are offline*. A handshake needs fresh input from both
sides, but the recipient may be asleep — so each user pre-makes a batch
of OTKs and parks the public halves at the server. When Alice first
messages Bob, she claims one of Bob's OTKs and finishes the handshake
alone, instantly. Each is used once and then destroyed, which is what
makes recorded traffic undecryptable even if long-term keys are stolen
later (forward secrecy). Details: [olm.md](olm.md).

**How they are generated.** Always by the user, never by the server. The
user's own machine generates them (100 at a time), keeps the private
halves in its encrypted local store, and uploads only the public halves
(`publish_keys`). When the server reports the pool is low, the user's
client generates and uploads more (`maintain()`, run automatically by
`retalk receive --follow`). The server is just a vending machine for
keys that users pre-stocked.

**Why server storage is safe.** A public OTK half lets you do exactly one
thing: encrypt a handshake *to* its owner — which is its purpose, and
something the server is welcome to do under its own identity like anyone
else. It does not let the server:

- *read* messages sent to the owner (needs the private half, which never
  left the owner's machine);
- *impersonate the sender* (a message's sender identity comes from the
  sender's private identity key, which the server also lacks — a forged
  "from Alice" message fails decryption on arrival and is discarded);
- *swap in a poisoned OTK it knows the private half of* (the handshake
  also mixes in the recipient's identity key, so the server still can't
  derive the session secret — the handshake just fails).

The worst a hostile server can do with this table is refuse to hand keys
out or drain them — denial of service, never reading or forging. That is
the design's general rule: everything the server stores is public
material, ciphertext, or bookkeeping.

## Nonces (the `nonces` table)

**The attack this stops.** Every request to the server is signed, and a
signature proves the request is genuine — but a *copy* of a genuine
request is still genuine. Someone who captures one of your requests (say,
from a proxy log on a no-TLS setup) could submit the copy again. Example:
resubmitting your captured `read_messages` would make the server mark
your new mail as already delivered, so you'd never see it.

**How it works.** Each request includes a nonce — a large random number
the client generates fresh every time ("number used once") — and the
nonce is covered by the signature, so it can't be swapped out. The server
keeps each nonce it has seen; if the same one ever arrives again, that is
by definition a replayed copy, and it is rejected ("replay detected").

**Why the table stays small.** Signatures also include a timestamp, and
the server rejects anything older than ~2.5 minutes outright. So a nonce
only needs to be remembered for that window — replays older than the
window already die on the timestamp check. The server deletes expired
nonces on every request; the table never grows beyond a few minutes of
traffic.

## Why calls are authenticated at all

The ciphertext is unreadable, so why authenticate callers? Because the
mailbox itself needs an owner. Without authentication:

- **Anyone could drain your inbox.** `read_messages` advances your read
  cursor inside the same transaction that returns messages. An attacker
  claiming your ID would receive your (undecryptable) ciphertext — and the
  cursor would move past it, so *you* never see those messages. That is a
  silent, total denial of service, plus the attacker harvests your
  metadata.
- **The sender label would be a lie.** The server stamps each message with
  the authenticated caller's ID. Unauthenticated, anyone could send junk
  labeled as anyone else; recipients would waste one-time keys and CPU
  failing to decrypt forgeries, and real delivery problems would be
  indistinguishable from spam.

## How callers are authenticated

Every request is **self-signed**: it carries the caller's public keys, a
timestamp, a one-time random number, and an ed25519 signature binding all
of it (plus the tool name, arguments, and this server's URL) to the
caller's user ID. The server verifies the signature and that the keys
hash to the claimed ID — no accounts, no tokens, no registration step,
nothing credential-like stored on either side. Onboarding to a server is
simply `publish_keys` (which also creates the mailbox). Full explanation
and wire format: [auth.md](auth.md).

The user ID is the sha256 fingerprint of the user's public keys, so the
binding is enforced twice: the server rejects published keys that do not
hash to the caller's ID, and every *client* re-checks the fingerprint of
any keys the server serves.

**ID squatting** is impossible by construction: there is nothing to
squat — using an ID at all requires producing signatures from keys that
hash to it, which only the keys' owner can do.

**Open access** is the default: anyone who can reach the server can
publish keys and get a mailbox. Firewall the server or add auth at the
reverse proxy for a closed deployment.

## Self-chosen names vs peer names

The name a user publishes is **attacker-chosen display text** —
anyone can call themselves `alice-user-1`. Clients therefore treat it as
decoration: it is shown prefixed with `~` (unverified). To display a
trusted name, assign a local *peer name* for a peer ID (`names={peer_id:
"bob"}` / `PEER_NAME`); peer names never come from the network. Trust the
ID, never the self-chosen name.

## What a hostile server can still do — and the countermeasures

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
