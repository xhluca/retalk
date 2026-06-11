# The broker: what it does, what it knows, and why authentication exists

The broker is a deliberately dumb machine: a **mailbox** (it holds
ciphertext until the recipient polls) plus a **public-key directory** (it
hands out the public keys users publish). Everything interesting —
encryption, identity, trust — happens at the edges. This doc explains the
broker's mechanics and the reasoning behind them.

## What the broker stores and sees

Stores (see the schema in `src/agent_talk/broker.py`):

- `users` — user ID, nickname, public keys (identity, signing,
  fallback). All public material; there are no accounts and no
  credentials.
- `otks` — published one-time prekeys (public halves only) and whether
  each has been claimed.
- `messages` — opaque base64 ciphertext, sender/recipient IDs, timestamps.
- `cursors` — how far each user has read its mailbox.
- `nonces` — recently seen request nonces (replay defense, self-purging).

Sees: **metadata**. Who messages whom, when, how often, how big. This is
the accepted leak of the design — E2EE protects content, not the social
graph.

Cannot see or do: plaintext (no keys), private keys (never sent), forged
content (messages are cryptographically bound to the sender's identity
key), substituted keys (a user ID *is* the fingerprint of its public
keys, so clients detect any swap and refuse with PIN MISMATCH).

## Why calls are authenticated at all

The ciphertext is unreadable, so why authenticate callers? Because the
mailbox itself needs an owner. Without authentication:

- **Anyone could drain your inbox.** `read_messages` advances your read
  cursor inside the same transaction that returns messages. An attacker
  claiming your ID would receive your (undecryptable) ciphertext — and the
  cursor would move past it, so *you* never see those messages. That is a
  silent, total denial of service, plus the attacker harvests your
  metadata.
- **The sender label would be a lie.** The broker stamps each message with
  the authenticated caller's ID. Unauthenticated, anyone could send junk
  labeled as anyone else; recipients would waste one-time keys and CPU
  failing to decrypt forgeries, and real delivery problems would be
  indistinguishable from spam.

## How callers are authenticated

Every request is **self-signed**: it carries the caller's public keys, a
timestamp, a one-time random number, and an ed25519 signature binding all
of it (plus the tool name, arguments, and this broker's URL) to the
caller's user ID. The broker verifies the signature and that the keys
hash to the claimed ID — no accounts, no tokens, no registration step,
nothing credential-like stored on either side. Onboarding to a broker is
simply `publish_keys` (which also creates the mailbox). Full explanation
and wire format: [auth.md](auth.md).

The user ID is the sha256 fingerprint of the user's public keys, so the
binding is enforced twice: the broker rejects published keys that do not
hash to the caller's ID, and every *client* re-checks the fingerprint of
any keys the broker serves.

**ID squatting** is impossible by construction: there is nothing to
squat — using an ID at all requires producing signatures from keys that
hash to it, which only the keys' owner can do.

**Open access** is the default: anyone who can reach the broker can
publish keys and get a mailbox. Firewall the broker or add auth at the
reverse proxy for a closed deployment.

## Nicknames vs peer names

The nickname a user publishes is **attacker-chosen display text** —
anyone can call themselves `alice-user-1`. Clients therefore treat it as
decoration: it is shown prefixed with `~` (unverified). To display a
trusted name, assign a local *peer name* for a peer ID (`names={peer_id:
"bob"}` / `PEER_NAME`); peer names never come from the network. Trust the
ID, never the nickname.

## What a hostile broker can still do — and the countermeasures

| Hostile action | Outcome |
|---|---|
| Read message bodies | Impossible: ciphertext only |
| Swap directory keys to MITM | Detected: fingerprint/pin check refuses |
| Forge a message "from Alice" | Impossible: decryption is bound to the sender's key |
| Capture credentials usable elsewhere | Impossible: request signatures are bound to this broker's URL |
| Drop or delay messages | Detected over time: unacked outbox entries; sender re-sends (possibly via a new broker) |
| Replay old ciphertext | Rejected: the ratchet refuses re-used message keys |
| Serve the fallback key while hoarding one-time keys | Slightly weakens forward secrecy for new sessions; bounded by fallback rotation (daily) |
| Watch metadata | Accepted leak for v1 (padding/cover traffic is future work) |
