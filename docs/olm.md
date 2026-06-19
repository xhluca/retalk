# One-time prekeys and fallback keys

Users upload a batch of public one-time prekeys when they publish their keys.
Those prekeys are the least obvious part of retalk. They exist so another
user can start an encrypted session with you while you are offline.

## The key types

Retalk uses several kinds of keys:

- **Identity key**: long-lived public key. It is part of the user ID
  fingerprint and is what peers pin.
- **Signing key**: long-lived public key. It authenticates server requests and
  is also part of the user ID fingerprint.
- **One-time prekeys**: short-lived public keys used to start new sessions.
  Each one is used at most once.
- **Fallback key**: reusable prekey used only when the one-time prekey pool is
  empty.

The server stores public key material only. Private halves stay in the user's
encrypted local store.

## Why one-time prekeys exist

Suppose "Alice" wants to message "Bob" while "Bob" is offline. A normal handshake
needs fresh key material from both sides, but "Bob" is not there to answer.

Olm solves this by letting "Bob" prepare handshake material ahead of time:

1. "Bob" generates a batch of one-time keypairs.
2. "Bob" keeps the private halves locally.
3. "Bob" uploads the public halves to the server.
4. "Alice" claims one public prekey when she sends the first message.
5. "Alice" creates an outbound session immediately.
6. "Bob" later receives the pre-key message and creates the matching inbound
   session with the private half he kept.

In code, "Alice"'s first `send` calls `claim_key` and then
`create_outbound_session`. "Bob"'s `receive` sees a pre-key message
(`mtype == 0`) and calls `create_inbound_session`.

## Why each prekey is single-use

One-time prekeys are consumed once for two reasons.

Forward secrecy:

After "Bob" uses a prekey, "Bob" deletes the private half. If "Bob"'s machine is
stolen later, that deleted prekey cannot be recovered and used to reconstruct
old session starts.

Replay resistance:

The server is not trusted. If prekeys were reusable, a hostile server could
replay old handshake messages and make "Bob" create duplicate sessions or
reprocess old traffic. With single-use keys, a replayed handshake refers to a
private half that has already been deleted, so it fails.

The server also claims one-time keys inside a `BEGIN IMMEDIATE` transaction.
That ensures two concurrent senders cannot receive the same prekey.

## Not one key per message

Prekeys are used to start sessions, not to encrypt every message.

After a session exists, Olm handles message ratcheting inside that session.
"Alice" and "Bob" can exchange many messages while consuming only one one-time
prekey for the original handshake.

The pool drains only when new sessions are created. That can happen when:

- a peer contacts you for the first time,
- a peer loses its local store and must handshake again,
- a server or attacker drains keys by repeatedly calling `claim_key`, or
- many independent users start sessions with you.

## Replenishment

The default publish uploads 100 one-time prekeys. The pool only shrinks, so
clients need to refill it.

`User.sync()` calls `count_keys`. If fewer than `min_otks` keys remain
unclaimed, it generates and uploads a new batch.

Defaults:

- `min_otks=20`
- `batch=100`

`retalk receive --all --follow` runs this key upkeep — a `sync(resend=False)`
pass — every minute. Resending unacknowledged messages is a separate step
(`send` and the explicit `retalk sync` command do it; `receive` never does).

Without replenishment, an empty pool would stop new sessions from starting.
Existing sessions would still work.

## Fallback key

The fallback key is a reusable backup prekey.

The server returns it only when the one-time prekey pool is empty, and marks
the response with `"fallback": true`.

This trades some forward secrecy for availability. A reusable key is weaker
than a true one-time key, but it prevents an empty prekey pool from becoming a
complete denial of service for new sessions.

## Fallback rotation

Because the fallback key is reusable, it should not live forever.

`maintain()` rotates it when it is older than `fallback_max_age` seconds. The
default is `86400`, or one day.

Rotation means:

1. Generate a new fallback key.
2. Publish it to the server.
3. Record the local rotation time.

vodozemac keeps the previous fallback private key alive through one rotation.
That gives in-flight handshakes time to arrive. After a second rotation, the
older fallback key is gone. A very stale handshake can then fail with an
unknown one-time-key error, and the sender must handshake again.

With daily rotation, in-flight messages have about a 24-48 hour grace window.

## Summary

One-time prekeys are disposable handshake ingredients. They let users start
sessions while recipients are offline, and they are deleted after use so old
session starts stay protected.

`maintain()` keeps the pool from running dry and rotates the fallback key so
the reusable backup stays short-lived.
