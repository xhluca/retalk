# One-time prekeys: why users upload a batch of keys, and why they run out

The least obvious part of this system is the batch of 100 keys each user
uploads via `publish()`. This doc explains what they are, why each is used
only once, and how the pool is kept healthy (replenishment and fallback-key
rotation).

## Two different kinds of keys

Each user has one **identity key** that never changes. That's the value a peer
pins out-of-band; it's hashed into the user ID, and `retalk add --pin` adds an
explicit full-key pin. The 100 keys uploaded by `publish()` are **one-time
prekeys**, and they do something different: they're single-use ingredients
for *starting a session*, not keys that encrypt messages.

## The problem one-time prekeys solve

Say A wants to start an encrypted conversation with B, but B is offline (B is
just a poll loop that might not run for an hour). A handshake normally needs
both parties live to exchange fresh randomness. The Olm/Signal trick: B
pre-generates a batch of throwaway keypairs, keeps the private halves locally,
and parks the public halves at the server. When A wants to talk, A calls
`claim_key`, takes one prekey, and completes the handshake alone, immediately,
while B is asleep. When B wakes up and reads the pre-key message, B finds the
matching private half and finishes its side.

That's what happens in `retalk/user.py`: A's first `send` to a peer claims one
prekey and calls `create_outbound_session`; B's `receive` sees the pre-key
message (`mtype == 0`) and calls `create_inbound_session`, which consumes the
key.

## Why each prekey is used only once

Two reasons:

1. **Forward secrecy.** Each session's initial secret is mixed from that
   one-time key. After B consumes it, B deletes the private half. If someone
   later steals B's machine, they can't reconstruct the start of any past
   session, because the ingredient no longer exists. If the same prekey were
   reused for every session, it would become a long-lived secret whose theft
   would retroactively break every session that used it.
2. **Replay protection.** The server is hostile in our trust model. If
   prekeys were reusable, the server could replay an old handshake message
   back at B and trick B into creating duplicate sessions or re-processing old
   traffic. Single-use means a replayed handshake just fails, because the
   private half is already gone.

This is also why the server's `claim_key` marks the key claimed inside a
`BEGIN IMMEDIATE` transaction: each key must be handed out at most once, even
under concurrent claims.

## This is *not* "a new key every message"

After the handshake, the session does its own internal ratcheting (the Olm
double ratchet) and never touches the one-time key pool again. A and B can
exchange a million messages on one session and consume exactly **one** prekey
total. The pool only drains when *new sessions* are established.

## Why replenishment matters

The pool is finite (we upload 100) and it only shrinks. It drains when peers
legitimately start new sessions, when a peer clears its local store and has to
re-handshake, or maliciously: anyone who can reach the server can call
`claim_key("b")` 100 times and empty B's pool. Without a countermeasure, an
empty pool would mean **nobody can start a new conversation with B** until B
publishes again. Existing sessions keep working; new ones couldn't form.

Two countermeasures close this gap, both implemented:

- **Replenishment.** `User.maintain()` asks the server how many of the user's
  keys remain unclaimed (the `count_keys` tool) and uploads a fresh batch of
  `batch` keys (default 100) whenever the count drops below `min_otks`
  (default 20). It's cheap, since generating them is just
  `generate_one_time_keys(n)`. `retalk receive --follow` calls `maintain()`
  every minute.
- **Fallback key.** One special *reusable* prekey (`generate_fallback_key()`),
  published on the first `publish()` and stored in the server's `users` table.
  The server's `claim_key` hands it out (with a `"fallback": true` flag) only
  when the one-time pool is empty. It trades a little forward secrecy (it's
  reusable until rotated) for availability, so the drain attack stops being a
  denial of service.

## Fallback-key rotation

Because the fallback key is reusable, it shouldn't live forever: the longer it
sits, the more session-starts a future compromise of it would expose.
`maintain()` auto-rotates it once it's older than `fallback_max_age` seconds
(default 86400, i.e. daily). Rotation is just `generate_fallback_key()` plus a
re-publish; the user records the rotation time locally in its `meta` table.

Rotation has a built-in grace window. vodozemac keeps the *previous* fallback
key's private half alive through exactly one rotation, so a handshake message
that was in flight to the old fallback key still decrypts after the key has
rotated once. Only after a second rotation is the old key truly gone; then a
stale handshake fails with an "unknown one-time key" error and the sender has
to re-handshake. With daily rotation, that gives in-flight messages a ~24-48
hour window, far more than enough for a polling loop.

## Summary

It's not "a new key every time we send." It's one disposable ingredient per
*handshake*, disposable so that past conversations stay secret even if a
machine is later compromised. `maintain()` keeps the pool from running out and
retires the reusable emergency key daily.
