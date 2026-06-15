# How users prove who they are (signed requests)

This page explains how a user proves to the server that a request really
came from them, without accounts, passwords, tokens, or registration. No
security background needed.

## The problem

The server keeps one mailbox per user. Mail is encrypted, so a thief can't
read it. But `read_messages` also marks mail as delivered. If anyone could
call it while claiming to be you, they could make your messages disappear
before you ever poll for them. So every request has to prove who's calling.

## The usual way, and why we don't use it

Most internet services use a **bearer token**: a long secret string sent
with every request. Whoever holds it is treated as the owner. That works,
but the token becomes a thing to steal. It sits in a file on your disk, it
crosses the network on every call, and it can end up in logs or proxies.
Anyone who sees it once can act as you until you rotate it.

Our users already have something better: a **keypair**. A keypair is two
linked numbers, a private key that never leaves your machine and a public key
anyone can see. The private key can produce a **signature** for any piece of
data. A signature has two useful properties:

1. only the private-key holder could have produced it, and
2. anyone with the public key can check it, and the check fails if even one
   character of the signed data changed.

So instead of sending a reusable token, each request carries a fresh
signature that says "I, the holder of this key, approve exactly this
request." Nothing on the wire can be reused, and there's no secret to store
beyond the keys the user already has.

## What exactly gets signed

A signature only vouches for the bytes that went into it. Anything left out
can be swapped by an attacker while the signature stays valid. So the signed
text bundles together everything that defines the request:

```
tool | server URL | user ID | timestamp | nonce | hash of the arguments
```

Each field exists for a reason:

- **tool** — a signature made for the harmless `count_keys` can't be reused
  to authorize `read_messages`.
- **server URL** — a request captured at one server is rejected at every
  other server. This is why the server's `SERVER_AUDIENCE` setting must
  exactly match the URL users connect to.
- **user ID** — says who is calling. The ID is the fingerprint (a one-way
  hash) of the user's public keys, so the server can check that the keys in
  the request really belong to this ID without keeping any user table.
- **timestamp** — a captured request expires after ~2.5 minutes instead of
  being valid forever.
- **nonce** (a random number used once) — closes the remaining gap. The
  server remembers recently seen nonces and rejects an exact re-submission
  even inside the time window.
- **hash of the arguments** — a signed "send to Bob" can't be replayed as
  "send to Charlie".

## What the server checks, step by step

For every call the server: (1) hashes the keys in the request and compares
with the claimed user ID; (2) checks the timestamp is within ±150 seconds;
(3) rebuilds the signed text from its own copy of each field and verifies the
signature against the caller's public key; (4) checks the nonce is new, then
remembers it (old nonces are purged automatically). Any failure rejects the
request with a reason. The whole check costs about 4 ms per request.

## What an attacker gets

- **Sniffing traffic (operator skipped TLS):** they see ciphertext and
  signatures. Nothing they capture lets them issue new requests, because
  there's no token to steal. Use TLS anyway; it also hides metadata in
  transit.
- **A fully compromised server:** it can always mess with its own database
  (drop your mail, refuse service); no auth scheme prevents that. What it
  cannot do is impersonate you elsewhere, because it never sees anything that
  works at another server.
- **Your store file stolen (without your `PICKLE_SECRET`):** the signing key
  is encrypted at rest, and there's no other credential in the file. The
  thief can't call the server as you at all.

## Requirements and limits

- **A roughly correct clock.** Requests with timestamps off by more than
  ~2.5 minutes are rejected ("stale or future timestamp"). Any machine
  running NTP is fine; a badly wrong clock is the one new failure mode this
  design adds.
- **`SERVER_AUDIENCE` must be configured** on the server to the exact URL
  users use. If they disagree, every request fails signature verification
  (loudly, so the misconfiguration is obvious).
- The server keeps a small, self-purging table of recent nonces.

## For reimplementers: the exact wire format

If you implement a user client in another language, the bytes have to match
exactly. This is the part of the design where "almost the same" fails
silently.

- Arguments hash: `sha256` over the JSON encoding of the tool's business
  arguments (everything except `auth`) with **keys sorted**, separators `,`
  and `:` (no spaces), and every parameter present explicitly. Optional
  parameters are included as `null`, never omitted.
- Signed text: the six fields joined with `|` (pipe), encoded as UTF-8:
  `tool|server_url|user_id|ts|nonce|args_hash`. `ts` is integer seconds since
  epoch, as a decimal string. `nonce` is 32 hex characters.
- Signature: ed25519 over those bytes, base64. The `auth` object sent with
  each call is `{user_id, identity_key, signing_key, ts, nonce, sig}`.
- User ID: `sha256(identity_key_b64 + "|" + signing_key_b64)`, hex, first 32
  characters.

## Why we chose this over tokens (decision record)

We built and tested both. Tokens are the industry default and simpler to
reason about, but measurement flipped the decision for this project. The
signed version is *fewer* lines (deleting registration and token plumbing
outweighed the signing code), costs ~4 ms per request, and all three attack
defenses (replay, stale timestamp, wrong server) are covered by permanent
tests. The security wins that decided it: self-hosters who skip TLS don't
fall all the way to a full mailbox takeover, a stolen store file holds no
usable credential, and identity is one mechanism (the keys) instead of two
(keys plus a token lifecycle). The accepted costs: users need a working
clock, the server needs the vodozemac library, and the byte format above is
a contract that reimplementations must follow exactly.
