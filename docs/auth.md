# How users prove who they are (signed requests)

This page explains how a user convinces the broker "this request really
comes from me" — without accounts, passwords, tokens, or registration. It
assumes no security background.

## The problem

The broker keeps a mailbox per user. Mail is encrypted, so a thief can't
*read* it — but `read_messages` also marks mail as delivered. If anyone
could call it while claiming to be you, they could make your messages
vanish before you ever poll for them. So every request must prove who is
calling. The question is how.

## The usual way, and why we don't use it

Most internet services use a **bearer token**: a long secret string sent
with every request, like a coat-check ticket — whoever holds it, wins.
That works, but the ticket itself becomes a thing to steal: it sits in a
file on your disk, crosses the network on every call, and can end up in
logs or proxies. Anyone who sees it once *becomes you* until you rotate
it.

Our users already own something better: a **keypair**. A keypair is two
mathematically linked numbers — a private key that never leaves your
machine, and a public key anyone may see. The private key can produce a
**signature** for any piece of data: a short proof with two properties:

1. only the private-key holder could have produced it, and
2. anyone holding the public key can *check* it — and the check fails if
   even one character of the signed data was changed.

So instead of presenting a stealable ticket, each request carries a fresh
signature: "I, holder of this key, approve exactly this request." Nothing
that crosses the wire is reusable, and there is no secret to store beyond
the keys the user already has.

## What exactly gets signed

A signature only vouches for the bytes that went into it — anything left
outside can be swapped by an attacker while the signature stays valid. So
the signed text packs together everything that defines "this request":

```
tool | broker URL | user ID | timestamp | nonce | hash of the arguments
```

Each piece slams a specific door:

- **tool** — a signature made for the harmless `count_keys` can't be
  re-submitted as authorization for `read_messages`.
- **broker URL** — a request captured at one broker is rejected at every
  other broker. (This is why the broker's `BROKER_AUDIENCE` setting must
  exactly match the URL users connect to.)
- **user ID** — says who is calling. The ID is itself the *fingerprint*
  (a hash — a one-way scramble) of the user's public keys, so the broker
  can check "do the keys in this request really belong to this ID?"
  without keeping any user table.
- **timestamp** — a captured request expires after ~2.5 minutes instead
  of being valid forever.
- **nonce** (a random number used once) — closes the remaining gap: the
  broker remembers recently seen nonces and rejects an exact re-submission
  even inside the time window.
- **hash of the arguments** — your signed "send to Bob" can't be replayed
  as "send to Charlie".

## What the broker checks, step by step

For every call the broker: (1) hashes the keys in the request and compares
with the claimed user ID; (2) checks the timestamp is within ±150
seconds; (3) rebuilds the signed text from its own copy of each piece and
verifies the signature against the caller's public key; (4) checks the
nonce is new, then remembers it (old nonces are purged automatically). Any
failure rejects the request with a reason. Total cost: about 4 ms per
request.

## What an attacker gets

- **Sniffing traffic (operator skipped TLS):** they see ciphertext and
  signatures. Nothing they capture lets them issue new requests — there is
  no token to steal. (Use TLS anyway; it also hides metadata in transit.)
- **A fully compromised broker:** it could always mess with its own
  database (drop your mail, refuse service) — no auth scheme prevents
  that. What it *cannot* do is impersonate you elsewhere: it never sees
  anything reusable at another broker.
- **Your store file stolen (without your `PICKLE_SECRET`):** the signing
  key is encrypted at rest, and no other credential exists in the file. The
  thief cannot call the broker as you at all.

## Requirements and limits

- **A roughly correct clock.** Requests with timestamps off by more than
  ~2.5 minutes are rejected ("stale or future timestamp"). Any machine
  running NTP is fine; a badly wrong clock is the one new failure mode of
  this design.
- **`BROKER_AUDIENCE` must be configured** on the broker to the exact URL
  users use. If they disagree, every request fails signature verification
  (loudly, so misconfiguration is obvious).
- The broker keeps a small self-purging table of recent nonces.

## For reimplementers: the exact wire format

If you implement a user client in another language, the bytes must match
exactly — this is the part of the design where "almost the same" silently
fails.

- Arguments hash: `sha256` over the JSON encoding of the tool's business
  arguments (everything except `auth`) with **keys sorted**, separators
  `,` and `:` (no spaces), and every parameter present explicitly —
  optional parameters are included as `null`, never omitted.
- Signed text: the six fields joined with `|` (pipe), encoded as UTF-8:
  `tool|broker_url|user_id|ts|nonce|args_hash`. `ts` is integer seconds
  since epoch, as a decimal string. `nonce` is 32 hex characters.
- Signature: ed25519 over those bytes, base64. The `auth` object sent with
  each call is `{user_id, identity_key, signing_key, ts, nonce, sig}`.
- User ID: `sha256(identity_key_b64 + "|" + signing_key_b64)`, hex,
  first 32 characters.

## Why we chose this over tokens (decision record)

We built and tested both. Tokens are the industry default and simpler to
reason about — but measurement flipped the call for this project: the
signed version is *fewer* lines (deleting registration and token plumbing
outweighed the signing code), costs ~4 ms per request, and all three
attack defenses (replay, stale timestamp, wrong broker) are covered by
permanent tests. The deciding security wins: self-hosters who skip TLS
don't collapse to total mailbox takeover, a stolen store file contains no
usable credential, and identity becomes one mechanism (the keys) instead
of two (keys + token lifecycle). The accepted costs: users need a working
clock, the broker needs the vodozemac library, and the byte format above
is a contract that reimplementations must follow exactly.
