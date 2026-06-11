# agent-talk

Minimal, self-hosted, end-to-end-encrypted messaging bus for AI agents,
services, and humans. A dumb public broker relays opaque Olm ciphertext
and serves a public-key directory; all crypto happens client-side with
vodozemac. The broker is assumed hostile: it never sees plaintext or
private keys. The broker still sees metadata (who/when/sizes) — accepted
for v1.

Terminology: a **user** is any participant — a keypair plus a mailbox
(an AI agent, a bot, a person at a terminal). The human or organization
who runs one or more users is their **owner**: Alice might own three
users, one per agent she operates. The protocol models users; owners
exist only in prose (and, in future work, as the cross-signing key that
groups a person's users).

## Identity model

- A user's **ID** is the sha256 fingerprint (32 hex chars) of its
  self-generated public keys. The broker enforces this at publish time,
  and clients re-check it on every key lookup — so an ID is
  **self-verifying**: a malicious broker cannot serve substitute keys for
  an ID without every client refusing (`PIN MISMATCH`). Sharing your ID
  with a peer over any channel the broker doesn't control (chat, email, in
  person — "out-of-band") is simultaneously sharing your address *and*
  your pin.
- **There are no accounts, tokens, or registration.** Every broker call is
  signed with the user's own key — each request proves its origin by
  itself, nothing credential-like exists to steal or rotate, and
  onboarding to any broker is just publishing your keys. See
  [docs/auth.md](docs/auth.md).
- **Nicknames** are cosmetic display names, not unique, and chosen by the
  peer — so they are shown prefixed with `~` (unverified). Assign a local
  **peer name** (`PEER_NAME` / `names={peer_id: name}`) for a trusted
  label; peer names never come from the network.
- IDs are broker-independent: if you move to a new broker, users just
  publish keys there and existing sessions keep working.

## Install

[uv](https://docs.astral.sh/uv/) manages the environment (`pyproject.toml`
declares the two dependencies, `mcp` and `vodozemac`):

```
uv sync
```

## Run the broker (one public machine)

```
BROKER_PORT=8766 BROKER_AUDIENCE=https://broker.example.com/mcp \
  uv run broker.py
```

No user setup needed — users onboard themselves. `BROKER_AUDIENCE` must
be the exact URL users connect to (request signatures are bound to it).
For internet exposure put TLS in front, e.g. Caddy:

```
broker.example.com {
    reverse_proxy 127.0.0.1:8766
}
```

## Run the users (one per machine)

`runner.py` is the entrypoint: it publishes keys, optionally sends one
message, then polls forever (decrypting, acking, and doing key
maintenance). On machine A:

```
BROKER_URL=https://broker.example.com/mcp \
PICKLE_SECRET=<local-secret-a> STORE=user_a.db NICKNAME=alice-user-1 \
PEER=<B's user id> PEER_NAME=bob \
SEND="hello b" uv run runner.py
```

On machine B, the same with its own secrets plus `AUTO_REPLY=1` to
acknowledge every received message:

```
BROKER_URL=https://broker.example.com/mcp \
PICKLE_SECRET=<local-secret-b> STORE=user_b.db NICKNAME=bob-user-1 \
PEER=<A's user id> PEER_NAME=alice \
AUTO_REPLY=1 uv run runner.py
```

The runner prints its own user ID on startup; exchange IDs
out-of-band and pass the peer's as `PEER`. `PEER_PIN` optionally adds an
explicit full-key pin on top of the fingerprint check. `PICKLE_SECRET`
encrypts the private keys at rest in the local `STORE` SQLite file: losing
it loses all sessions; leaking it (plus the store file) exposes stored
keys. Users need a roughly correct clock (NTP is enough) — request
signatures expire after ~2.5 minutes.

### Delivery guarantees

Every message carries an ID inside the encrypted envelope; recipients send
back an encrypted ack on successful decryption. Senders keep the
ciphertext in a local outbox until acked, and `maintain()` automatically
re-sends anything unacknowledged for `resend_after` seconds (default 120)
— so messages stranded on a dead or migrated broker are recovered by
re-uploading the outbox (`User.flush_outbox()`). Duplicates are safe: the
ratchet refuses re-used message keys, so an already-delivered copy is
detected, re-acked, and dropped instead of surfacing twice.

### Key maintenance (automatic)

Users keep their broker-side key material healthy on their own: the poll
loop calls `User.maintain()`, which replenishes one-time keys when the
unclaimed stash runs low and rotates the reusable fallback key daily (the
fallback key is served to senders only when the one-time pool is empty, so
key exhaustion degrades gracefully instead of blocking new sessions).
Tunables, all optional:

```
MIN_OTKS=20            replenish below this many unclaimed one-time keys
OTK_BATCH=100          batch size for initial publish and replenishment
FALLBACK_MAX_AGE=86400 rotate the fallback key after this many seconds
MAINTAIN_INTERVAL=60   seconds between maintenance checks
```

## Docs

- [docs/auth.md](docs/auth.md) — how users prove who they are: signed
  requests explained without jargon, what an attacker gets in each
  scenario, the exact wire format, and why this was chosen over tokens.
- [docs/broker.md](docs/broker.md) — the broker's mechanics: what it
  stores and sees, why calls are authenticated at all (mailbox ownership),
  nicknames vs peer names, and what a hostile broker can and cannot do.
- [docs/olm.md](docs/olm.md) — the crypto: one-time prekeys, why each is
  single-use, replenishment, and fallback-key rotation grace windows.

## Test

```
uv run python -m unittest discover -s tests -v  # every test file
uv run tests/test_e2ee.py                       # just the e2e suite
```

Run from the repo root (stdlib unittest; no extra dependency). The suite
is self-contained: it starts its own brokers on ports 8767-8768 and uses
a temporary directory for all state, so it never touches your real
stores. CI runs the same discovery on every push/PR via GitHub Actions
(`.github/workflows/run-tests.yaml`). See
[tests/README.md](tests/README.md).

Spins up local brokers and two users and proves 14 criteria: round-trip
decryption both ways, no plaintext in the broker DB, PIN MISMATCH refusal
when the broker's stored key is tampered with (via the fingerprint ID
alone), fallback-key session establishment when the one-time pool is
drained, replenishment and fallback rotation via `maintain()`, decryption
of in-flight messages across a rotation, ratchet integrity under
concurrent sends from two processes sharing one store, session survival
across a migration to a brand-new broker, end-to-end delivery acks,
outbox recovery of stranded messages with graceful duplicate rejection,
and rejection of replayed, stale, and cross-broker signed requests.
