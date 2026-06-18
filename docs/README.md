# retalk documentation

This folder is the reference for retalk's protocol, server, and tooling. For
installation and a getting-started walkthrough, start with the
[project README](../README.md); the pages here go deeper on each part.

## How retalk fits together

retalk splits a messaging system into trusted clients and an untrusted relay.
Clients hold every private key and do all the encryption, decryption, and
request signing. The server only stores public keys and ciphertext and forwards
sealed messages between mailboxes — it never sees plaintext, private keys, or
display names. A user's ID is the sha256 fingerprint of their public keys, so a
client can detect and reject a server that tries to substitute keys.

The pages below document each piece in depth.

## Authentication

Every request to the server is self-signed with the caller's Ed25519 key — no
accounts, passwords, tokens, or registration. The signature binds the tool
name, the server URL, a timestamp, and a nonce, so a captured request can't be
replayed or reused against a different server, and a stranger can't drain your
mailbox or forge messages as you.

→ [auth.md](auth.md) — what gets signed, the exact wire format, replay
protection, and why retalk avoids bearer tokens.

## Encryption and key management

retalk encrypts with Olm (via `vodozemac`). Each user uploads a batch of public
one-time prekeys so others can start a session while they are offline, plus a
single reusable fallback key for when that pool runs dry. Clients replenish the
prekeys and rotate the fallback automatically.

→ [olm.md](olm.md) — one-time prekeys, fallback keys, replenishment, and
rotation.

## The server and its trust model

The relay stores only public key material and ciphertext (deleted on delivery).
It can see metadata — who talks to whom, when, and message sizes — but never
message content, private keys, or self-chosen names, and it cannot impersonate
users or silently swap their keys.

→ [server.md](server.md) — database tables, what the server sees, why mailbox
calls are authenticated, and exactly what a hostile server can and cannot do.

## Running a server on the internet

The relay speaks plain HTTP on one local port. To expose it publicly, use a host
that terminates TLS for you, or put your own TLS proxy in front:

- [server/huggingface.md](server/huggingface.md) — a free Hugging Face Docker
  Space: a public HTTPS URL with no domain, firewall, or TLS setup. Quickest
  zero-cost option; the free tier has no persistent disk and sleeps when idle.
- [server/cloudflare.md](server/cloudflare.md) — Cloudflare Tunnel: a free
  quick tunnel, or a stable hostname on your own domain. No firewall changes.
- [server/gcp.md](server/gcp.md) — a small Google Cloud VM, with locked-down
  SSH, per-month cost notes, scaling, and teardown.

## Data format

The CLI and library exchange newline-delimited JSON in one stable shape, so you
can pipe retalk into other tools without parsing ad-hoc output.

→ [STANDARD.md](STANDARD.md) — the JSON contract: objects, fields, and
conventions.

## Library usage

Everything the CLI does is available from Python through the `User` class. A
`User` is one identity backed by a local store file:

```python
from retalk import User

alice = User(
    "https://server.example.com",
    passphrase="...",            # encrypts the private keys in `store`
    name="alice-1",              # self-chosen display name (unverified)
    store="alice/store.db",
)

print(alice.fingerprint())               # share out-of-band
alice.publish()                          # upload public keys to this server
alice.send("<bob-user-id>", "hello")     # returns the message id

for m in alice.receive():                # each m: {"id","from","name","text"}
    print(m["name"] or m["from"], m["text"])

alice.maintain()                         # replenish one-time keys, rotate the
                                         # fallback, resend unacked messages
```

`receive()` returns the same message objects the CLI prints — see
[STANDARD.md](STANDARD.md). Call `maintain()` periodically to keep the
server-side key pool healthy and to resend unacknowledged mail; the CLI's
`retalk receive --all --follow` does this for you once a minute.

## Scripting the CLI

`retalk receive` prints one JSON object per message on stdout, while banners
and errors go to stderr (see [STANDARD.md](STANDARD.md)), so it composes with
ordinary Unix tools.

Drain the mailbox from cron:

```cron
*/5 * * * * RETALK_PASSPHRASE=... retalk receive --all >> ~/inbox.jsonl 2>/dev/null
```

Pipe messages into another tool:

```sh
retalk receive --all | jq -r .text
```

Tiny auto-responder:

```sh
retalk receive --all --follow | while read -r msg; do
  sender=$(jq -r .from <<<"$msg")
  text=$(jq -r .text <<<"$msg")
  retalk send --peer "$sender" "you said: $text"
done
```

## Filtering who can reach you

Two client-side filters drop unwanted senders during `receive`, before any
decryption — so a hostile or unknown sender can never even make you consume
one of your one-time keys:

```sh
retalk block bob              # drop bob's mail (by saved name or 32-hex id)
retalk blocked                # list blocked senders (--json for objects)
retalk unblock bob            # stop dropping bob

retalk receive --all --peers-only   # accept only senders you `retalk add`ed
```

Both filters are local to your store: nothing is sent to the server or the
peer, and the dropped sender's mail simply stays unread on the server when you
target a single sender. (A drained `receive --all` still clears the mailbox
server-side; the filtered messages just aren't surfaced or acknowledged.)
Blocked senders are always dropped; `--peers-only` additionally drops anyone
not in your saved peers. From the library, pass `blocked={...}`,
`receive_policy="peers-only"`, and/or `known={...}` to `User`.

## Contributing

→ [CONTRIBUTING.md](CONTRIBUTING.md) — development setup, running the tests,
and cutting a release.
