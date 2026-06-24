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

## Command reference

`retalk` has twelve subcommands. This is the quick reference; run `retalk
<command> --help` for the full text, and see [STANDARD.md](STANDARD.md) for the
JSON each one emits. Most commands work entirely on your local store — only the
ones that touch a mailbox reach the relay.

| Command | What it does | Relay? |
| --- | --- | --- |
| `init` | Create a new identity (keypair + store). The only command that creates one. | no |
| `id` | Print this identity's user id (its public-key fingerprint). | no |
| `add` | Save a peer's user id under a local name. | no |
| `verify` | Record a saved peer's public keys (explicit first contact). | yes¹ |
| `contacts` | List saved peers; `--show` one as a Contact card, `--remove` one. | no |
| `share` | Send a contact to a peer (an introduction). | yes |
| `import` | Save a contact from a card, or from the contact-inbox. | no |
| `block` | Drop a sender's mail before decryption; `--remove` to undo, `--list` to view. | no |
| `send` | Encrypt and send one message. | yes |
| `receive` | Fetch, decrypt, and print pending messages. | yes |
| `history` | Replay messages saved by `receive --save-messages`. | no |
| `sync` | Reconcile keys and resend the outbox against the relay. | yes |

¹ `verify` reaches the relay only when fetching keys; with `--identity-key`/`--signing-key` it stays offline.

### Options every command shares

Identity selection (first match wins — retalk never guesses which user you mean):

- `--dir DIR` — use the identity in directory `DIR`.
- `-u`, `--user NAME` — the user under `~/.local/share/retalk/NAME/` (or the `RETALK_USER` env var).
- `--relay URL` — relay for this call (overrides `RETALK_RELAY` and the URL saved at init).
- `--api-key KEY` — relay access key, sent as `Authorization: Bearer` (overrides `RETALK_API_KEY`).
- `--passphrase SECRET` — unlocks the store; prefer the `RETALK_PASSPHRASE` env var, since a value passed here is visible in the process list. Omit it for a `--no-passphrase` identity.

Results go to stdout; banners and errors go to stderr, so pipes stay clean.
There is no interactive prompt — commands never block waiting on a human.

### Identity — `init`, `id`

**`retalk init`** — create a new identity: generate a keypair, encrypt it with
your passphrase, and write `store.db` under `--user NAME` or `--dir DIR`. Prints
the new user id. Offline; keys publish automatically on first send/receive.

- `--display-name NAME` — name attached to your messages (peers see it as unverified `~NAME`). Defaults to the user name.
- `--no-passphrase` — store keys unencrypted, protected only by file permissions.

**`retalk id`** — print this identity's user id (sha256 of its public keys); it holds no secret and is safe to post publicly.

- `--json` — emit `{fingerprint, identity_key, name}`.
- `--card` — emit your OWN **Contact card** as JSON — `{fingerprint, name, identity_key, signing_key, verified, relay}` — the shareable form of your identity (your address + keys + the relay you use). A peer saves it with `retalk import`; pipe it out-of-band or `retalk id --card | retalk import --dir ./them`.
- `--invite-message` — render that card as a copy-paste **invite** for onboarding a peer out-of-band: install retalk, set the relay, and `retalk add` you, plus a prompt to send their id back.
- `--as NAME` — with `--card`/`--invite-message`, the nickname you suggest the peer save you under (default: your display name).

### Contacts — `add`, `verify`, `contacts`

**`retalk add NAME FINGERPRINT`** — save a peer's 32-hex user id under a local
name, so `send NAME …` works and their mail displays as `NAME`. The name is
yours alone and never travels over the network.

**`retalk verify PEER`** — record a saved peer's public keys, making explicit the
key exchange that otherwise happens on first message. Keys are checked against
the saved fingerprint; a mismatch is refused with **PIN MISMATCH** and nothing
is recorded.

- `--identity-key KEY` / `--signing-key KEY` — record keys you already hold (offline) instead of fetching from the relay; pass both together.

**`retalk contacts`** — list saved peers, one per line as tab-separated `NAME`, `FINGERPRINT`, and `STATUS` (verified or unverified), sorted by name. With `--show`, print just one contact instead of the whole list — its status row, or its full **Contact card** with `--json`. That card is the shareable form `share` sends and `import` ingests, so you can also pipe or paste it out-of-band; keys are included only when the contact is verified, and the fingerprint pins them, so a card is safe to share in the clear.

- `--json` — emit [Contact](STANDARD.md) objects instead of status rows (one per line; with `--show`, the full card).
- `--show CONTACT` — print just this contact (a saved peer name or a raw 32-hex user id, even one you haven't saved) rather than the whole list.
- `--remove CONTACT` — delete a saved peer (a name or user id) — the inverse of `add`; a fingerprint drops every name pinned to it.
- `--as NAME` — with `--show`: recommended nickname to put in the card (default: the saved peer name).

### Sharing contacts — `share`, `import`

To get a contact's card for sharing, use `retalk contacts --show CONTACT --json`
(above). `share` sends that card over the relay; `import` saves one you receive.

**`retalk share CONTACT --peer PEER`** — introduce `CONTACT` to `--peer` by
sending its card, encrypted, over the relay. The recipient sees it in `receive`
and saves it with `import`. Delivery is tracked like `send`; prints a
`{id, to, shared}` receipt.

- `--peer PEER` — the recipient (required): a saved peer name or a raw user id.
- `--as NAME` — override the recommended nickname (default: the contact's saved name).

**`retalk import [CARD]`** — save a contact from a Contact card: the `CARD`
argument, or stdin when it is omitted or `-`. Keys must hash to the card's
fingerprint or import refuses with **PIN MISMATCH**; a keyless card is saved
unverified.

- `--inbox` — import from the contact-inbox (cards that `receive` staged when peers shared contacts) instead of a `CARD`. Plain `--inbox` promotes and removes every staged contact (a move); `--inbox NAME-OR-ID` does just the one match; a staged card that fails its key check is reported and left in the inbox.
- `--list` — with `--inbox`, list the staged contacts and import nothing.
- `--json` — with `--inbox --list`, emit one JSON object per staged contact.
- `--as NAME` — nickname to save under (required when the card has no name).

### Filtering senders — `block`

These filters drop senders during `receive` before any decryption, so a dropped
sender never makes you spend a one-time key. See [Filtering who can reach
you](#filtering-who-can-reach-you) for the full model (including the signed
negative acks that keep refused mail from resurrecting).

**`retalk block [PEER]`** — block a sender (saved name or raw id); their incoming
mail is dropped, unread, and nothing is sent to the server or the peer.

- `--remove` — with a `PEER`, take that sender back off the block list (so `receive` delivers their mail again); removing one that isn't blocked is a no-op.
- `--list` — print the block list instead of blocking (omit `PEER`).
- `--json` — with `--list`, emit one `{fingerprint, name}` object per line.

### Messaging — `send`, `receive`, `history`

**`retalk send --peer PEER TEXT`** — encrypt `TEXT` for one peer and upload the
ciphertext. First contact performs the key handshake automatically; a served key
that doesn't match the peer's fingerprint (or your verified keys) is refused with
**PIN MISMATCH**. Delivery is tracked in your outbox until the peer acks; prints
a `{id, to}` receipt.

- `--peer PEER` — recipient (required): a saved peer name or a raw user id.

**`retalk receive`** — fetch, decrypt, ack, and print pending messages as NDJSON.
A shared contact arrives as a contact record (`{…, "kind": "contact", "card":
{…}}`) and is also staged to the contact-inbox for `import --inbox`. Name a
target with `--peer` or `--all` (one is required, not both).

- `--peer PEER` — read only this sender's mail.
- `--all` — read every sender (the whole mailbox).
- `--follow` — keep polling every 2s and run key maintenance every 60s until ctrl-c.
- `--peers-only` — accept only saved peers; unknown senders are dropped before decryption. Blocked senders are always dropped regardless.
- `--no-save-contacts` — do not stage shared contacts to the contact-inbox (staging is on by default).
- `--save-messages` — also keep a local copy of each chat message, sealed with this identity's key, for `history`. Off by default; on a `--no-passphrase` identity the seal is not real encryption, since the store key is public.

**`retalk history`** — replay messages saved by `receive --save-messages`,
oldest first, as NDJSON in the same shape `receive` emits. Each body is decrypted
from its at-rest seal on the way out, so this needs the passphrase but never the
relay.

- `--peer PEER` — show only this sender's saved messages.

### Maintenance — `sync`

**`retalk sync`** — run one reconciliation pass against the relay: republish your
keys if it has forgotten them, replenish one-time keys, rotate a stale fallback
key, and resend unacknowledged outbox mail. `send` and `sync` resend; `receive`
never does — so run `sync` from cron or a timer for a mostly-listening client.

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

alice.sync()                             # reconcile keys (publish/replenish/
                                         # rotate) + resend unacked messages
```

`receive()` returns the same message objects the CLI prints — see
[STANDARD.md](STANDARD.md). Call `sync()` periodically to keep your keys
healthy on the relay and to resend unacknowledged mail (this is the `retalk
sync` command). `send` resends too — it runs a full `sync` before handing
over the new message — so the only thing that never resends is `receive`,
which runs just the key-upkeep half.

## Scripting the CLI

`retalk receive` prints one JSON object per message on stdout, while banners
and errors go to stderr (see [STANDARD.md](STANDARD.md)), so it composes with
ordinary Unix tools.

Drain the mailbox from cron:

```cron
*/5 * * * * RETALK_PASSPHRASE=... retalk receive --all >> ~/inbox.jsonl 2>/dev/null
```

Note: `receive --all` is a full mailbox drain — it reads, acks, and deletes every sender's mail at once. Use it sparingly. For ongoing receipt a single long-lived `retalk receive --all --follow` (or `retalk receive --peer NAME` for one sender) is better than repeated `--all` polls; two concurrent `--all` readers split the mail between them.

Retry unacknowledged sends from cron — useful for a mostly-listening client
that rarely calls `send` (every `send` already resends; `receive` never does):

```cron
*/5 * * * * RETALK_PASSPHRASE=... retalk sync >/dev/null 2>&1
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
retalk block bob              # drop "bob"'s mail (by saved name or 32-hex id)
retalk block --list           # list blocked senders (--json for objects)
retalk block --remove bob     # stop dropping "bob"

retalk receive --all --peers-only   # accept only senders you `retalk add`ed
```

Both filters are local to your store: nothing is sent to the server or the
peer, and the dropped sender's mail simply stays unread on the server when you
target a single sender. (A drained `receive --all` still clears the mailbox
server-side; the filtered messages just aren't surfaced or acknowledged.)
Blocked senders are always dropped; `--peers-only` additionally drops anyone
not in your saved peers. From the library, pass `blocked={...}`,
`receive_policy="peers-only"`, and/or `known={...}` to `User`.

When you drop a message this way, your client records a signed **negative ack**
on the relay (keyed by the message's ciphertext hash, so no decryption and no
one-time key is spent). The relay then refuses that ciphertext's resends and
hands the sender your signature as proof; the sender verifies it and marks the
message dropped in its outbox. This works even for a sender that only ever
`send`s and never `receive`s — without it, an unacked dropped message would be
re-uploaded on every send and re-delivered if you later accepted the sender.

The relay cannot forge a refusal: the proof is signed by you, so a sender that
gets an unsigned or invalid one keeps the message live (a hostile relay could
only drop it, which it can always do). The trade is that the negative ack
reveals to the sender that the message was refused, and the relay learns it too
(it stores the refused hash, bounded by `--max-refused` and aged out by
`--refused-ttl`); it never sees
plaintext or your block list.

## Contributing

→ [CONTRIBUTING.md](CONTRIBUTING.md) — development setup, running the tests,
and cutting a release.
