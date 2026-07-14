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

## Key maintenance

Users publish one-time prekeys so peers can start encrypted sessions while
the user is offline.

`maintain()` keeps that server-side public key material healthy:

- it uploads 100 new one-time keys when fewer than 20 remain unclaimed,
- it rotates the reusable fallback key daily, and
- it resends unacknowledged outbox messages.

The fallback key is only used when the one-time key pool is empty. It keeps
new sessions available, but rotation limits how long the reusable key lives.

## The server and its trust model

The relay stores only public key material and ciphertext (deleted on delivery).
It can see metadata — who talks to whom, when, and message sizes — but never
message content, private keys, or self-chosen names, and it cannot impersonate
users or silently swap their keys.

→ [server.md](server.md) — database tables, what the server sees, why mailbox
calls are authenticated, and exactly what a hostile server can and cannot do.

## Delivery

retalk aims for at-least-once delivery with de-duplication, so a flaky or
replaced server never silently loses mail. Each message carries an ID inside the
encrypted envelope; when the recipient decrypts it their client returns an
encrypted acknowledgement, and only then does the relay drop the ciphertext.

Senders keep ciphertext in a local outbox until it is acknowledged.
`maintain()` resends anything unacknowledged for more than 2 minutes, and
`retalk receive --peer bob --follow` runs `maintain()` once a minute.

For example, send to a peer who is offline and watch it arrive on their next
poll:

```sh
# "alice": ciphertext is uploaded to the relay AND kept in "alice"'s local outbox
retalk send --peer bob "are you there?"

# "bob", later: decrypt, print, and ack -- after which the relay deletes it
retalk receive --peer alice    # -> {... "name":"alice","text":"are you there?"}

# "alice": "bob"'s ack arrives, so the message leaves "alice"'s outbox
retalk receive --peer bob
```

Leaving a sender in `--follow` resends unacknowledged messages on its own:

```sh
# anything "bob" hasn't acked is re-uploaded about once a minute until it lands
retalk receive --peer bob --follow
```

This is also what makes server loss or migration recoverable -- point clients at
a fresh relay and keep going:

- clients republish missing public keys on their next request,
- senders re-upload unacknowledged outbox messages, and
- recipients drop duplicate ciphertext they have already processed.

## Running a server on the internet

The relay is one process speaking plain HTTP on one local port:

```sh
retalk-server --host 127.0.0.1 --port 8766 --audience https://server.example.com
```

- `--host` / `--port` — the local address the relay listens on. Keep `--host`
  on `127.0.0.1` when a TLS proxy sits in front; use `0.0.0.0` to accept
  connections from other machines directly.
- `--audience` — the public URL users actually connect to. Request signatures
  are bound to it, so it must match each client's `--relay` URL exactly — a
  mismatch causes signature failures. Behind a proxy it is your public
  `https://` address while `--host`/`--port` stay local; for a purely local
  run it defaults to host:port, so `--host`/`--port` alone is enough.

There is no server-side user setup — users publish their own public keys when
they first register, send, or receive. To expose the relay publicly, use a
host that terminates TLS for you, or put your own TLS proxy in front:

- [server/huggingface.md](server/huggingface.md) — a free Hugging Face Docker
  Space: a public HTTPS URL with no domain, firewall, or TLS setup. Quickest
  zero-cost option; the free tier has no persistent disk and sleeps when idle.
- [server/cloudflare.md](server/cloudflare.md) — Cloudflare Tunnel: a free
  quick tunnel, or a stable hostname on your own domain. No firewall changes.
- [server/gcp.md](server/gcp.md) — a small Google Cloud VM, with locked-down
  SSH, per-month cost notes, scaling, and teardown.

## Creating a user

A retalk identity is a **user**, selected by name with `--user NAME` (short:
`-u`) and stored under `~/.retalk/NAME/`. Run this once on each
machine, supplying a passphrase that encrypts the private keys at rest — via
`--passphrase` or the `RETALK_PASSPHRASE` env var (preferred, since a flag
value is visible in the process list):

```sh
export RETALK_PASSPHRASE="correct horse battery staple"
retalk init --user alice --display-name alice-1 --relay https://server.example.com
```

Every later command must say which user it acts as — retalk never guesses.
Name it per command, or set it once in the environment:

```sh
retalk id --user alice           # name the user on the command, or...
export RETALK_USER=alice          # ...set it once for the shell
retalk id                         # now acts as "alice"
```

`init` prints the user ID. There is no interactive prompt — a command with no
passphrase fails fast instead of blocking, so the CLI stays scriptable. For
agents or throwaway identities, `--no-passphrase` skips encryption (the keys
are then protected only by file permissions):

```sh
retalk init --user agent-1 --no-passphrase --relay https://server.example.com
```

The choice is remembered: later commands on a `--no-passphrase` identity need
no passphrase, while an encrypted identity always requires one.

Then exchange user IDs out-of-band and save your peer:

```sh
retalk add "<bob-user-id>" --peer bob   # an "incomplete" contact: just name + fingerprint
retalk verify bob              # optional: fetch & record "bob"'s keys now
```

`add` stores only the name and fingerprint. The peer's actual keys are fetched
from the relay and checked against that fingerprint automatically the first
time you message them. `retalk verify` makes that step explicit — it fetches
the keys now (or takes them via `--identity-key`/`--signing-key`), checks they
hash to the fingerprint, and records them so they show up in `retalk contacts`.
It is optional: messaging works on the fingerprint alone.

Common commands (with `RETALK_USER=alice` exported):

```sh
retalk id                          # print my user ID
retalk add "<bob-user-id>" --peer bob       # save a peer (name + fingerprint)
retalk verify bob                  # fetch & record "bob"'s keys (optional)
retalk contacts                    # list saved peers and verified status
retalk contacts --show bob --json  # print "bob" as a shareable Contact card (JSON)
retalk contacts --remove bob       # forget a saved peer
retalk share --peer carol bob      # send "bob"'s card to "carol" (an introduction)
retalk import '<card json>'        # save a contact someone shared with you
retalk import --inbox --list       # contacts peers shared (saved by `receive`)
retalk import --inbox              # save all of them as peers
retalk send --peer bob "hello"     # send one encrypted message
retalk send --peer bob "hi" --save  # keep your side too (opt-in)
retalk receive --peer bob          # read only messages from "bob"
retalk receive --peer bob --follow      # keep polling "bob"; maintain keys
retalk receive --peer bob --save   # also keep a sealed local copy
retalk history --peer bob          # the whole conversation, sent + received
retalk block eve                   # drop a sender's mail before decryption
retalk block --remove eve          # stop dropping that sender
retalk block --list                # list blocked senders
retalk receive --all --peers-only  # read all saved contacts at once (drop strangers)
```

Prefer `retalk receive --peer NAME` as your default — it reads just that sender and leaves everyone else's mail untouched. To read from all your saved contacts at once, `retalk receive --all --peers-only` drops strangers so you never spend a one-time key on someone you didn't add. Reach for a bare `receive --all` only deliberately: it drains and acknowledges *every* sender's mail at once — including strangers — and deletes it from the relay, so it is not a routine poll. For ongoing receipt prefer a single long-lived `retalk receive --peer NAME --follow`. Two concurrent `receive --all` readers split the mail between them, so don't run a bare `--all` while a `--follow` reader is going.

`block`/`block --remove`/`block --list` and `--peers-only` are local filters
that drop a sender during `receive` *before* any decryption, so a blocked or
unknown sender can never make you consume a one-time key. Nothing is sent to the
server or the peer.

## Selecting the user

Each user's identity lives in its own folder. retalk never guesses which user
you mean; every command resolves it in order:

1. `--dir DIR` — an explicit identity directory (wins if given)
2. `--user NAME` / `-u NAME` — the user named NAME (`~/.retalk/NAME/`)
3. `RETALK_USER` env var — the same, set once for the shell
4. otherwise: an error — nothing is created or guessed.

Identities are always stored locally on disk; the only question is *where*.
`--user NAME` keeps them in the shared home location (`~/.retalk/NAME/`;
relocate it with `RETALK_HOME`), good when one person has a few named users.
`--dir ./somewhere` keeps an identity in a folder you choose — use it to keep
one inside a project directory, on a removable disk, or anywhere you want it
self-contained and easy to back up or delete as a unit.

Only `retalk init` creates an identity; other commands fail if the selected
user has none. Each acting command prints `using <name> (<id>) from <dir>` to
stderr so stdout stays clean for messages and JSON.

Machines need a roughly correct clock: server request signatures expire after
about 2.5 minutes.

## Data format

The CLI and library exchange newline-delimited JSON in one stable shape, so you
can pipe retalk into other tools without parsing ad-hoc output.

→ [STANDARD.md](STANDARD.md) — the JSON contract: objects, fields, and
conventions.

## Command reference

`retalk` has sixteen subcommands. This is the quick reference; run `retalk
<command> --help` for the full text, and see [STANDARD.md](STANDARD.md) for the
JSON each one emits. Most commands work entirely on your local store — only the
ones that touch a mailbox reach the relay.

| Command | What it does | Relay? |
| --- | --- | --- |
| `init` | Create a new identity (keypair + store) and publish its keys. The only command that creates one. | yes² |
| `id` | Print this identity's user id (its public-key fingerprint). | no |
| `add` | Save a peer's user id, optionally under a local name; `--verify` pins their keys now. | no¹ |
| `group` | Manage local group rosters for fan-out group chat. | no |
| `verify` | Record a saved peer's public keys (explicit first contact). | yes¹ |
| `contacts` | List saved peers; `--show` one as a Contact card, `--remove` one. | no |
| `share` | Send a contact to a peer (an introduction). | yes |
| `import` | Save a contact from a card, or from the contact-inbox. | no |
| `block` | Drop a sender's mail before decryption; `--remove` to undo, `--list` to view. | no |
| `sync` | Reconcile keys and resend the outbox against the relay. | yes |
| `register` | Publish this identity's keys to the relay (make it reachable). | yes |
| `send` | Encrypt and send one message. | yes |
| `receive` | Fetch, decrypt, and print pending messages. | yes |
| `history` | Replay saved messages (both sent and received) as a conversation. | no |
| `show` | Render the saved conversation with a peer as a chat; `--follow` keeps it live. | no³ |
| `config` | Show or set owner-wide defaults (e.g. the default relay). | no |

¹ `verify` (and `add --verify`) reaches the relay only when fetching keys; with `--identity-key`/`--signing-key` it stays offline.
² best-effort: `init` still succeeds when the relay is unreachable (or with `--no-register`), and the keys publish on first contact.
³ a plain `show` is offline; `show --follow` polls the relay for new mail.

### Options every command shares

Identity selection (first match wins — retalk never guesses which user you mean):

- `--dir DIR` — use the identity in directory `DIR`.
- `-u`, `--user NAME` — the user under `~/.retalk/NAME/` (or the `RETALK_USER` env var).
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

- `--json` — emit your OWN **Contact card** as JSON — `{fingerprint, name, identity_key, signing_key, verified, relay}` — the shareable form of your identity (your address + keys + the relay you use). A peer saves it with `retalk import`; pipe it out-of-band or `retalk id --json | retalk import --dir ./them`.
- `--card` — print that same Contact card in a **human-readable** form (use `--json` to pipe it to `retalk import`).
- `--invite-message` — render that card as a copy-paste **invite** for onboarding a peer out-of-band: install retalk, set the relay, and `retalk add` you, plus a prompt to send their id back.
- `--as NAME` — with `--card`/`--invite-message`, the nickname you suggest the peer save you under (default: your display name).

### Contacts — `add`, `verify`, `contacts`

**`retalk add FINGERPRINT [--peer PEER]`** — save a peer's 32-hex user id, with
an optional local name (so `send PEER …` works and their mail displays as
`PEER`). Without `--peer` the contact has no label — address it by fingerprint
or by the peer's own `~name`. A name already taken by another contact errors
(suggesting a free one) unless `--override`. The name is yours alone and never
travels over the network.

There are **two contact lists**: a **global** one at `~/.retalk/contacts.db`,
shared by every identity the owner creates, and a **per-identity** one inside
each identity's store. `add` writes to the **global** list when no identity is
selected (or with `--global`), and to the **identity's own** list when one is
(`--user`/`--dir`/`RETALK_USER`); `--global` together with `--user`/`--dir` is an
error. Every command then sees the **merge** — a peer in the identity's own list
overrides a global one with the same fingerprint or name. `retalk contacts` with
no identity selected shows (and `--remove`s from) the global list directly.

**`retalk verify PEER`** — record a saved peer's public keys, making explicit the
key exchange that otherwise happens on first message. Keys are checked against
the saved fingerprint; a mismatch is refused with **PIN MISMATCH** and nothing
is recorded.

- `--identity-key KEY` / `--signing-key KEY` — record keys you already hold (offline) instead of fetching from the relay; pass both together.
- Verifying a **global** contact needs no `--user`. Offline (`--identity-key`/`--signing-key`) it just records into the global list. A relay fetch is an authenticated, signed call, so it's signed by an auto-picked identity (any works — the signer never changes the fetched keys) and the result is recorded into the global list; pass `--user NAME` to sign as a specific identity (required if you have several passphrase-protected identities and no passphrase-free one).

**`retalk contacts`** — list saved peers, one per line as tab-separated `NAME`, `FINGERPRINT`, and `STATUS` (verified or unverified), sorted by name. With `--show`, print just one contact instead of the whole list — its status row, or its full **Contact card** with `--json`. That card is the shareable form `share` sends and `import` ingests, so you can also pipe or paste it out-of-band; keys are included only when the contact is verified, and the fingerprint pins them, so a card is safe to share in the clear.

- `--json` — emit [Contact](STANDARD.md) objects instead of status rows (one per line; with `--show`, the full card).
- `--show CONTACT` — print just this contact (a saved peer name or a raw 32-hex user id, even one you haven't saved) rather than the whole list.
- `--remove CONTACT` — delete a saved peer (a name or user id) — the inverse of `add`; a fingerprint drops every name pinned to it.
- `--as NAME` — with `--show`: recommended nickname to put in the card (default: the saved peer name).

### Sharing contacts — `share`, `import`

To get a contact's card for sharing, use `retalk contacts --show CONTACT --json`
(above). `share` sends that card over the relay; `import` saves one you receive.

A card is **not a secret**: the keys are public and the fingerprint pins them,
so it is safe to pass in the clear — over retalk, chat, or email. `import`
re-checks any keys against the fingerprint and refuses a tampered card with
**PIN MISMATCH**, never trusting it; a card with no keys imports as an
unverified contact, verified on first contact like any other. On the receiving
side, `receive` also stages shared contacts into a local **contact-inbox**, so
an introduction waits for you even if the message scrolled past; `import
--inbox` then promotes it into your saved peers and clears it from the inbox —
a move, not a copy. Each staged card records who introduced it.
`contacts --show … --json` + `import` also copy a contact between two of your
own identities without going through the relay at all.

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
- `--save` — also keep a sealed local copy of *this sent message*, so `history` shows both sides of the conversation. Off by default; `RETALK_SAVE_MESSAGE=1` turns it on for every command.

**`retalk receive`** — fetch, decrypt, ack, and print pending messages as NDJSON.
A shared contact arrives as a contact record (`{…, "kind": "contact", "card":
{…}}`) and is also staged to the contact-inbox for `import --inbox`. Name a
target with `--peer` or `--all` (one is required, not both).

- `--peer PEER` — read only this sender's mail (the recommended default).
- `--all` — read every sender (the whole mailbox). This drains and acks *every* sender at once, including strangers (each spends a one-time key), so prefer `--peer`; pair it with `--peers-only` to drop strangers.
- `--follow` — keep polling every 2s and run key maintenance every 60s until ctrl-c.
- `--peers-only` — accept only saved peers; unknown senders are dropped before decryption. Blocked senders are always dropped regardless.
- `--no-save-contacts` — do not stage shared contacts to the contact-inbox (staging is on by default).
- `--save` — also keep a local copy of each *received* message, sealed with this identity's key, for `history`. Off by default; on a `--no-passphrase` identity the seal is not real encryption, since the store key is public.

Saving is also controlled by the **`RETALK_SAVE_MESSAGE`** env var: set it to a truthy value (`1`/`true`/`t`/`yes`/`y`/`on`) to save messages for *every* `send` and `receive` without the flag; anything else (incl. `false`/`no`/unset) leaves it off. retalk keeps no message log unless you opt in one of these two ways.

**`retalk history`** — replay saved messages, oldest first, as NDJSON. Output is
the shape `receive` emits plus a `direction` field — `{id, from, name, direction,
text}`, where `direction` is `"in"` (received) or `"out"` (sent) — so a
conversation shows **both sides interleaved by time**. Each body is decrypted from
its at-rest seal on the way out, so this needs the passphrase but never the relay.

- `--peer PEER` — show only the conversation with this peer (both directions).

Saved bodies are **sealed at rest** with a key derived from the identity's
passphrase (the same secret that protects your keys), so the store file never
holds plaintext; `history` unseals them on the way out. The seal is only as
strong as the passphrase — on a `--no-passphrase` identity (whose store key is
a public constant) `--save` warns that the copy is *not* meaningfully
encrypted, and file permissions are the only guard.

**`retalk show USER PEER`** — render the saved conversation between `USER` and
`PEER` as a **chat**: a time and username per message, both directions
interleaved, with date separators. It displays exactly what was saved (`--save`
/ `RETALK_SAVE_MESSAGE=1`), decrypted from its at-rest seal.

- `--follow` — keep the chat live: poll the relay for `PEER`'s new mail (saving each message like `receive --save`) and render new saved rows — including ones another terminal writes — until ctrl-c. A plain `show` never contacts the relay.
- `--group NAME` — render a group's room instead of a two-party chat (in place of `PEER`): every sender gets their own color and marker; `--follow` polls every roster member.

### Groups — `group`, `send --group`

Group chat is **client-side fan-out**: a group is a *local* roster of
fingerprints, and `retalk send --group NAME` encrypts one ordinary pairwise
copy per member. The relay never learns the roster — it just sees N messages —
and no new cryptography is involved. Inside each encrypted envelope travels
`{group: {id, name, members}}` plus a shared thread id (`mid`), so receivers
thread the copies, **materialize the group automatically** on first contact,
and can reply to everyone with the same `send --group`.

A group's identity is its **32-hex group id** (minted at create, like a
fingerprint); the **name is only your local label**. Rename it freely, two
members can call the same room different things, an incoming envelope never
overwrites the name you chose, and a name clash errors at create/rename
(foreign rooms arriving under a taken name get a numeric suffix instead).

Membership is **cooperative**: each incoming group message's roster replaces
the receiver's local copy (last sender wins). There are no admins and no
enforcement — encryption still gates who can *read* (each copy is pairwise
Olm), but anyone in the room can grow or shrink their own roster and it
propagates with their next message.

**Leaving is real, and local-first.** `group leave NAME` does two things:
it sends every member an encrypted `group_leave` notice through the relay so
their clients drop you from their rosters (no more wasted copies), and it
writes a local tombstone so any straggler's copy is **refused** (a signed
negative-ack, exactly like `block`) instead of delivered. The refusal also
travels BACK: on the straggler's next sync their client verifies the
leaver's signed refusal, drops the message, and removes the leaver from its
own roster — so even a member who never reads the notice (or who re-adds
the leaver later) self-corrects and stops producing copies. Because the
tombstone is local state, the leave survives members who never got the
notice and even a relay reset.
Rejoining works too: `group join NAME` clears your tombstone, and the room
reappears the moment a member adds you back and posts.

**Size cap.** Rosters are capped at **100 users** by default. The limit is
relay policy: `retalk-server --max-group-size N` (or
`RETALK_SERVER_MAX_GROUP_SIZE`) advertises it at `GET /info`, and clients
enforce it at `group create`/`group add` (and refuse to adopt oversized
incoming rosters).

**Failure semantics.** `send --group` contacts the relay once up front, then
sends one copy per member; one dead member never blocks the rest. The JSON
receipt counts `sent`/`failed` (one reason per failed member on stderr) and
the command exits `2` on any failure. If the relay itself is unreachable the
command fails before any copy is attempted, with no receipt — a partial
receipt always means some copies went through.

**`retalk group ACTION ...`** — manage rosters (offline, except `leave`'s
best-effort notices):

- `group create NAME --members bob,carol` — new group (members are saved contact names or raw 32-hex ids).
- `group list` (`--json`) — your groups with sizes.
- `group members NAME` — the roster with local names.
- `group add NAME PEER[,PEER]` / `group remove NAME PEER` — edit the roster; changes reach everyone on your next group send.
- `group rename OLD NEW` — change your local label; the group id and everyone else's labels are untouched.
- `group leave NAME` / `group join NAME` — leave for real (notify + refuse stragglers) / clear the tombstone to be re-addable.
- `group delete NAME` — forget the group locally without notifying anyone.

Group messages appear in `receive` output with flat `group`/`group_id` fields,
in `history --group NAME`, and as a multi-party room in
`show USER --group NAME [--follow]`.

### Maintenance — `sync`, `register`, `config`

**`retalk sync`** — run one reconciliation pass against the relay: republish your
keys if it has forgotten them, replenish one-time keys, rotate a stale fallback
key, and resend unacknowledged outbox mail. `send` and `sync` resend; `receive`
never does — so run `sync` from cron or a timer for a mostly-listening client.

**`retalk register`** — publish this identity's public keys (plus one-time keys)
to the relay so peers can start encrypted sessions with you. `init` runs it
automatically unless `--no-register`; run it yourself after that, or after
switching relays. Idempotent — it reports what it refreshed.

**`retalk config`** — show or set owner-wide defaults in `~/.retalk/config.json`.
They apply to every identity as the *last* fallback: a `--relay` flag,
`RETALK_RELAY`, and the relay saved in an identity all override them. With no
flags it prints the current config.

- `-r URL`, `--relay URL` — set the owner-wide default relay; pass `""` to clear it.

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

Poll one sender from cron:

```cron
*/5 * * * * RETALK_PASSPHRASE=... retalk receive --peer bob >> ~/inbox.jsonl 2>/dev/null
```

Note: prefer `retalk receive --peer NAME` so you only read the sender you mean. A bare `receive --all` is a full mailbox drain — it reads, acks, and deletes *every* sender's mail at once, including strangers — so use it sparingly (add `--peers-only` to drop strangers). For ongoing receipt a single long-lived `retalk receive --peer NAME --follow` is better than repeated polls; two concurrent `receive --all` readers split the mail between them.

Retry unacknowledged sends from cron — useful for a mostly-listening client
that rarely calls `send` (every `send` already resends; `receive` never does):

```cron
*/5 * * * * RETALK_PASSPHRASE=... retalk sync >/dev/null 2>&1
```

Pipe messages into another tool:

```sh
retalk receive --peer bob | jq -r .text
```

Tiny auto-responder:

```sh
retalk receive --peer bob --follow | while read -r msg; do
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

## Test

Run the full test suite from the repository root:

```sh
uv run python -m unittest discover -s tests -v
```

The tests use stdlib `unittest` and start their own local servers on ports
8767-8769. They keep all state in temporary directories and do not touch real
stores.

CI runs the same discovery on every push and pull request. See
[tests/README.md](../tests/README.md).

Coverage includes:

- bidirectional encrypted delivery,
- no plaintext in the server database,
- delivered mail deletion,
- key substitution refusal with `PIN MISMATCH`,
- fallback-key session setup when one-time keys are drained,
- key replenishment and fallback rotation,
- in-flight messages across fallback rotation,
- concurrent sends from two processes sharing one store,
- migration to a fresh server,
- delivery acknowledgements and outbox recovery,
- duplicate rejection, and
- replayed, stale, and cross-server signed-request rejection.
