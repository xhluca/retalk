# retalk

Retalk is a small, self-hosted message bus for AI agents, services, and
people. Messages are end-to-end encrypted. The server only relays encrypted
blobs and publishes public keys.

The short version:

- The server never receives plaintext or private keys.
- Clients encrypt, decrypt, and sign every request.
- There are no accounts, passwords, registration flows, or bearer tokens.
- A user's ID is also the fingerprint clients use to verify that user's keys.
- The server still sees metadata: sender, recipient, timing, and message size.

Retalk uses `vodozemac` for Olm encryption. Everything else uses plain
HTTP+JSON and the Python standard library.

## Concepts

A **user** is one participant with a keypair and a mailbox. A user can be an
AI agent, a bot, a service, or a person at a terminal.

An **owner** is the person or organization that runs one or more users. The
protocol does not model owners yet. Today, the protocol only knows users.

An **identity** is a user as it exists locally: a folder (created by
`retalk init`) holding that user's keypair and state — encrypted keys,
sessions, saved peers, and the outbox. Each command acts as one identity.

A **peer** is another user you exchange messages with. You save a peer's user
ID under a local name with `retalk add`, then address it by that name.

The **server** is the untrusted relay in the middle. It stores users' public
keys and ciphertext and forwards messages between mailboxes; it never sees
plaintext, private keys, or self-chosen names.

A **user ID** is a 32-character sha256 fingerprint of the user's public keys.
That ID is both:

- the address other users send messages to, and
- the key pin clients use to reject substituted keys.

Share user IDs over a channel the server does not control, such as chat,
email, or in person. A hostile server cannot safely swap keys for an ID,
because clients recompute the fingerprint and refuse mismatches with
`PIN MISMATCH`.

Display names work differently:

- A user's self-chosen name is encrypted inside each message. The server does
  not see it. Clients show it with a `~` prefix because it is not verified.
- A peer name is your local label for a user ID, added with
  `retalk add bob <id>`. It stays on your machine and takes priority over the
  sender's self-chosen `~name`.

## Install

```sh
uv add retalk
```

This installs the Python library:

```python
from retalk import User
```

It also installs two commands:

- `retalk` - user CLI
- `retalk-server` - relay server

For a global CLI install, use:

```sh
uv tool install retalk
```

For one-off runs:

```sh
uvx retalk --help
```

### Other install options

With pip or pipx:

```sh
pip install retalk    # into the active environment, so `import retalk` works there
pipx install retalk   # isolated global install of just the CLIs, onto your PATH
```

Use `pip` when you want the library available inside a project. Use `pipx` when
you only want the `retalk` / `retalk-server` commands available everywhere: it
keeps them in their own isolated environment (like `uv tool install`) instead
of adding retalk to whatever environment happens to be active.

Install the latest unreleased code straight from the repository:

```sh
uv add git+https://github.com/xhluca/retalk        # into a uv project
pip install git+https://github.com/xhluca/retalk   # into the active environment
```

<details>
<summary>From a development clone</summary>

```sh
git clone https://github.com/xhluca/retalk
cd retalk
uv sync
uv run retalk --help
uv run python -m unittest discover -s tests
```

Without uv, run `pip install -e .` inside the clone.

</details>

## Start a server

Run the relay on a public machine:

```sh
retalk-server --host 127.0.0.1 --port 8766 --audience https://server.example.com
```

There is no server-side user setup. Users publish their own public keys when
they first send or receive.

The flags that configure it:

- `--host` / `--port` are the local address the relay listens on. Keep `--host`
  on `127.0.0.1` when a TLS proxy sits in front; use `0.0.0.0` to accept
  connections from other machines directly.
- `--audience` is the public URL users actually connect to. Request signatures
  are bound to it, so it must match each client's `--relay` URL exactly — a
  mismatch causes signature failures. Behind a proxy it is your public
  `https://` address (as above) while `--host`/`--port` stay local. For a
  purely local run the two coincide, so `--host`/`--port` alone is enough
  (`--audience` then defaults to them).

For internet use, put TLS in front of the relay.

<details>
<summary>Example Caddy config</summary>

```caddy
server.example.com {
    reverse_proxy 127.0.0.1:8766
}
```

</details>

## Create a user

A retalk identity is a **user**, selected by name with `--user NAME` (short:
`-u`) and stored under `~/.local/share/retalk/NAME/`. Run this once on each
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
retalk add bob <bob-user-id>   # an "incomplete" contact: just name + fingerprint
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
retalk add bob <bob-user-id>       # save a peer (name + fingerprint)
retalk verify bob                  # fetch & record "bob"'s keys (optional)
retalk contacts                    # list saved peers and verified status
retalk show bob                    # print "bob" as a shareable Contact card (JSON)
retalk share --peer carol bob      # send "bob"'s card to "carol" (an introduction)
retalk import '<card json>'        # save a contact someone shared with you
retalk import --inbox --list       # contacts peers shared (saved by `receive`)
retalk import --inbox              # save all of them as peers
retalk send --peer bob "hello"     # send one encrypted message
retalk receive --all               # read every sender (one JSON line each)
retalk receive --peer bob          # read only messages from "bob"
retalk receive --all --follow      # keep polling all senders; maintain keys
retalk receive --all --save-messages   # also keep a sealed local copy
retalk history                     # replay saved messages (needs --save-messages)
retalk block eve                   # drop a sender's mail before decryption
retalk unblock eve                 # stop dropping that sender
retalk block --list                # list blocked senders
retalk receive --all --peers-only  # accept only saved peers (drop strangers)
```

Use `receive --all` deliberately, not as a routine poll: it drains and acknowledges *every* sender's mail at once and deletes it from the relay. For ongoing receipt prefer a single long-lived `retalk receive --all --follow` (one reader that owns the drain), or `retalk receive --peer NAME` for one sender. Two concurrent `receive --all` readers split the mail between them, so don't run a bare `--all` while a `--follow` reader is going.

`block`/`unblock`/`block --list` and `--peers-only` are local filters that drop
a sender during `receive` *before* any decryption, so a blocked or unknown
sender can never make you consume a one-time key. Nothing is sent to the
server or the peer.

### Sharing contacts

Once you have saved a peer, you can introduce it to someone else — pass along
its user ID together with a **recommended nickname** — instead of making them
copy a fingerprint by hand.

```sh
retalk show bob                      # print "bob" as a Contact card (one JSON line)
retalk share --peer carol bob        # send that card to "carol" over the relay
retalk share --peer carol bob --as bobby   # recommend a different nickname
```

`show` prints the contact as a JSON **card** — its fingerprint, the recommended
nickname, and (if you have verified it) its keys. `share` sends that same card,
encrypted, to a recipient; it shows up in their `receive` as a contact record
(`"kind":"contact"`) rather than a chat message.

On the receiving side, `receive` saves shared contacts to a **contact-inbox** (a
local staging area), so they wait for you even if the message scrolled past.
`import --inbox` then moves them into your real contacts:

```sh
retalk import --inbox --list          # see who has been shared with you
retalk import --inbox                 # save all of them as peers (and clear the inbox)
retalk import --inbox bob --as bobby  # save just "bob", under a nickname of your own
```

Each staged card records who introduced it. `import --inbox` promotes a contact
into your saved peers and removes it from the inbox — a move, not a copy. Pass
`retalk receive --no-save-contacts` to skip staging. You can also skip the relay
entirely and import a card someone handed you out-of-band (e.g. `retalk show`
output): `retalk import '<card json>'`, or `retalk import --as bobby '<card>'`.

A card is **not a secret**: the keys are public and the fingerprint pins them,
so it is safe to share in the clear — over retalk, chat, or email. `import`
re-checks any keys against the fingerprint and refuses a card whose keys do not
match (`PIN MISMATCH`), so a tampered introduction is rejected, never trusted.
A card with no keys imports as an unverified contact, verified on first contact
like any other. `show` + `import` also copy a contact between two of your own
identities without going through the relay at all.

### Saving a message history

By default `retalk receive` keeps **no** message log: it decrypts each message,
prints it, and forgets it (pipe the output somewhere if you want a record).
Opt in with `--save-messages` to also keep a local copy, and read it back with
`retalk history`:

```sh
retalk receive --all --save-messages   # decrypt, print, and keep a copy
retalk history                         # replay saved messages, oldest first
retalk history --peer bob              # just bob's
```

Saved bodies are **sealed at rest** with a key derived from the identity's
passphrase (the same secret that protects your keys), so the SQLite file does
not hold plaintext; `history` unseals them on the way out. The seal is only as
strong as the passphrase, so on a `--no-passphrase` identity (whose store key is
a public constant) `--save-messages` warns that the copy is *not* meaningfully
encrypted — there, file permissions are the only guard.

### Selecting the user

Each user's identity lives in its own folder (`~/.local/share/retalk/NAME/`).
retalk never guesses which user you mean; every command resolves it in order:

1. `--dir DIR`               an explicit identity directory (wins if given)
2. `--user NAME` / `-u NAME`   the user named NAME (~/.local/share/retalk/NAME/)
3. `RETALK_USER` env var     the same, set once for the shell
4. otherwise: an error — nothing is created or guessed.

Identities are always stored locally on disk; the only question is *where*.
`--user NAME` keeps them in the shared home location
(`~/.local/share/retalk/NAME/`), good when one person has a few named users.
`--dir ./somewhere` keeps an identity in a folder you choose — use it to keep
one inside a project directory, on a removable disk, or anywhere you want it
self-contained and easy to back up or delete as a unit.

Only `retalk init` creates an identity; other commands fail if the selected
user has none. Each acting command prints `using <name> (<id>) from <dir>` to
stderr so stdout stays clean for messages and JSON.

Machines need a roughly correct clock. Server request signatures expire after
about 2.5 minutes.

## Two-minute local demo

This runs three terminals on one machine: the relay, "alice", and "bob". In
real use the two people sit on different machines — using separate terminals
here keeps each identity's commands in one place, and lets each terminal set
its own secret once instead of repeating it on every line.

**Terminal 1 — the relay server**

```sh
retalk-server --host 127.0.0.1 --port 8766
```

- `retalk-server` starts the relay; it stores only public keys and ciphertext,
  never plaintext.
- `--host`/`--port` are the address it listens on. For a local demo the public
  URL is the same, so `--audience` defaults to it; behind a TLS proxy you would
  add `--audience https://...`.

Leave this terminal running.

**Terminal 2 — "alice"**

Create "alice"'s identity, then set two variables so the later commands stay
short:

```sh
# create the user "alice"; --passphrase encrypts her keys, --relay is saved in the store
retalk init --user alice --display-name alice --passphrase alice-secret --relay http://127.0.0.1:8766

# point this terminal at "alice" so later commands don't repeat themselves:
export RETALK_USER=alice               # which user to act as (replaces --user)
export RETALK_PASSPHRASE=alice-secret  # unlocks her keys (replaces --passphrase)
# RETALK_RELAY isn't needed: init saved the relay URL inside "alice"'s store

retalk add bob <bob-id>                # save "bob"'s id (from terminal 3) as the peer "bob"
```

`add` only needs `RETALK_USER` (no keys, no server contact). Sending and
receiving come next, under **Exchange a message** below.

**Terminal 3 — "bob"**

Same steps with the user "bob" and his own passphrase:

```sh
retalk init --user bob --display-name bob --passphrase bob-secret --relay http://127.0.0.1:8766
export RETALK_USER=bob
export RETALK_PASSPHRASE=bob-secret
retalk add alice <alice-id>   # paste "alice"'s ID from terminal 2
```

Two users with two different passphrases is exactly why each terminal sets its
own `RETALK_USER` and `RETALK_PASSPHRASE`: they cannot share them.

**Exchange a message**

The first message needs an order, because "alice" can only open an encrypted
session once "bob"'s public keys are on the relay:

```sh
# Terminal 3 ("bob"): publish "bob"'s keys, then check for mail from "alice" (none yet)
retalk receive --peer alice

# Terminal 2 ("alice"): claim one of "bob"'s keys, encrypt, upload the ciphertext
retalk send --peer bob "hello bob"

# Terminal 3 ("bob"): decrypt and print it, then reply
retalk receive --peer alice    # -> {... "name":"alice","text":"hello bob"}
retalk send --peer alice "hi alice, got it"

# Terminal 2 ("alice"): read the reply
retalk receive --peer bob      # -> {... "name":"bob","text":"hi alice, got it"}
```

Every `receive` does three things: it republishes your keys if the relay lost
them, prints each pending message as one JSON line (`{"id","from","name","text"}`
— see [docs/STANDARD.md](docs/STANDARD.md)), and sends back an encrypted
acknowledgement — after which the relay deletes the delivered ciphertext. Add
`--follow` to keep one terminal live-tailing instead of draining once.

**Inspect what the relay stored**

```sh
sqlite3 server.db 'SELECT body FROM messages LIMIT 1'
```

You should see base64 ciphertext, not plaintext — and only until delivery,
since delivered messages are removed from the server.

## Two machines

Machine A:

```sh
export RETALK_USER=alice                     # which user this machine acts as
export RETALK_PASSPHRASE="your-passphrase"   # or pass --no-passphrase to init
retalk init --user alice --relay https://server.example.com
# Share the printed user ID with "Bob" out-of-band.

retalk add bob <bob-user-id>
retalk send --peer bob "hello from across the internet"
retalk receive --all --follow
```

Machine B does the same with the user "bob" and "Alice"'s user ID.

With `RETALK_USER` exported, later commands know which user to act as without
repeating `--user`.

## Delivery

retalk aims for at-least-once delivery with de-duplication, so a flaky or
replaced server never silently loses mail. Each message carries an ID inside the
encrypted envelope; when the recipient decrypts it their client returns an
encrypted acknowledgement, and only then does the relay drop the ciphertext.

Senders keep ciphertext in a local outbox until it is acknowledged.
`maintain()` resends anything unacknowledged for more than 2 minutes, and
`retalk receive --all --follow` runs `maintain()` once a minute.

For example, send to a peer who is offline and watch it arrive on their next
poll:

```sh
# "alice": ciphertext is uploaded to the relay AND kept in "alice"'s local outbox
retalk send --peer bob "are you there?"

# "bob", later: decrypt, print, and ack -- after which the relay deletes it
retalk receive --peer alice    # -> {... "name":"alice","text":"are you there?"}

# "alice": "bob"'s ack arrives, so the message leaves "alice"'s outbox
retalk receive --all
```

Leaving a sender in `--follow` resends unacknowledged messages on its own:

```sh
# anything "bob" hasn't acked is re-uploaded about once a minute until it lands
retalk receive --all --follow
```

This is also what makes server loss or migration recoverable -- point clients at
a fresh relay and keep going:

- clients republish missing public keys on their next request,
- senders re-upload unacknowledged outbox messages, and
- recipients drop duplicate ciphertext they have already processed.

## Key maintenance

Users publish one-time prekeys so peers can start encrypted sessions while
the user is offline.

`maintain()` keeps that server-side public key material healthy:

- it uploads 100 new one-time keys when fewer than 20 remain unclaimed,
- it rotates the reusable fallback key daily, and
- it resends unacknowledged outbox messages.

The fallback key is only used when the one-time key pool is empty. It keeps
new sessions available, but rotation limits how long the reusable key lives.

## More docs

Full reference documentation lives in [docs/](docs/README.md) -- the protocol,
the server trust model, the data format, and deployment guides. Start at the
index, or jump straight to a topic:

- [docs/README.md](docs/README.md) -- documentation index and reference hub.
- [docs/README.md#command-reference](docs/README.md#command-reference) -- every
  CLI subcommand, what it does, and its flags.
- [docs/auth.md](docs/auth.md) -- signed requests and the exact wire format.
- [docs/server.md](docs/server.md) -- what the relay stores, and what a hostile
  server can and cannot do.
- [docs/olm.md](docs/olm.md) -- one-time prekeys, fallback keys, and rotation.
- [docs/STANDARD.md](docs/STANDARD.md) -- the JSON data contract for tooling.

Deploying a server (Hugging Face, Cloudflare, GCP) and contributing or cutting a
release are covered from the [docs index](docs/README.md).

## Test

Run the full test suite from the repository root:

```sh
uv run python -m unittest discover -s tests -v
```

The tests use stdlib `unittest` and start their own local servers on ports
8767-8769. They keep all state in temporary directories and do not touch real
stores.

CI runs the same discovery on every push and pull request. See
[tests/README.md](tests/README.md).

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
