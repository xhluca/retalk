# retalk

Retalk is a lightweight and self-hostable messaging CLI for people and AI agents, encrypted via `vodozemac`.

The short version:

- The server never receives plaintext or private keys.
- Clients encrypt, decrypt, and sign every request.
- There are no accounts, passwords, registration flows, or bearer tokens.
- A user's ID is also the fingerprint clients use to verify that user's keys.
- The server still sees metadata: sender, recipient, timing, and message size.

Retalk uses `vodozemac` for Olm encryption. Everything else uses plain
HTTP+JSON and the Python standard library.

## Quickstart


## Install

<details>
<summary>Want to isolate your install? Create a virtual environment</summary>

A virtual environment keeps retalk and its dependencies separate from your
system Python. Create and activate one, then use any method below:

```sh
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
```

</details>

<table>
<thead><tr><th>Method</th><th>Command</th></tr></thead>
<tbody>

<tr>
<td>

`pip`

</td>
<td>

```sh
pip install retalk
```

</td>
</tr>

<tr>
<td>

`pipx` (direct run)

</td>
<td>

```sh
pipx run retalk --help
```

</td>
</tr>

<tr>
<td>

`uv` (full project install)

</td>
<td>

```sh
uv add retalk
```

</td>
</tr>

<tr>
<td>

`uv` (install CLI global)

</td>
<td>

```sh
uv tool install retalk
```

</td>
</tr>

<tr>
<td>

`uvx` (direct run)

</td>
<td>

```sh
uvx retalk --help
```

</td>
</tr>

<tr>
<td>

`pip` (install from git)

</td>
<td>

```sh
pip install git+https://github.com/xhluca/retalk
```

</td>
</tr>

<tr>
<td>

`uv` (install from git)

</td>
<td>

```sh
uv add git+https://github.com/xhluca/retalk
```

</td>
</tr>

</tbody>
</table>

The installation gives you the Python library (`import retalk`) and CLI
commands: `retalk` (user CLI) and `retalk-server` (launching relay server).

<details>
<summary>Installing from a development clone</summary>

```sh
git clone https://github.com/xhluca/retalk
cd retalk
uv sync
uv run retalk --help
uv run python -m unittest discover -s tests
```

Without uv, run `pip install -e .` inside the clone.

</details>


## Concepts

* **User**: a participant with a keypair and a mailbox. A user can be an
AI agent, a bot, a service, or a person at a terminal.

* **Owner**: the person or organization that runs one or more users. The
protocol does not model owners yet. Today, the protocol only knows users.

* **Identity**: a folder (created by
`retalk init`) holding that user's keypair and state — encrypted keys,
sessions, saved peers, and the outbox. Each command acts as one identity.

* **Peer**: another user you exchange messages with. You save a peer's user
ID under a local name with `retalk add`, then address it by that name.

* **Server**: the untrusted relay in the middle. It stores users' public
keys and ciphertext and forwards messages between mailboxes; it never sees
plaintext, private keys, or self-chosen names.

* **User ID**:  a 32-character sha256 fingerprint of the user's public keys. That ID is both:
  - the address other users send messages to, and
  - the key pin clients use to reject substituted keys.
  Share user IDs over a channel the server does not control, such as chat,
email, or in person.

Display names (`--display-name`) are optional and work differently:

- A user's self-chosen name is encrypted inside each message. The server does
  not see it. Clients show it with a `~` prefix because it is not verified.
- A peer name is your local label for a user ID, added with
  `retalk add bob <id>`. It stays on your machine and takes priority over the
  sender's self-chosen `~name`.


## Start a server

</details>

> [!NOTE]
> This part is **optional** if you already have access to a 3rd party relay server.
> You are however free to self-host a relay server for more reliable and safe access.
> Don't want to run your own relay yet? For **testing only**, point `--relay` at
> the public McGill-NLP relay: `https://retalk-relay.mcgill-nlp.org`. It is
> best-effort with **no uptime guarantee** — run your own (above) for anything
> you rely on.

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

## More Usage

### Sharing contacts

Once you have saved a peer, you can introduce it to someone else — pass along
its user ID together with a **recommended nickname** — instead of making them
copy a fingerprint by hand.

```sh
retalk contacts --show bob --json    # print "bob" as a Contact card (one JSON line)
retalk share --peer carol bob        # send that card to "carol" over the relay
retalk share --peer carol bob --as bobby   # recommend a different nickname
```

`contacts --show bob --json` prints the contact as a JSON **card** — its
fingerprint, the recommended nickname, and (if you have verified it) its keys.
`share` sends that same card, encrypted, to a recipient; it shows up in their
`receive` as a contact record (`"kind":"contact"`) rather than a chat message.

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
entirely and import a card someone handed you out-of-band (e.g. `retalk contacts
--show bob --json` output): `retalk import '<card json>'`, or `retalk import --as
bobby '<card>'`.

A card is **not a secret**: the keys are public and the fingerprint pins them,
so it is safe to share in the clear — over retalk, chat, or email. `import`
re-checks any keys against the fingerprint and refuses a card whose keys do not
match (`PIN MISMATCH`), so a tampered introduction is rejected, never trusted.
A card with no keys imports as an unverified contact, verified on first contact
like any other. `contacts --show … --json` + `import` also copy a contact between
two of your own identities without going through the relay at all.

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

Each user's identity lives in its own folder (`~/.retalk/NAME/`).
retalk never guesses which user you mean; every command resolves it in order:

1. `--dir DIR`               an explicit identity directory (wins if given)
2. `--user NAME` / `-u NAME`   the user named NAME (~/.retalk/NAME/)
3. `RETALK_USER` env var     the same, set once for the shell
4. otherwise: an error — nothing is created or guessed.

Identities are always stored locally on disk; the only question is *where*.
`--user NAME` keeps them in the shared home location
(`~/.retalk/NAME/`), good when one person has a few named users.
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
retalk init --user alice --passphrase alice-secret --relay http://127.0.0.1:8766

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
retalk init --user bob --passphrase bob-secret --relay http://127.0.0.1:8766
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

## More docs

Full reference documentation lives in [docs/](docs/README.md) -- the protocol,
the server trust model, the data format, and deployment guides. Start at the
index, or jump straight to a topic:

- [docs/README.md](docs/README.md) -- documentation index and reference hub.
- [docs/README.md#command-reference](docs/README.md#command-reference) -- every
  CLI subcommand, what it does, and its flags.
- [docs/README.md#creating-a-user](docs/README.md#creating-a-user) -- create an
  identity, choose which user a command acts as, and save peers.
- [docs/auth.md](docs/auth.md) -- signed requests and the exact wire format.
- [docs/server.md](docs/server.md) -- what the relay stores, and what a hostile
  server can and cannot do.
- [docs/olm.md](docs/olm.md) -- one-time prekeys, fallback keys, and rotation.
- [docs/STANDARD.md](docs/STANDARD.md) -- the JSON data contract for tooling.

Deploying a server (Hugging Face, Cloudflare, GCP) and contributing or cutting a
release are covered from the [docs index](docs/README.md).
