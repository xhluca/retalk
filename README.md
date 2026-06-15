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

<details>
<summary>Other install options</summary>

With pip:

```sh
pip install retalk
pipx install retalk
```

From the latest repository version:

```sh
uv add git+https://github.com/xhluca/retalk
pip install git+https://github.com/xhluca/retalk
```

From a development clone:

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
SERVER_PORT=8766 SERVER_AUDIENCE=https://server.example.com retalk-server
```

There is no server-side user setup. Users publish their own public keys when
they first send or receive.

`SERVER_AUDIENCE` must exactly match the URL users connect to. Request
signatures are bound to that URL, so a mismatch causes signature failures.

For internet use, put TLS in front of the relay. Example Caddy config:

```caddy
server.example.com {
    reverse_proxy 127.0.0.1:8766
}
```

## Create a user

Run this once on each machine:

```sh
retalk init -u --name alice-1 --server https://server.example.com
```

`init` creates a local identity and prints the user ID. The private keys are
encrypted with a secret you choose. In scripts, set that secret with
`PICKLE_SECRET`; otherwise the CLI prompts for it.

Then exchange user IDs out-of-band and save your peer:

```sh
retalk add bob <bob-user-id>
```

Common commands:

```sh
retalk id                          # print my user ID
retalk add bob <bob-user-id>       # save a trusted local name
retalk send bob "hello"            # send one encrypted message
retalk receive                     # drain my mailbox once
retalk receive --follow            # keep polling and maintain keys
retalk receive --json              # one JSON object per message
```

### Identity locations

Each identity lives in its own folder.

- `retalk init -u` creates `~/.local/share/retalk/default/`.
- `retalk init -u work` creates `~/.local/share/retalk/work/`.
- `retalk init ./alice` creates an identity at `./alice/`.

Every command finds its identity in this order:

1. `-s DIR`
2. `-u [NAME]`
3. `STORE` environment variable
4. user-level `default`, if it exists

Only `retalk init` creates an identity. Other commands fail if the selected
folder does not already contain one. Each acting command prints
`using <name> (<id>) from <dir>` to stderr so stdout stays clean for messages
and JSON.

Machines need a roughly correct clock. Server request signatures expire after
about 2.5 minutes.

## Two-minute local demo

This demo runs on one machine. It creates two identities and a local relay.

Terminal 1:

```sh
SERVER_AUDIENCE=http://127.0.0.1:8766 retalk-server
```

Terminal 2:

```sh
export SERVER_URL=http://127.0.0.1:8766

ALICE_ID=$(PICKLE_SECRET=alice-secret retalk init ./alice --name alice)
BOB_ID=$(PICKLE_SECRET=bob-secret retalk init ./bob --name bob)

PICKLE_SECRET=alice-secret retalk add bob "$BOB_ID" -s ./alice
PICKLE_SECRET=bob-secret retalk add alice "$ALICE_ID" -s ./bob

PICKLE_SECRET=bob-secret retalk receive -s ./bob
PICKLE_SECRET=alice-secret retalk send bob "hello bob" -s ./alice

PICKLE_SECRET=bob-secret retalk receive -s ./bob
# alice: hello bob

PICKLE_SECRET=bob-secret retalk send alice "hi alice, got it" -s ./bob
PICKLE_SECRET=alice-secret retalk receive -s ./alice
# bob: hi alice, got it
```

The first `receive` publishes Bob's keys so Alice can start a session.

To inspect what the server stored:

```sh
sqlite3 server.db 'SELECT body FROM messages LIMIT 1'
```

You should see base64 ciphertext, not plaintext. Delivered messages are
deleted from the server.

## Two machines

Machine A:

```sh
retalk init -u --name alice --server https://server.example.com
# Share the printed user ID with Bob out-of-band.

retalk add bob <bob-user-id>
retalk send bob "hello from across the internet"
retalk receive --follow
```

Machine B does the same with Bob's identity and Alice's user ID.

After `init -u`, commands use the user-level identity by default, so you do
not need `-s` flags.

## Scripting

Drain the mailbox from cron:

```cron
*/5 * * * * PICKLE_SECRET=... retalk receive --json >> ~/inbox.jsonl 2>/dev/null
```

Pipe messages into another tool:

```sh
retalk receive --json | jq -r .text
```

Tiny auto-responder:

```sh
retalk receive --follow --json | while read -r msg; do
  sender=$(jq -r .from <<<"$msg")
  text=$(jq -r .text <<<"$msg")
  retalk send "$sender" "you said: $text"
done
```

## Library usage

```python
from retalk import User

alice = User(
    "https://server.example.com",
    pickle_secret="...",
    name="alice-1",
    store="alice/store.db",
)

print(alice.user_id())       # share out-of-band
alice.publish()              # publish public keys to this server
alice.send("<bob-user-id>", "hello")

for sender, name, text in alice.receive():
    print(name or sender, text)
```

## Delivery

Each message carries an ID inside the encrypted envelope. When the recipient
decrypts it, the recipient sends back an encrypted acknowledgement.

Senders keep ciphertext in a local outbox until it is acknowledged.
`maintain()` resends messages that have gone unacknowledged for 2 minutes.
`retalk receive --follow` runs `maintain()` automatically.

This makes server loss or server migration recoverable:

- clients republish missing public keys,
- senders re-upload unacknowledged outbox messages, and
- recipients drop duplicate ciphertext that they have already processed.

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

- [docs/auth.md](docs/auth.md) explains signed requests, the exact wire
  format, replay protection, and why retalk does not use bearer tokens.
- [docs/server.md](docs/server.md) explains what the relay stores, what
  metadata it sees, why mailbox calls are authenticated, and what a hostile
  server can and cannot do.
- [docs/olm.md](docs/olm.md) explains one-time prekeys, fallback keys,
  replenishment, and rotation.

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

## Release

Publishing is automated. Creating a GitHub Release triggers
`.github/workflows/publish.yaml`, which checks that the tag matches the
package version, runs the tests, builds with uv, and publishes to PyPI through
trusted publishing.

To cut a release:

1. Bump `version` in `pyproject.toml` and `src/retalk/__init__.py`.
2. Commit and push.
3. Create a release whose tag is the version, optionally prefixed with `v`.

```sh
gh release create v0.0.1 --title v0.0.1 --notes "first beta"
```

Maintainers only need to do PyPI setup once: on pypi.org, add a trusted
publisher for project `retalk` pointing at this repository, workflow
`publish.yaml`, environment `pypi`.
