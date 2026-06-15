# retalk

A minimal, self-hosted, end-to-end-encrypted messaging bus for AI agents,
services, and humans.

The server is a relay. It stores and forwards encrypted blobs and serves a
directory of public keys. All encryption happens on the client using
vodozemac (retalk's only dependency; the transport is plain HTTP+JSON over
the standard library). The server never sees plaintext or private keys, so
you can run it on a machine you don't fully trust. It does see metadata
(who talks to whom, when, and message sizes), which v1 accepts.

A **user** is one participant: a keypair plus a mailbox. That could be an AI
agent, a bot, or a person at a terminal. The person or organization running
one or more users is their **owner**. Alice might own three users, one per
agent she runs. The protocol only models users; owners are a future feature
(a cross-signing key that groups a person's users).

## Identity model

- A user's **ID** is the sha256 fingerprint (32 hex chars) of its public
  keys, which it generates itself. The server checks this when you publish,
  and clients re-check it on every key lookup. So an ID verifies itself: a
  malicious server can't serve different keys for an ID without every client
  rejecting them (`PIN MISMATCH`). When you share your ID over a channel the
  server doesn't control (chat, email, in person), you're sharing both your
  address and the key fingerprint that pins it.
- **No accounts, tokens, or registration.** Every server call is signed with
  the user's own key, so each request proves where it came from. There's no
  credential to steal or rotate. Onboarding to a server is just publishing
  your keys. See [docs/auth.md](docs/auth.md).
- A user's self-chosen **name** rides inside the encrypted message (the
  server never sees it) and displays with a `~` prefix. It's unverified,
  since anyone can pick any name. To get a trusted label, save a local
  **peer name** with `retalk add bob <id>`. It stays on your machine and
  always overrides the sender's `~name`.
- IDs don't depend on a server. Move to a new server and users just publish
  their keys there; existing sessions keep working.

## Install

```
uv add retalk
```

This installs the `retalk` library (`from retalk import User`) and two
commands: `retalk` (the user CLI) and `retalk-server` (the relay). To put
the CLI on your PATH globally, use `uv tool install retalk` (or `uvx retalk
...` for one-off runs).

<details>
<summary>Other ways to install (pip, git+, git clone)</summary>

**With pip** (any environment manager):

```
pip install retalk           # library + both commands into the active env
pipx install retalk          # CLI on your PATH, isolated env
```

**Straight from the repository** (latest main, no PyPI release needed):

```
uv add git+https://github.com/xhluca/retalk
pip install git+https://github.com/xhluca/retalk
```

**From a clone** (for development):

```
git clone https://github.com/xhluca/retalk
cd retalk
uv sync                      # creates .venv with retalk installed editable
uv run retalk --help
uv run python -m unittest discover -s tests   # run the test suite
```

or without uv: `pip install -e .` inside the clone (editable install;
changes to `src/` take effect immediately).

</details>

## Run the server (one public machine)

```
SERVER_PORT=8766 SERVER_AUDIENCE=https://server.example.com \
  retalk-server
```

There's no user setup; users onboard themselves. `SERVER_AUDIENCE` must be
the exact URL users connect to, because request signatures are bound to it.
To expose the server on the internet, put TLS in front of it, for example
with Caddy:

```
server.example.com {
    reverse_proxy 127.0.0.1:8766
}
```

## CLI

Run this once on each machine:

```
retalk init -u --name alice-1 --server https://server.example.com
```

`init` creates the identity (keys encrypted with a secret you choose, either
at the prompt or via `PICKLE_SECRET` for scripts) and prints your **user
ID**. Exchange IDs with your peer out-of-band, then:

```
retalk add bob <bob's user id>     # save a trusted local name
retalk send bob "hello"            # one-shot encrypted send
retalk receive                     # drain my mailbox once
retalk receive --follow            # keep polling; auto-maintains keys
retalk receive --json              # one JSON object per message (for scripts)
retalk id                          # print my user id again
```

Each identity lives in its own folder. `init -u [NAME]` puts one at
`~/.local/share/retalk/NAME/` (default name: `default`); `init ./alice` puts
one wherever you point it. Every command finds its identity in this order:
`-s DIR`, then `-u [NAME]`, then the `STORE` env var, then the user-level
default if one exists. Only `init` ever creates an identity, so a mistyped
path fails with an error instead of quietly making a new one. Every command
prints a `using <name> (<id>) from <dir>` banner to stderr so you always
know who acted. Users need a roughly correct clock (NTP is enough), since
request signatures expire after ~2.5 minutes.

## Examples

### Two-minute local demo (one machine)

This runs as-is. The three identities never leave your machine. Terminal 1,
the relay:

```sh
SERVER_AUDIENCE=http://127.0.0.1:8766 retalk-server
```

Terminal 2 creates both identities, introduces them, and talks.
`PICKLE_SECRET` is set inline to skip the interactive prompts; in real use,
let `init` prompt you.

```sh
export SERVER_URL=http://127.0.0.1:8766

ALICE_ID=$(PICKLE_SECRET=alice-secret retalk init ./alice --name alice)
BOB_ID=$(PICKLE_SECRET=bob-secret retalk init ./bob --name bob)

PICKLE_SECRET=alice-secret retalk add bob "$BOB_ID" -s ./alice
PICKLE_SECRET=bob-secret retalk add alice "$ALICE_ID" -s ./bob

PICKLE_SECRET=bob-secret retalk receive -s ./bob     # first contact: publishes bob's keys
PICKLE_SECRET=alice-secret retalk send bob "hello bob" -s ./alice

PICKLE_SECRET=bob-secret retalk receive -s ./bob
# alice: hello bob

PICKLE_SECRET=bob-secret retalk send alice "hi alice, got it" -s ./bob
PICKLE_SECRET=alice-secret retalk receive -s ./alice
# bob: hi alice, got it
```

Check what the server actually saw. It's ciphertext only:

```sh
sqlite3 server.db 'SELECT body FROM messages LIMIT 1'    # base64 noise, no plaintext
```

### Two machines for real

Machine A (machine B is the mirror image):

```sh
retalk init -u --name alice --server https://server.example.com
# prints alice's user id -> hand it to bob out-of-band (chat, email, paper)

retalk add bob <bob's id>
retalk send bob "hello from across the internet"
retalk receive --follow          # live tail; ctrl-c to stop
```

After `init -u`, you don't need `-s` flags. The user-level identity is the
default for every command.

### Scripting and automation

```sh
# cron job: drain the mailbox every 5 minutes, append to a log
*/5 * * * * PICKLE_SECRET=... retalk receive --json >> ~/inbox.jsonl 2>/dev/null

# pipe messages into a tool
retalk receive --json | jq -r .text

# a 6-line auto-responder (an "agent"):
retalk receive --follow --json | while read -r msg; do
  sender=$(jq -r .from <<<"$msg")
  text=$(jq -r .text <<<"$msg")
  retalk send "$sender" "you said: $text"
done
```

## Library usage

```python
from retalk import User

alice = User("https://server.example.com", pickle_secret="...",
             name="alice-1", store="alice/store.db")
print(alice.user_id())            # share out-of-band; address + pin in one
alice.publish()                   # onboard to the server
alice.send("<bob's id>", "hello")
for sender, name, text in alice.receive():
    print(name or sender, text)
```

## Delivery guarantees

Every message carries an ID inside the encrypted envelope. When a recipient
decrypts a message, it sends back an encrypted ack. Senders keep the
ciphertext in a local outbox until it's acked. `maintain()` (run
automatically by `receive --follow`) re-sends anything that's gone
unacknowledged for 2 minutes, so messages stranded on a dead or migrated
server are recovered by re-uploading the outbox (`User.flush_outbox()`).
Duplicates are safe: the ratchet refuses re-used message keys, so an
already-delivered copy is detected, re-acked, and dropped instead of showing
up twice.

## Key maintenance (automatic)

`maintain()` keeps your server-side key material healthy. It replenishes
one-time keys when the unclaimed supply runs low (below 20, in batches of
100) and rotates the reusable fallback key daily. The fallback key is served
to senders only when the one-time pool is empty, so running out of one-time
keys slows new sessions down a little instead of blocking them. `receive
--follow` calls `maintain()` every minute; library users can tune every
threshold through `User.maintain()` parameters.

## Docs

- [docs/auth.md](docs/auth.md) — how users prove who they are: signed
  requests explained plainly, what an attacker gets in each scenario, the
  exact wire format, and why we chose this over tokens.
- [docs/server.md](docs/server.md) — what the server does: what it stores and
  sees, why calls are authenticated (mailbox ownership), self-chosen names vs
  peer names, and what a hostile server can and can't do.
- [docs/olm.md](docs/olm.md) — the crypto: one-time prekeys, why each is
  single-use, replenishment, and fallback-key rotation.

## Releasing

Publishing is automated. Pushing a **GitHub Release** triggers
`.github/workflows/publish.yaml`, which checks the tag matches the package
version, runs the tests, builds with uv, and uploads to PyPI via trusted
publishing (no stored token).

To cut a release:

1. Bump `version` in `pyproject.toml` **and** `src/retalk/__init__.py`
   (keep them in sync, or CI fails the release). Stay on `0.0.x` during
   beta.
2. Commit and push.
3. Create a release whose tag is the version, optionally `v`-prefixed:
   ```
   gh release create v0.0.1 --title v0.0.1 --notes "first beta"
   ```

One-time PyPI setup (done once per project, by a maintainer): on pypi.org,
add a **trusted publisher** for project `retalk` pointing at this repo,
workflow `publish.yaml`, environment `pypi`.

## Test

```
uv run python -m unittest discover -s tests -v
```

Run this from the repo root (stdlib unittest, no extra dependency). The
suites are self-contained: they start their own servers on ports 8767-8769
and keep all state in temporary directories, so they never touch your real
stores. CI runs the same discovery on every push and PR via GitHub Actions
(`.github/workflows/run-tests.yaml`). See [tests/README.md](tests/README.md).

`tests/test_e2ee.py` proves 14 criteria: round-trip decryption both ways, no
plaintext in the server DB (and delivered mail deleted), PIN MISMATCH
refusal when the server's stored key is tampered with (using the fingerprint
ID alone), fallback-key session establishment when the one-time pool is
drained, replenishment and fallback rotation via `maintain()`, decryption of
in-flight messages across a rotation, ratchet integrity under concurrent
sends from two processes sharing one store, session survival across a
migration to a brand-new server, end-to-end delivery acks, outbox recovery
of stranded messages with graceful duplicate rejection, and rejection of
replayed, stale, and cross-server signed requests. `tests/test_cli.py`
drives the real CLI subprocesses through init/add/send/receive, including the
refusal paths (no identity, double init, wrong secret).
