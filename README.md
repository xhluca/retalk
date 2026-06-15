# retalk

Minimal, self-hosted, end-to-end-encrypted messaging bus for AI agents,
services, and humans. A dumb
public server relays opaque Olm ciphertext and serves a public-key
directory; all crypto happens client-side with vodozemac (the
project's only dependency — the transport is plain HTTP+JSON over the
standard library). The server is
assumed hostile: it never sees plaintext or private keys. It still sees
metadata (who/when/sizes) — accepted for v1.

(Architecturally the server is a *message broker*: an intermediary that
only stores and forwards sealed messages. The docs just say "server.")

Terminology: a **user** is any participant — a keypair plus a mailbox
(an AI agent, a bot, a person at a terminal). The human or organization
who runs one or more users is their **owner**: Alice might own three
users, one per agent she operates. The protocol models users; owners
exist only in prose (and, in future work, as the cross-signing key that
groups a person's users).

## Identity model

- A user's **ID** is the sha256 fingerprint (32 hex chars) of its
  self-generated public keys. The server enforces this at publish time,
  and clients re-check it on every key lookup — so an ID is
  **self-verifying**: a malicious server cannot serve substitute keys for
  an ID without every client refusing (`PIN MISMATCH`). Sharing your ID
  with a peer over any channel the server doesn't control (chat, email, in
  person — "out-of-band") is simultaneously sharing your address *and*
  your pin.
- **There are no accounts, tokens, or registration.** Every server call is
  signed with the user's own key — each request proves its origin by
  itself, nothing credential-like exists to steal or rotate, and
  onboarding to any server is just publishing your keys. See
  [docs/auth.md](docs/auth.md).
- A user's self-chosen **name** travels inside the encrypted message
  (the server never sees it) and displays prefixed with `~` — unverified,
  since anyone can call themselves anything. Save a local **peer name**
  (`retalk add bob <id>`) for a trusted label; it never leaves your
  machine and always wins over the sender's `~name`.
- IDs are server-independent: if you move to a new server, users just
  publish keys there and existing sessions keep working.

## Install

```
uv add retalk
```

This provides the `retalk` library (`from retalk import User`) and two
commands: `retalk` (the user CLI) and `retalk-server` (the relay). To get
the CLI on your PATH globally instead: `uv tool install retalk` (or
`uvx retalk ...` for one-off runs).

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

No user setup needed — users onboard themselves. `SERVER_AUDIENCE` must
be the exact URL users connect to (request signatures are bound to it).
For internet exposure put TLS in front, e.g. Caddy:

```
server.example.com {
    reverse_proxy 127.0.0.1:8766
}
```

## CLI

One-time setup on each machine:

```
retalk init -u --name alice-1 --server https://server.example.com
```

`init` creates the identity — keys encrypted with a secret you choose
(prompted, or `PICKLE_SECRET` for scripts) — and prints your **user ID**.
Exchange IDs with your peer out-of-band, then:

```
retalk add bob <bob's user id>     # save a trusted local name
retalk send bob "hello"            # one-shot encrypted send
retalk receive                     # drain my mailbox once
retalk receive --follow            # keep polling; auto-maintains keys
retalk receive --json              # one JSON object per message (for scripts)
retalk id                          # print my user id again
```

Identities live in folders. `init -u [NAME]` puts one at
`~/.local/share/retalk/NAME/` (default name: `default`); `init ./alice`
puts one wherever you say. Every command picks its identity via
`-s DIR` > `-u [NAME]` > `STORE` env > the user-level default if it
exists — and **only `init` ever creates one**, so a mistyped path fails
loudly instead of silently minting a new identity. Each command prints a
`using <name> (<id>) from <dir>` banner to stderr so you always know
who acted. Users need a roughly correct clock (NTP is enough) — request
signatures expire after ~2.5 minutes.

## Examples

### Two-minute local demo (one machine)

Runnable verbatim — three identities never leave your machine. Terminal 1,
the relay:

```sh
SERVER_AUDIENCE=http://127.0.0.1:8766 retalk-server
```

Terminal 2 — create both identities, introduce them, talk. `PICKLE_SECRET`
is set inline here to skip the interactive prompts; in real use just let
`init` prompt you.

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

Check what the server actually saw — ciphertext only:

```sh
sqlite3 server.db 'SELECT body FROM messages LIMIT 1'    # base64 noise, no plaintext
```

### Two machines for real

Machine A (and the mirror image on machine B):

```sh
retalk init -u --name alice --server https://server.example.com
# prints alice's user id -> hand it to bob out-of-band (chat, email, paper)

retalk add bob <bob's id>
retalk send bob "hello from across the internet"
retalk receive --follow          # live tail; ctrl-c to stop
```

After `init -u`, no `-s` flags are needed — the user-level identity is the
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

Every message carries an ID inside the encrypted envelope; recipients send
back an encrypted ack on successful decryption. Senders keep the
ciphertext in a local outbox until acked, and `maintain()` (run
automatically by `receive --follow`) re-sends anything unacknowledged for
2 minutes — so messages stranded on a dead or migrated server are
recovered by re-uploading the outbox (`User.flush_outbox()`). Duplicates
are safe: the ratchet refuses re-used message keys, so an
already-delivered copy is detected, re-acked, and dropped instead of
surfacing twice.

## Key maintenance (automatic)

`maintain()` keeps server-side key material healthy: it replenishes
one-time keys when the unclaimed stash runs low (below 20, in batches of
100) and rotates the reusable fallback key daily (the fallback key is
served to senders only when the one-time pool is empty, so key exhaustion
degrades gracefully instead of blocking new sessions). `receive --follow`
calls it every minute; library users can tune every threshold via
`User.maintain()` parameters.

## Docs

- [docs/auth.md](docs/auth.md) — how users prove who they are: signed
  requests explained without jargon, what an attacker gets in each
  scenario, the exact wire format, and why this was chosen over tokens.
- [docs/server.md](docs/server.md) — the server's mechanics: what it
  stores and sees, why calls are authenticated at all (mailbox ownership),
  self-chosen names vs peer names, and what a hostile server can and cannot do.
- [docs/olm.md](docs/olm.md) — the crypto: one-time prekeys, why each is
  single-use, replenishment, and fallback-key rotation grace windows.

## Releasing

Publishing is automated: pushing a **GitHub Release** triggers
`.github/workflows/publish.yaml`, which checks the tag matches the
package version, runs the tests, builds with uv, and uploads to PyPI via
trusted publishing (no stored token).

To cut a release:

1. Bump `version` in `pyproject.toml` **and** `src/retalk/__init__.py`
   (keep them in sync — CI fails the release otherwise). Stay on `0.0.x`
   during beta.
2. Commit and push.
3. Create a release whose tag is the version, optionally `v`-prefixed:
   ```
   gh release create v0.0.1 --title v0.0.1 --notes "first beta"
   ```

One-time PyPI setup (done once per project, by a maintainer): on
pypi.org add a **trusted publisher** for project `retalk` -> this repo,
workflow `publish.yaml`, environment `pypi`.

## Test

```
uv run python -m unittest discover -s tests -v
```

Run from the repo root (stdlib unittest; no extra dependency). The suites
are self-contained: they start their own servers on ports 8767-8769 and
use temporary directories for all state, so they never touch your real
stores. CI runs the same discovery on every push/PR via GitHub Actions
(`.github/workflows/run-tests.yaml`). See
[tests/README.md](tests/README.md).

`tests/test_e2ee.py` proves 14 criteria: round-trip decryption both ways,
no plaintext in the server DB (and delivered mail deleted), PIN MISMATCH refusal when the server's
stored key is tampered with (via the fingerprint ID alone), fallback-key
session establishment when the one-time pool is drained, replenishment
and fallback rotation via `maintain()`, decryption of in-flight messages
across a rotation, ratchet integrity under concurrent sends from two
processes sharing one store, session survival across a migration to a
brand-new server, end-to-end delivery acks, outbox recovery of stranded
messages with graceful duplicate rejection, and rejection of replayed,
stale, and cross-server signed requests. `tests/test_cli.py` drives the
real CLI subprocesses through init/add/send/receive, including the
refusal paths (no identity, double init, wrong secret).
