# retalk

retalk lets AI agents, bots, and cron jobs — and their humans — exchange
end-to-end-encrypted messages from the command line, with the guarantees
people expect from Signal. No accounts and nothing to sign up for: an
identity is a keypair created by one command, and its fingerprint is its
address. Every message is encrypted with Olm (via `vodozemac`), so the relay
in the middle — a single process you can run anywhere — holds only public
keys and ciphertext, and deletes each message on delivery
([what a hostile relay can and can't do](docs/server.md)). Output is JSON
lines, so it pipes.

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

<details>
<summary>New to uv? Install it first</summary>

[uv](https://docs.astral.sh/uv/) is a fast Python package manager. Install it
once:

```sh
curl -LsSf https://astral.sh/uv/install.sh | sh   # macOS / Linux
# Windows: powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
# or, with an existing Python: pip install uv
```

Then the `uv`/`uvx` rows below work as written. Which one to pick:
`uv tool install retalk` gives you a global `retalk` command in its own
isolated environment (best for daily use); `uv add retalk` adds it to the
current project's dependencies; `uvx retalk` runs it one-off without
installing anything.

</details>

<table>
<thead><tr><th>Method</th><th>Command</th></tr></thead>
<tbody>

<tr>
<td>

`pip3`

</td>
<td>

```sh
pip3 install retalk
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

`pip3` (install from git)

</td>
<td>

```sh
pip3 install git+https://github.com/xhluca/retalk
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

This gives you the Python library (`import retalk`) and two commands:
`retalk` (the client) and `retalk-server` (the relay). Next: [Quickstart](#quickstart).

<details>
<summary>Installing from a development clone</summary>

```sh
git clone https://github.com/xhluca/retalk
cd retalk
uv sync
uv run retalk --help
uv run python -m unittest discover -s tests
```

Without uv, run `pip3 install -e .` inside the clone.

</details>

## Quickstart

Three steps get you messaging. You run them on your machine; your peer runs
the same three on theirs.

```sh
# 1. Create your identity. This prints your USER ID (a 32-hex fingerprint) —
#    share it with your peer over any channel (chat, email, in person).
retalk init --user alice --passphrase "<YOUR-PASSPHRASE>"

# tell this shell which user to act as, and its passphrase
export RETALK_USER=alice
export RETALK_PASSPHRASE="<YOUR-PASSPHRASE>"
# alternatively, pass -u / -p on each command instead

# 2. Save your peer's ID under a name. --verify fetches and pins their keys
#    now; without it that happens on your first message.
retalk add "<bobs-user-id>" --peer "bob" --verify

# 3. Message each other.
retalk send --peer "bob" "hello"
retalk receive --peer "bob"              # print bob's replies once...
retalk receive --peer "bob" --follow     # ...or keep listening
```

What the steps rely on:

- **Relay.** With no `--relay`, commands use the public test relay
  `https://retalk-relay.mcgill-nlp.org` — fine for trying retalk out, but
  best-effort with **no uptime guarantee**. Use your own with
  `retalk init --relay URL` (saved into the identity), the `RETALK_RELAY` env
  var, or `retalk config --relay URL` (owner-wide default). See
  [Run your own relay](#run-your-own-relay).
- **Reachability.** `init` publishes your public keys to the relay
  automatically, so peers can message you right away. Skip that with
  `--no-register` and publish later with `retalk register`.
- **Passphrase.** It encrypts your private keys at rest, and every later
  command needs it again (`-p` or `RETALK_PASSPHRASE` — there are no
  interactive prompts). For agents or throwaway identities,
  `--no-passphrase` stores keys unencrypted and warns you loudly.
- **Lost your ID?** `retalk id` reprints it (`retalk id --last` for the most
  recently created identity). `init` also prints a ready-to-paste invite for
  onboarding a peer who isn't on retalk yet.

<details>
<summary>Troubleshooting: <code>ssl.SSLCertVerificationError: … unable to get local issuer certificate</code></summary>

If your first command that touches the relay (`init`, `register`, `send`,
`receive`, `verify`) dies with this traceback, your **Python has no root CA
certificates** — the relay and retalk are fine. It is most common on macOS
with a python.org installer (the traceback shows
`/Library/Frameworks/Python.framework/Versions/3.XY/...`), which ships
without CA certs wired up.

**Fix for python.org Pythons on macOS** — run the certificate installer that
ships with your Python version, then retry:

```sh
open "/Applications/Python 3.10/Install Certificates.command"   # match your version
```

**Fix for any Python / OS** — point Python at a CA bundle via `SSL_CERT_FILE`:

```sh
python3 -m pip install certifi
export SSL_CERT_FILE="$(python3 -m certifi)"    # add to your shell profile
```

On macOS, `export SSL_CERT_FILE=/etc/ssl/cert.pem` (the system bundle) also
works.

</details>

## Commands

One line per subcommand, matching `retalk --help`. Run
`retalk <command> --help` for its flags and examples, or read the
[full command reference](docs/README.md#command-reference).

| Command | What it does |
| --- | --- |
| `init` | Create a new identity (the only command that ever does) and publish its keys. |
| `id` | Print my user id (`--card`/`--json` for a shareable Contact card, `--invite-message` for a paste-able invite). |
| `add` | Save a peer's user id, optionally under a local name (`--peer "NAME"`); `--verify` pins their keys now. |
| `verify` | Record a saved peer's keys (explicit first contact). |
| `contacts` | List saved peers; `--show` one as a Contact card, `--remove` one. |
| `share` | Send a saved contact to a peer (an introduction). |
| `import` | Save a contact from a shared Contact card. |
| `block` | Silently drop a sender's messages (`--remove` to undo, `--list` them). |
| `sync` | Reconcile this identity with the relay (keys + outbox). |
| `register` | Publish this identity's keys to the relay (make it reachable). |
| `send` | Encrypt and send one message. |
| `receive` | Decrypt pending messages (`--follow` to keep listening). |
| `history` | Replay messages saved by `send`/`receive --save`. |
| `show` | Render the saved conversation with a peer as a chat (`--follow` keeps it live). |
| `config` | Show or set owner-wide defaults (e.g. the default relay). |

Every command picks the identity it acts as from `--dir DIR`, then
`--user`/`-u NAME`, then the `RETALK_USER` env var — retalk never guesses
([details](docs/README.md#selecting-the-user)). Results go to stdout; banners
and errors go to stderr, so output pipes cleanly into `jq` and friends
([scripting recipes](docs/README.md#scripting-the-cli)).

## Concepts

- **User** — anything with a keypair and a mailbox: a person, an AI agent, a
  service. Its **identity** is a local folder (`~/.retalk/NAME/`, created by
  `retalk init`) holding the encrypted keys, sessions, contacts, and outbox.
- **User ID** — a 32-hex sha256 fingerprint of the user's public keys. It is
  both the address peers send to *and* the pin that lets clients reject
  substituted keys, so share it over any channel the relay does not control.
- **Peer** — another user you saved with `retalk add`, addressed by
  fingerprint or by your local name for them. Contacts live in a per-identity
  list plus an owner-wide global list shared by all your identities
  ([details](docs/README.md#contacts--add-verify-contacts)).
- **Relay (server)** — the untrusted middleman. It stores public keys and
  ciphertext (deleted on delivery) and forwards sealed mail; it never sees
  plaintext, private keys, or names — though it does see metadata
  ([trust model](docs/server.md)).
- **Names** — display names and peer names are conveniences layered on top of
  fingerprints, never identity ([how names work](docs/README.md#creating-a-user)).

## Run your own relay

> [!NOTE]
> This is **optional**: the public test relay
> `https://retalk-relay.mcgill-nlp.org` works out of the box (no uptime
> guarantee — testing only). Self-host for anything you rely on.

```sh
retalk-server --host 127.0.0.1 --port 8766 --audience https://server.example.com
```

One process, one SQLite file, no server-side user setup — users publish their
own keys. `--audience` is the public URL clients pass as `--relay` (request
signatures are bound to it, so it must match exactly); for internet use put a
TLS proxy in front. Flag details and free hosting guides (Hugging Face,
Cloudflare Tunnel, GCP):
[docs → running a server](docs/README.md#running-a-server-on-the-internet).

## Try it locally

A full round trip on one machine, no internet needed: one relay and two users
in three terminals.

```sh
# terminal 1 — the relay (leave it running; local demo, so no --audience needed)
retalk-server --host 127.0.0.1 --port 8766
```

```sh
# terminal 2 — "alice"
export RETALK_USER=alice RETALK_PASSPHRASE=alice-secret
retalk init --relay http://127.0.0.1:8766      # prints alice's user id
retalk add "<bobs-id>" --peer "bob"                # paste the id from terminal 3
retalk send --peer "bob" "hello bob"
retalk receive --peer "bob"                      # read bob's reply
```

```sh
# terminal 3 — "bob"
export RETALK_USER=bob RETALK_PASSPHRASE=bob-secret
retalk init --relay http://127.0.0.1:8766      # prints bob's user id
retalk add "<alices-id>" --peer "alice"            # paste the id from terminal 2
retalk receive --peer "alice"                    # -> {..., "name":"alice", "text":"hello bob"}
retalk send --peer "alice" "hi alice"
```

Each terminal exports its own `RETALK_USER`/`RETALK_PASSPHRASE` because the
two users have different secrets. `init` publishes each user's keys, so the
sends work in any order once both have run it; every `receive` prints pending
mail as JSON lines and acknowledges it, after which the relay deletes the
ciphertext.

Check that the relay never held plaintext — send one message nobody receives
(delivered mail is deleted from the relay, so only pending mail is visible),
then look inside `server.db`, which sits where terminal 1 started the relay:

```sh
retalk send --peer "bob" "one more"                       # ...and don't receive it
sqlite3 server.db 'SELECT body FROM messages LIMIT 1'   # base64 ciphertext
```

## Going further

The [docs index](docs/README.md) covers everything this page doesn't:

- [Sharing contacts](docs/README.md#sharing-contacts--share-import) —
  introduce saved peers to each other with `share`/`import` instead of
  copying fingerprints by hand.
- [Saving a message history](docs/README.md#messaging--send-receive-history) —
  opt-in, sealed-at-rest conversation logs with `--save` /
  `RETALK_SAVE_MESSAGE=1`, replayed by `history`.
- [Selecting the user](docs/README.md#selecting-the-user) — `--user` vs
  `--dir`, `RETALK_HOME`, and how commands resolve which identity acts.
- [Filtering who can reach you](docs/README.md#filtering-who-can-reach-you) —
  `block` and `--peers-only`, applied before any decryption.
- [Scripting the CLI](docs/README.md#scripting-the-cli) — cron polling, `jq`
  pipelines, a tiny auto-responder.
- [Library usage](docs/README.md#library-usage) — the same features from
  Python via `retalk.User`.
- Protocol internals: [signed requests](docs/auth.md) ·
  [key management](docs/olm.md) · [server trust model](docs/server.md) ·
  [JSON data contract](docs/STANDARD.md).
