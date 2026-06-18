# Running the server on a free Hugging Face Space

A Hugging Face **Docker Space** gives you a public HTTPS URL with TLS already
terminated, on the free CPU tier, with no domain, no firewall changes, and no
`cloudflared`. You push two small files (a `README.md` and a `Dockerfile`),
Hugging Face builds the container and hosts it at
`https://<owner>-<space>.hf.space`. The steps below were run end to end against
a live Space.

This is the quickest zero-cost way to put `retalk-server` on the internet. Read
the [trade-offs](#what-you-give-up-on-the-free-tier) first — the free tier has
no persistent disk and sleeps when idle, so it suits a personal or testing
relay, not something that must never drop in-flight mail. For that, use
[gcp.md](gcp.md) + [cloudflare.md](cloudflare.md).

## The one rule that matters for retalk

Clients sign every request and bind the signature to the server URL, so
**`RETALK_SERVER_AUDIENCE` must be the exact public URL clients use**. On a Space that
URL is deterministic:

```text
https://<owner>-<space>.hf.space
```

lowercased, with the `/` between owner and space replaced by `-`. For
`alice/retalk-relay` it is `https://alice-retalk-relay.hf.space`. If
`RETALK_SERVER_AUDIENCE` and that URL disagree, every request fails with
`bad signature`. You set it as a Space **variable** (below); the `Dockerfile`
refuses to start without it rather than serve an audience that silently breaks
every client.

Hugging Face terminates TLS at its edge and forwards plain HTTP to the
container, so the server itself still speaks HTTP on one port; only the public
URL is HTTPS.

## Create the two files

In an empty local folder, create `README.md`. The YAML header is what tells
Hugging Face this is a Docker Space and which port to expose:

```text
---
title: Retalk Relay
emoji: 🔁
colorFrom: blue
colorTo: green
sdk: docker
app_port: 7860
pinned: false
---

# retalk relay

Untrusted relay for retalk. Stores only public keys and ciphertext; never sees
plaintext or private keys.
```

Then create `Dockerfile`:

```dockerfile
FROM python:3.12-slim

RUN pip install --no-cache-dir retalk

# Hugging Face runs the container as uid 1000, so write the DB under its home.
RUN useradd -m -u 1000 user
USER user

ENV HOME=/home/user \
    PATH=/home/user/.local/bin:$PATH \
    RETALK_SERVER_HOST=0.0.0.0 \
    RETALK_SERVER_PORT=7860 \
    RETALK_SERVER_DB=/home/user/server.db

WORKDIR /home/user
EXPOSE 7860

# RETALK_SERVER_AUDIENCE must equal the Space's public URL; set it as a Space variable.
# Fail loudly if it's missing rather than break every client signature.
CMD ["sh", "-c", ": \"${RETALK_SERVER_AUDIENCE:?set the RETALK_SERVER_AUDIENCE Space variable to https://<owner>-<space>.hf.space}\"; echo \"retalk audience: $RETALK_SERVER_AUDIENCE\"; exec retalk-server --audience \"$RETALK_SERVER_AUDIENCE\""]
```

`app_port` (7860) and `RETALK_SERVER_PORT` must match: Hugging Face routes public HTTPS
to exactly that one container port.

## Create the Space and set the audience

You can do this from the web UI or the CLI.

**Web UI:** go to https://huggingface.co/new-space, pick **Docker -> Blank**,
the **CPU basic - free** hardware, and **Public** visibility. Then, in the
Space's **Settings -> Variables and secrets**, add a **variable** (not a secret
— the URL isn't sensitive) named `RETALK_SERVER_AUDIENCE` with value
`https://<owner>-<space>.hf.space` for your Space. Finally add the two files
(drag-and-drop in the *Files* tab, or `git push`).

**CLI** (`pip install huggingface_hub`, then `hf auth login`):

```sh
hf repo create <owner>/retalk-relay --repo-type space --space-sdk docker
python -c "from huggingface_hub import HfApi; HfApi().add_space_variable('<owner>/retalk-relay', 'RETALK_SERVER_AUDIENCE', 'https://<owner>-retalk-relay.hf.space')"
hf upload <owner>/retalk-relay . --repo-type space   # run from the folder with the two files
```

The Space must be **public**. A private Space requires a Hugging Face token on
every request, which retalk clients don't send — so remote clients could not
reach it. Public here means the same thing as any open retalk server: anyone who
finds the URL can publish keys and get a mailbox. See
[Is an open relay safe?](#is-an-open-relay-safe) below.

## Watch it build, then test

Open the Space's **Logs** tab. The build takes a minute or two; when it's
running you'll see the line the `Dockerfile` prints:

```text
retalk audience: https://<owner>-retalk-relay.hf.space
```

If instead the container exits with `set the RETALK_SERVER_AUDIENCE Space variable...`,
you skipped the variable step above — add it and restart the Space.

Then, from your own machine, do a round trip against the public URL:

```sh
retalk init --user alice --display-name alice --relay https://<owner>-retalk-relay.hf.space
# create a second identity for "bob" the same way, then have each `add` the
# other's user id as a peer, then:
retalk send --peer bob "hello through hugging face"
retalk receive --all --dir ./bob
```

If sends fail with `bad signature`, the audience and the client URL don't match
— make the `RETALK_SERVER_AUDIENCE` variable exactly equal to the `--relay` URL
(scheme included, no trailing slash) and restart.

## What you give up on the free tier

The free tier is genuinely free, but two limits matter for a relay:

- **No persistent storage.** The container filesystem is wiped on every
  restart — a new commit, a factory reboot, or waking from sleep. `server.db`
  goes with it. retalk is built so the [server database is
  disposable](../server.md#the-server-database-is-disposable): clients
  republish their public keys automatically on their next request, and senders
  resend unacknowledged messages from their local outbox, so the relay heals
  itself. (You can watch this happen: right after a rebuild the server knows no
  one's keys, so a send to a peer who hasn't re-contacted the server yet fails
  with `unknown peer or no published keys` until that peer's next command
  republishes.) The real cost is that **messages sitting undelivered in a
  mailbox at the moment of a reset are dropped** (the sender resends, but a
  recipient that never polls in between won't see the gap). For a personal or
  testing relay that's fine. If you can't tolerate it, attach paid [persistent
  storage](https://huggingface.co/docs/hub/spaces-storage) and point
  `RETALK_SERVER_DB` at the mounted path (e.g. `/data/server.db`), or use the
  [GCP](gcp.md) route instead.
- **It sleeps when idle.** Free Spaces pause after about 48 hours with no
  traffic. A client running `retalk receive --follow` polls every couple of
  seconds, which counts as traffic and keeps the Space awake; if everything
  goes quiet for two days the Space pauses and you restart it from its page (the
  next request also wakes it, after a short cold start).

Also note Hugging Face Spaces are intended for ML apps and demos; a messaging
relay is a lightweight, unofficial use. It's great for trying retalk out with
zero setup, but for a relay you depend on, a small VM ([gcp.md](gcp.md)) behind
[Cloudflare](cloudflare.md) is the sturdier home.

## Is an open relay safe?

Yes, in the same sense the rest of retalk is. The server only ever holds public
key material and ciphertext (deleted on delivery), and it
[authenticates every request](../auth.md) with the caller's signature, so a
stranger can't drain your mailbox or forge messages from you. What an open relay
*can't* do is stop strangers from using it as a relay or from generating load.
On a free Space your main exposure is resource abuse (someone hammering it), and
the only built-in backstop is that Hugging Face will pause a Space that misuses
resources. If you want a closed relay, the free Space isn't the right tool —
run your own VM and put authentication in front of it.

## Cost

The **CPU basic** hardware is free and stays free. The only thing you'd ever
pay for is optional persistent storage (a paid add-on) or upgraded hardware,
neither of which retalk needs. Deleting the Space leaves nothing to bill.

## Delete it

From the Space's **Settings** tab, scroll to *Delete this Space*. Or from the
CLI:

```sh
hf repo delete <owner>/retalk-relay --repo-type space
```
