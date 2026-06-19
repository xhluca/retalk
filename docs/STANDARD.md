# retalk JSON standard

retalk's command-line interface and Python library exchange data as JSON in a
single, stable shape. This document is the contract: tools that produce or
consume retalk data should follow it.

## Conventions

- **Line-delimited JSON (NDJSON).** Commands that emit zero or more records
  print one JSON object per line on **stdout**, UTF-8, no surrounding array.
- **stdout is data; stderr is not.** Identity banners, progress, and errors go
  to stderr and are never part of the JSON stream.
- **All ids are 32 lowercase hex characters.** Both user ids and message ids
  use this form, but they are unrelated things that merely share a shape:
  a **user id** is a fingerprint (hash) of a user's public keys, while a
  **message id** is a random value the sender mints for one message. Neither
  the message id nor the user id is a secret, and a message id is not derived
  from any key — do not treat one as the other.
- **Be liberal in what you accept.** Consumers should ignore unknown keys so
  the format can grow without breaking them.

## Objects

### Message

Emitted by `retalk receive` -- one object per decrypted message -- and returned
by `User.receive()` (one dict per message).

| field  | type   | description |
|--------|--------|-------------|
| `id`   | string | the message's unique id: a random value the sender mints for this message (not derived from any key, not a user id). Stable across resends, so safe for de-duplication. |
| `from` | string | the sender's user id (a key fingerprint, not the message id). |
| `name` | string | display label: your saved peer name; else the sender's self-chosen name prefixed `~` (unverified); else `""`. |
| `text` | string | the decrypted message body. |

```json
{"id":"7d1f...c0","from":"1041c25c...","name":"bob","text":"hello"}
```

There is no timestamp field: message timing is metadata the relay sees, not
part of the authenticated message, so it is deliberately not surfaced here.

`receive` also emits [shared-contact](#shared-contact) records (`retalk share`)
in the same stream; a consumer that only wants chat messages keeps the records
with a `text` field and ignores those with `"kind": "contact"`.

### Send receipt

Emitted by `retalk send` -- exactly one object -- and returned by `User.send()`
as the `id` string.

| field | type   | description |
|-------|--------|-------------|
| `id`  | string | the id assigned to the message just sent; matches the `id` the recipient will see. |
| `to`  | string | the recipient's user id. |

```json
{"id":"7d1f...c0","to":"38b151a1..."}
```

### Contact

Emitted by `retalk contacts --json` -- one object per saved peer (created with
`retalk add`), sorted by name. The same object is the **contact card** that
`retalk show` prints, `retalk share` sends (inside a shared-contact record,
below), and `retalk import` ingests -- so a contact can be copied between
identities verbatim.

| field          | type    | description |
|----------------|---------|-------------|
| `name`         | string  | your local name for the peer; never leaves your machine. |
| `fingerprint`  | string  | the peer's user id (32-hex key fingerprint). |
| `identity_key` | string  | the peer's base64 identity key, recorded by `retalk verify`; `""` until verified. |
| `signing_key`  | string  | the peer's base64 signing key, recorded by `retalk verify`; `""` until verified. |
| `verified`     | boolean | `true` once the peer's keys have been recorded and checked against the fingerprint (via `retalk verify`); `false` for an add-only contact. |

```json
{"name":"bob","fingerprint":"1041c25c...","identity_key":"vGY3...=","signing_key":"Kcx2...=","verified":true}
```

An unverified contact (added but not yet verified) has empty `identity_key` and
`signing_key` and `"verified": false`. Messaging still works -- the keys are
fetched and checked against the fingerprint on the fly; `retalk verify` just
makes that explicit and records the result.

### Shared contact

Emitted by `retalk receive` -- and returned by `User.receive()` -- when a peer
sends you a contact with `retalk share`, in place of a Message. It carries the
distinguishing field `"kind": "contact"`; a chat message has no `kind` and a
`text` field instead, so the two are told apart by which of `text`/`card` is
present.

| field  | type   | description |
|--------|--------|-------------|
| `id`   | string | the message id (as for a Message). |
| `from` | string | the sender's user id -- the peer who shared the contact, not the contact being shared. |
| `name` | string | display label for the **sender** (as for a Message): your saved name for them, else their `~`-prefixed self-chosen name, else `""`. |
| `kind` | string | always `"contact"`. |
| `card` | object | the shared contact as a [Contact](#contact) object: the introduced user's `fingerprint`, recommended `name` (nickname), and `identity_key`/`signing_key` (`""` when the sharer had not verified them). |

```json
{"id":"7d1f...c0","from":"38b151a1...","name":"alice","kind":"contact","card":{"name":"bob","fingerprint":"1041c25c...","identity_key":"vGY3...=","signing_key":"Kcx2...=","verified":true}}
```

`retalk import` saves the `card` as a local peer, re-checking any keys against
the `fingerprint` (a card whose keys do not hash to it is refused, never
trusted). The recipient is free to keep the recommended `name` or choose
another (`import --as NAME`).

### Share receipt

Emitted by `retalk share` -- exactly one object -- and returned by
`User.share()` as the `id` string.

| field    | type   | description |
|----------|--------|-------------|
| `id`     | string | the id of the share message just sent; matches the `id` the recipient sees. |
| `to`     | string | the recipient's user id (who you introduced the contact *to*). |
| `shared` | string | the shared contact's user id (who you introduced). |

```json
{"id":"7d1f...c0","to":"38b151a1...","shared":"1041c25c..."}
```

## Notes for consumers

- `receive` prints **zero** lines when there is nothing to read; check for
  empty output, not for an error.
- To follow a conversation, match a send receipt's `id` against the `id` of a
  later received message.
