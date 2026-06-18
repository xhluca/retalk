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

Emitted by `retalk contacts --json` -- one object per saved peer (the peers you
created with `retalk add`), sorted by name.

| field          | type   | description |
|----------------|--------|-------------|
| `name`         | string | your local name for the peer; never leaves your machine. |
| `fingerprint`  | string | the peer's user id (32-hex key fingerprint). |
| `identity_key` | string | the peer's pinned base64 identity key (`retalk add --identity-key`), or `""` if none was pinned. |

```json
{"name":"bob","fingerprint":"1041c25c...","identity_key":"vGY3...="}
```

## Notes for consumers

- `receive` prints **zero** lines when there is nothing to read; check for
  empty output, not for an error.
- To follow a conversation, match a send receipt's `id` against the `id` of a
  later received message.
