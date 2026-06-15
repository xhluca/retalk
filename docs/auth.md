# Authentication: signed requests

Retalk does not have accounts, passwords, API keys, bearer tokens, or a
registration endpoint. Every server request proves its own origin with a
fresh signature from the user's signing key.

This page explains why that exists, what gets signed, and what another
implementation must match.

## Why the server needs authentication

The server cannot read messages, but it still controls mailboxes.

`read_messages` hands pending ciphertext to a user and then deletes it from
the server. If anyone could call `read_messages` while claiming to be you,
they could make your mail disappear before your client saw it.

The server also labels stored messages with the authenticated sender ID. If
senders were unauthenticated, anyone could send junk that appeared to come
from someone else.

So authentication is not about hiding content. End-to-end encryption already
does that. Authentication protects mailbox ownership and sender identity.

## Why signatures instead of tokens

Most services use a bearer token: a long secret string sent with each
request. Whoever has the token can act as the account.

That design is simple, but the token becomes another secret to protect. It
sits on disk, crosses the network, and can leak through logs or proxies. If
someone sees it once, they can use it until it is rotated.

Retalk users already have a better credential: a keypair.

- The private signing key stays on the user's machine.
- The public signing key can be sent to anyone.
- The private key can sign one exact request.
- Anyone with the public key can verify the signature.
- If the signed request changes by even one byte, verification fails.

The server receives proof that the user approved this request, but it never
receives a reusable secret.

## What gets signed

Each signature covers one canonical string:

```text
tool|server_url|user_id|timestamp|nonce|args_hash
```

Fields:

- `tool`: prevents a signature for `count_keys` from authorizing
  `read_messages`.
- `server_url`: prevents a request captured on one server from working on
  another server. This must match `SERVER_AUDIENCE`.
- `user_id`: says which user is making the request.
- `timestamp`: expires captured requests after about 2.5 minutes.
- `nonce`: a random value used once. It blocks replay inside the timestamp
  window.
- `args_hash`: binds the business arguments. A signed "send to Bob" request
  cannot become "send to Charlie".

The user ID is the sha256 fingerprint of the user's public identity and
signing keys. That means the keys in the request must hash back to the
claimed user ID.

## What the server checks

For every request, the server:

1. Recomputes the fingerprint of the supplied public keys.
2. Rejects the request if the fingerprint does not equal `user_id`.
3. Rejects timestamps more than about 150 seconds in the past or future.
4. Rebuilds the signed string from its own copy of the tool name, audience,
   user ID, timestamp, nonce, and argument hash.
5. Verifies the Ed25519 signature with the supplied public signing key.
6. Inserts the nonce into a short-lived nonce table.
7. Rejects the request if the nonce was already present.

Any failure rejects the request. The nonce table is cleaned automatically
because nonces only matter during the timestamp window.

## Attacker outcomes

- **Traffic sniffing on a no-TLS deployment:** the attacker sees ciphertext,
  public keys, signatures, and metadata. They do not get a reusable token.
  Use TLS anyway, especially to protect metadata in transit.
- **Fast replay of a captured request:** the nonce has already been used, so
  the server rejects the copy.
- **Late replay of a captured request:** the timestamp is stale, so the server
  rejects it.
- **Cross-server replay:** the signature is bound to the original server URL,
  so verification fails on another server.
- **Fully compromised server:** it can drop mail, delay mail, or refuse
  service. It still cannot impersonate you on another server because it never
  saw a reusable credential.
- **Stolen local store without `PICKLE_SECRET`:** the signing key is encrypted
  at rest. The store does not contain a separate token.

## Operational requirements

Clocks must be close enough. A machine using NTP is fine. If a clock is off
by more than about 2.5 minutes, requests fail with a stale or future
timestamp error.

`SERVER_AUDIENCE` must be the exact URL users connect to. For example, if
users connect to `https://server.example.com`, that must be the audience.
Using `http://127.0.0.1:8766` on the server while users connect through
HTTPS will break signatures.

The server keeps a small table of recent nonces. It deletes expired entries
as it handles requests.

## Wire format

Reimplementations must match this byte-for-byte.

Arguments hash:

- Take the tool's business arguments, excluding `auth`.
- Encode them as JSON with keys sorted.
- Use separators `,` and `:` with no spaces.
- Include every parameter explicitly.
- Use `null` for optional parameters, never omission.
- Hash those bytes with sha256.

Signed text:

```text
tool|server_url|user_id|ts|nonce|args_hash
```

Rules:

- UTF-8 encode the signed text.
- `ts` is integer seconds since epoch as a decimal string.
- `nonce` is 32 hex characters.
- The signature is Ed25519 over the UTF-8 bytes, encoded as base64.

The `auth` object sent with every call is:

```json
{
  "user_id": "...",
  "identity_key": "...",
  "signing_key": "...",
  "ts": "...",
  "nonce": "...",
  "sig": "..."
}
```

User ID:

```text
sha256(identity_key_b64 + "|" + signing_key_b64)
```

Use the first 32 hex characters.

## Decision record

Bearer tokens would have been familiar, but they added a second identity
system: keys for encryption, tokens for server access.

Signed requests keep identity in one place. The same keys define the user ID,
pin public keys, and authenticate server calls. The implementation also
removes registration and token lifecycle code.

Accepted costs:

- clients need a roughly correct clock,
- the server needs `vodozemac` for signature verification, and
- the canonical byte format above becomes a compatibility contract.
