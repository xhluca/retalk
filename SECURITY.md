# Security

## Status

retalk encrypts everything end to end by design, but the code has not been
independently audited yet. Please keep that in mind before trusting it with
sensitive messages.

What the design does and does not protect is documented in the
[server trust model](docs/server.md): the relay stores only public keys and
undelivered ciphertext, and cannot read messages or impersonate users, but it
does see metadata (who talks to whom, when, and message sizes).

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[Security tab](https://github.com/xhluca/retalk/security/advisories/new)
(Report a vulnerability) rather than in a public issue. Reports on the most
recent release are the most actionable; include the retalk version and, if
relevant, how the relay was deployed.
