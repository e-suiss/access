# access-parser-worker

Parses untrusted XML and DER for the Access protocol gateways, in disposable processes that hold
no key, open no file and make no network call. A crash, a panic or a limit kills one worker and
nothing else.

```
access-parser-worker          # the supervisor
access-parser-worker work     # one worker, started by the supervisor
```

## Supervisor

The supervisor binds its Unix socket, locks itself down (Landlock, seccomp, no network; it may
only start its own workers and kill them), starts the pool and answers the gateways whose user id
it was given. Configuration comes from the environment:

| Variable | Meaning |
|---|---|
| `ACCESS_PARSER_SOCKET` | Socket path (required) |
| `ACCESS_PARSER_CALLERS` | Comma-separated user ids of the gateways (required) |
| `ACCESS_PARSER_WORKERS` | Workers kept running, 1 to 64 (default 4) |
| `ACCESS_PARSER_LOADER` | Directories the workers' dynamic loader reads (default `/lib`, `/lib64`, `/usr/lib`, `/usr/lib64`, `/etc/ld.so.cache`) |
| `ACCESS_PARSER_RUN_AS` | `uid:gid` to switch to when started as root |

On any operating system other than Linux, and on a Linux host where the lockdown cannot be
applied, the supervisor and the workers refuse to start.

## Workers

Each worker sets `RLIMIT_AS` to 256 MiB, gives each request 2 s of CPU, enters the parser-worker
lockdown (no socket call, no file system) and reads one request at a time from its socket pair.
The supervisor allows 5 s of wall clock per request, checks that every byte of an answer comes
from the worker's own process (`SCM_CREDENTIALS`), and replaces a worker after 1000 requests or
after any answer that is not a clean `ok`.

## Limits

| Input | Limit |
|---|---|
| XML | UTF-8, no `DOCTYPE`, no processing instruction, only the five predefined entities and character references, one root, depth 64, 50 000 elements, 1 MB |
| Deflated XML (HTTP-Redirect) | Inflated within 1 MB and a ratio of 100 |
| DER | 8 KB, refused before it is read; definite shortest lengths, single-byte tags, depth 32 |

Each refusal is a stable code (`xml-doctype`, `der-too-large`, ...).

## SAML

| Operation | What it does |
|---|---|
| `saml.request` | Reads an `AuthnRequest` or `LogoutRequest` (alone, or in an ECP SOAP body), verifies its enveloped signature with the service provider's pinned certificates and returns the request's facts |
| `saml.redirect` | Verifies a detached HTTP-Redirect signature over the octets as received |

The message is read once, into one tree. Duplicate identifiers refuse the whole document. The one
`ds:Signature` must be a direct child of the request and its one `Reference` must name that
request's own `ID`; the facts are read from that same element, so the element whose signature
verified is the element that is read. Only the enveloped-signature and exclusive c14n transforms
are accepted, digests and signatures are SHA-2 (RSA or ECDSA), `KeyInfo` is never a trust anchor
and SHA-1 is refused. C14N and the signature check are this crate's own code over `quick-xml`,
the one parser.

## Wire

One request, one reply. Each is a deterministic CBOR header and a raw byte segment, both prefixed
with a big-endian `u32` length: `{op}` plus the document, and `{status, ...}` plus the result.

## License

[Apache License 2.0](../../LICENSE).
