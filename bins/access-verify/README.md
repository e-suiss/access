# access-verify

The Access Reference Verifier: a small command-line tool that checks Access artefacts offline. Anyone can run it without a Suiss service, account or key. It is a thin shell over the open Access Kernel, so it gives the same answer as every other conforming implementation.

- **Offline.** It reads files and arguments. It never opens a network connection.
- **No hidden clock.** It never reads the system time. Every moment that matters (`--now`, `--iat`) is an argument.
- **Deterministic.** The same inputs always print the same bytes.
- **Fail-closed.** Anything it cannot read or does not understand is rejected, never accepted.

## Install

```sh
cargo install --locked --path bins/access-verify
```

Or run it from a checkout:

```sh
cargo run --locked -p access-verify -- <command> [--option value]...
```

## Output

The first line is `accept` or `reject: <reason>`. An accepted result is followed by its outputs as `name: value` lines. Reasons are the stable names the conformance vectors use, for example `signature`, `unknown-kid`, `expired` or `outside-binding-scope`.

| Exit status | Meaning |
|---|---|
| `0` | accepted |
| `1` | rejected |
| `2` | usage or I/O error; nothing was verified |

## Inputs

- CBOR values (`key-set`, Domain Metadata, `COSE_Sign1`, validity contracts, records) are files holding the raw canonical bytes, in the shapes of [`kernel.cddl`](../../conformance/cddl/kernel.cddl).
- JWS tokens and SD-JWT presentations are text files. Surrounding whitespace is ignored.
- 32-byte hashes (Merkle roots, leaf hashes, a DomainID) are lowercase hex arguments. A proof path is a comma-separated list of hashes; an empty string is an empty path.
- Times are milliseconds since the Unix epoch.

## Commands

| Command | Verifies | Outputs |
|---|---|---|
| `metadata --signed F --trusted F` | Binding-signed Domain Metadata against the binding `key-set` you already trust | `metadata` (hex) |
| `key --metadata F [--trusted F] --domain H --excerpt F --usage U --iat T` | The operational key that may sign an artefact of domain `H` at time `T` for usage `U`, from Domain Metadata and the artefact's key excerpt. With `--trusted`, `--metadata` is signed and is verified first | `key` (hex) |
| `cose --sign1 F --content-type C --keys F` | A tagged `COSE_Sign1` against a `key-set` | `kid`, `payload` (hex) |
| `cose --sign1 F --content-type C --metadata F [--trusted F] --domain H --excerpt F --usage U --iat T` | A tagged `COSE_Sign1` against the operational key `key` resolves | `kid`, `payload` (hex) |
| `jws --token F --keys F --typ T --issuer I --audience A --now T --skew-ms N` | An Access-native compact JWS and its claims | `payload` (JSON) |
| `sd-jwt --presentation F --keys F --typ T --audience A --nonce N --now T --skew-ms N` | An Access-native SD-JWT presentation with key binding | `claims` (JSON) |
| `validity --contract F --now T --audience A --online true\|false --skew-ms N --iat T --horizon-cap-ms N [--understood a,b] [--last-refresh T]` | A validity contract at the moment of use | none |
| `inclusion --index I --size N --root H --path H,... (--leaf F \| --leaf-hash H)` | An RFC 9162 inclusion proof; `--leaf` is the leaf input, `--leaf-hash` its hash | none |
| `consistency --first M --second N --first-root H --second-root H --path H,...` | An RFC 9162 consistency proof | none |
| `record (--envelope F \| --disclosure F) [--size N --root H --path H,...]` | A record envelope or a selective disclosure, and with the proof options its inclusion at `pos` in the domain log | `leaf_hash`, `pos`, `domain` |

`--iat` for `key` and `cose` is the signing time the artefact itself states. `--domain` is the 32-byte SHA-256 value of the DomainID, without its digest tag.

## Example

```sh
$ access-verify metadata --signed metadata.cose --trusted bindings.cbor
accept
metadata: ab6463617073a1...

$ access-verify cose --sign1 receipt.cose --content-type application/access-receipt+cbor \
    --metadata metadata.cose --trusted bindings.cbor \
    --domain 0101...01 --excerpt excerpt.cose --usage receipt --iat 36000001
reject: outside-binding-scope
```

## Conformance

The tests run this binary over every case of the core track 1 vectors in [`conformance/vectors/core/1`](../../conformance/vectors/core/1) and compare the printed result with the expected one:

```sh
cargo nextest run -p access-verify
```

## License

[Apache License 2.0](../../LICENSE).
