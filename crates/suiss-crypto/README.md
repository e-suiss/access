# esuiss-crypto

Shared cryptography for Suiss products: deterministic CBOR, digests and Merkle proofs, signature and `COSE_Sign1` verification, and C2SP signed notes and checkpoints. Access, Work and One use the same code, so a record or proof that one of them accepts is accepted by the others.

- **`no_std` verification.** With `default-features = false, features = ["verify"]` the crate needs only `alloc`. It has no I/O, no async code and no FFI, and it builds for `wasm32-unknown-unknown` and `thumbv7em-none-eabihf`.
- **No panics on input.** Arithmetic is checked and every failure is a typed error. Error enums are `#[non_exhaustive]` and each value has a stable `code()` for problem details (RFC 9457).
- **Fail-closed.** Anything outside the profile is rejected: non-canonical CBOR, tags you did not allow, non-canonical base64, keys of small order, unknown algorithms.
- **Limits only narrow.** `Limits` and `TagAllowlist` start from fixed ceilings. A caller can make them stricter and never looser.

## Use

```toml
[dependencies]
esuiss-crypto = { version = "=0.2.0", default-features = false, features = ["verify"] }
```

The library is imported as `suiss_crypto`.

| Module | Contents |
|---|---|
| `dcbor` | RFC 8949 §4.2.1 deterministic CBOR: canonical encoder, strict decoder with `Limits` and `TagAllowlist`, prefix decoding |
| `digest` | Algorithm-tagged `Digest`, the `0x00` leaf, `0x01` node, `0x02` field and `0x03` body prefixes, context-labelled digests, RFC 9162 roots, inclusion and consistency proofs |
| `sig` | Ed25519 with strict pre-checks (canonical points, reduced `S`, no small order) and ECDSA P-256; high-S is refused for your own signatures and accepted from external signers |
| `cose` | `COSE_Sign1` parsing that keeps the received bytes, attached and detached payloads, algorithms allowed by your policy only (Ed25519, ESP256, ES256; ML-DSA modelled and off) |
| `note` | C2SP `signed-note`, `tlog-checkpoint` and Ed25519 `tlog-cosignature/v1`: parsing, verifier keys, checkpoint construction and verification |

### Server features

These need `std` and aws-lc-rs and are never part of `verify`.

| Feature | Module | Contents |
|---|---|---|
| `aws-lc` | `secret`, `dit`, `aws` | `Secret<T>`: never printed, zeroized on drop, compared in constant time; the ARM64 data-independent-timing guard; an aws-lc-rs verification backend |
| `aead` | `envelope` | Envelope encryption: a fresh DEK per body under AES-256-GCM, long-lived DEKs under AES-256-GCM-SIV with a message limit, DEKs wrapped by a KEK behind a port (AES-256 Key Wrap), rewrapping for KEK rotation, a bounded DEK cache. Deleting a DEK is crypto-shredding |
| `signer` | `signer` | The `Signer` port, a software signer (Ed25519, ECDSA P-256 with low S), `COSE_Sign1` signing, note signatures and checkpoint cosignatures |
| `pkcs11` | `pkcs11` | A PKCS#11 key store: signing keys and KEKs generated and kept inside the token, used through `Signer` and the envelope `Kek` port. Tested against SoftHSM |

```rust
use suiss_crypto::note::{verify_checkpoint, Verifier};
use suiss_crypto::sig::PureBackend;

let log = Verifier::parse("example.com/log+9be5d3c6+AYqI4910CfGV/VLbLTy6XXLKZwm/HZQSG/N0iAG0D29c")?;
let (checkpoint, signatures) = verify_checkpoint(&PureBackend, &note, "example.com/log", &log, &witnesses)?;
```

## Test vectors

The package ships its golden vectors under `vectors/`, with the SHA-256 of every file in `vectors/MANIFEST`. Read them from the exact version you depend on rather than copying them. They are byte-identical to the vectors in the Access repository, and the same files are checked by an independent Python implementation.

| File | Contents |
|---|---|
| `core/1/cbor-decode.json` | Canonical and rejected CBOR |
| `core/1/merkle.json` | Tree roots, inclusion and consistency proofs |
| `core/1/ed25519-strict.json` | Ed25519 edge cases |
| `core/1/cose.json` | `COSE_Sign1` profile cases |
| `exchange/1/checkpoint.json` | Signed and cosigned checkpoints and their rejections |
| `external/` | Wycheproof, NIST ACVP and ed25519-speccheck sets; sources in `external/SOURCES` |

## Versions

Until 1.0, a breaking change raises the minor version. Pin an exact version (`=0.y.z`). Changes are listed in [CHANGELOG.md](CHANGELOG.md).

## License

[Apache License 2.0](../../LICENSE).
