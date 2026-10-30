# Changelog

## 0.2.0

### Added

- `digest`: algorithm-tagged `Digest`, the leaf, node, field and body prefixes, `context_digest`, RFC 9162 `root`, `verify_inclusion` and `verify_consistency` with a bounded proof length.
- `sig`: Ed25519 with strict pre-checks and ECDSA P-256 verification behind a `Backend` trait, with the pure-Rust `PureBackend`.
- `cose`: `COSE_Sign1` parsing (`parse_sign1`) that keeps the received bytes, detached payloads (`verify_sign1_detached`), and `verify_sign1_with` for signatures from external signers, where high-S is accepted.
- `note`: C2SP `signed-note`, `tlog-checkpoint` and Ed25519 `tlog-cosignature/v1`.
- `dcbor`: `TagAllowlist`, `decode_with`, `decode_prefix` and `Value::Tag`.
- Stable `code()` on every error type.
- Golden vectors and `vectors/MANIFEST` in the package.

### Changed

- Error enums are `#[non_exhaustive]`.

## 0.1.1

First release: deterministic CBOR with `Limits`.
