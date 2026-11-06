# Changelog

## Unreleased

## 0.3.0

### Changed

- **Breaking.** `rotation::Key` and `rotation::Step::Generate` gain `founding`: the first key of a key set that has never been published signs as soon as it is published; every later key keeps the full `publish_lead` (CR-59, pending Adem's confirmation; SAI-46 unchanged for every key after the first).
- `rotation::usable` and `rotation::plan` honour the founding key.

### Added

- `SoftSigner::p256_from_parts`: an ECDSA P-256 key from a private JWK's `d`, `x` and `y`.
- `rotation::overdue`: how long the active key has stayed past its rotation time with no backup to rotate to, for a rotation delay alarm during a key-generation outage.
- `rotation::Step::name` and `Step::kid`, for audit events of key transitions.

## 0.2.6

No changes; released with `esuiss-access-kernel` and published from CI with trusted publishing.

## 0.2.5

No changes; released with `esuiss-retention`.

## 0.2.4

### Added

- `rotation`: the signing key state machine (pending, published, active, retiring, dropped), publish-before-use, the rotation schedule with jitter, and the `Policy::AUTHORITY` and `Policy::REALM` presets.
- `envelope::DekKek`: an HSM-unwrapped DEK used as a KEK under AES-256 Key Wrap (RFC 3394) for the DEKs below it; byte-identical to the PKCS#11 KEK for the same key.
- `pkcs11`: `KeyStore::destroy_kek`, which destroys a KEK inside the token and so crypto-shreds every key it wrapped.

### Fixed

- `note::Verifier::parse` accepts verifier keys whose name contains `+`.
- The `pkcs11` feature enables `aead`, so it builds on its own.

## 0.2.3

### Added

- `digest::sha256`: plain SHA-256, for example the RFC 8705 `x5t#S256` thumbprint of a certificate.
- `pkcs11`: HMAC-SHA-256 keys inside the token (`KeyStore::generate_mac`, `mac`, `import_mac`, `HsmMac`) and AES-256-GCM keys (`KeyStore::generate_aead`, `aead`, `HsmAead::seal`, `HsmAead::open` with a random 96-bit nonce and a 128-bit tag).
- `HsmError::Poisoned` for a shared session whose lock was poisoned.

## 0.2.2

No changes; released with `esuiss-sandbox`.

## 0.2.1

### Added

- `digest`: algorithm-tagged `Digest`, the leaf, node, field and body prefixes, `context_digest`, RFC 9162 `root`, `verify_inclusion` and `verify_consistency` with a bounded proof length.
- `sig`: Ed25519 with strict pre-checks and ECDSA P-256 verification behind a `Backend` trait, with the pure-Rust `PureBackend`.
- `cose`: `COSE_Sign1` parsing (`parse_sign1`) that keeps the received bytes, detached payloads (`verify_sign1_detached`), and `verify_sign1_with` for signatures from external signers, where high-S is accepted.
- `note`: C2SP `signed-note`, `tlog-checkpoint` and Ed25519 `tlog-cosignature/v1`.
- `dcbor`: `TagAllowlist`, `decode_with`, `decode_prefix` and `Value::Tag`.
- Stable `code()` on every error type.
- Golden vectors and `vectors/MANIFEST` in the package.
- Feature `pkcs11`: `KeyStore` on a PKCS#11 token, `HsmSigner` (Ed25519, P-256 keys generated inside the token) and `HsmKek` (AES Key Wrap inside the token, byte-identical to the in-process KEK).
- Server features `aws-lc`, `aead` and `signer`: `Secret`, the DIT guard, `AwsLcBackend`, envelope encryption, and the `Signer` port with `SoftSigner`, `sign_sign1`, `sign_note` and `cosign`.

### Changed

- Error enums are `#[non_exhaustive]`.

## 0.1.1

First release: deterministic CBOR with `Limits`.
