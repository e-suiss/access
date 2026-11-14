# Changelog

## 0.7.3

Released with `esuiss-access-kernel` 0.7.3 (Kernel 0.7.0 semantics, unchanged). No API change from 0.7.0; 0.7.0, 0.7.1 and 0.7.2 were never published.

## 0.7.2

Never published: the v0.7.2 release run stopped at a test that SoftHSM 2.6.1 failed under concurrency (OP-159 m.33). No API change from 0.7.0.

## 0.7.1

Never published: the v0.7.1 release run stopped at its test job's time limit before anything was published (OP-159 m.30). No API change from 0.7.0.

## 0.7.0

Never published: the v0.7.0 release run stopped at its FIPS image build before anything was published (OP-159 m.28). Prepared with `esuiss-access-kernel` 0.7.0 (Kernel 0.7.0 semantics: ML-DSA-44/65/87 verification through the `Backend` port, the hybrid signature policy and the `hybrid-artefact` carrier, PQ anchors and RA-7 acceptance of retired-algorithm artefacts, the superseded cause and inclusion evidence over a record's committed `artifacts`, root-term witness and replica sets, holding terms on meta-actions, the new-payee floor and `audit_export` as a CT1 read). Public structs and enums gained fields and variants, so the minor version moves. 0.6.0 was never published.

### Added

- `Backend::ml_dsa` and `Backend::supports`; `AwsLcBackend` verifies ML-DSA-44/65/87, `PureBackend` refuses them.
- `MlDsaSigner`: an ML-DSA key held only as a 32-byte seed (owned or in a `SecretArena` page) and expanded per signature; `random_seed`.
- PKCS#11: `ml_dsa_mechanisms`, `mechanism_names`, `generate_ml_dsa` and ML-DSA `HsmSigner`; a token without the mechanisms answers `HsmError::PqUnavailable` and nothing falls back to software.
- Feature `fips`: the validated AWS-LC module with its start-up check; the build declares its FIPS module.
- `dit`: every constant-time comparison runs under a DIT guard on arm64; a signer refuses an Apple CPU under Linux.

## 0.6.0

Never published: the v0.6.0 release run stopped at its test job before anything was published (OP-159 m.24). Prepared with `esuiss-access-kernel` 0.6.0 (Kernel 0.6.0 semantics: catalog 8, `domain_handover` and `domain_recover` with the recovery entry and rollback guard, the pre-recovery nonce closure, superseded-at bindings, version activation and algorithm retirement, self-anchor narrowing, conditional `anchor_transfer`, DistinctSurface surface paths, and the witness head the rollback guard reads). The Kernel's public structs gained fields, so the minor version moves. 0.5.0 was never published.

- `pkcs11::KeyStore::finalize`, `finalizer` and `open_handles`: an orderly shutdown that closes every session before `C_Finalize`; modules stay loaded until exit.
- `pkcs11::HsmKek::rewrap`: move a wrapped DEK to another KEK inside the token.
- `pkcs11::KeyStore::{install_clone_key, generate_cloneable, export_clone, import_clone}`: a signing key cloned to a DR token, wrapped only under a trusted clone key.
- `signer::{KeyPages, Pager, PagedSigner}`: a signer whose key document lives only in protected memory.

## 0.5.0

Never published (OP-158 m.21 (d)). Prepared with `esuiss-access-kernel` 0.5.0 (Kernel 0.4.1 semantics: catalog 7 types, `policy.set` structural polarity, the closed `derived.*` values, policy defaults, compatibility mappings, `DistinctSurface` and the actor Party exclusion, and a Mandate decided by its window, while-conditions, budget and pin). The Kernel's public structs gained fields, so the minor version moves.

### Added

- `ecdh_es` (feature `aead`): JWE `ECDH-ES` direct key agreement on P-256 with `A128GCM`/`A256GCM` and the RFC 7518 Concat KDF, and recipient keys derived from a secret with HKDF-SHA-256; for OID4VP `direct_post.jwt` responses.

## 0.4.0

No changes; released with `esuiss-access-kernel` 0.4.0 (intent plan reference, parameter provenance and Mandate origin sets; `disclose`/`declassify` core classes; runtime and effect attestation, executor control and workload binding Claim classes; Approval Act surface class and evidence; action reversibility). The Kernel's public structs gained fields, so the minor version moves.

## 0.3.2

No changes; released with `esuiss-access-kernel` 0.3.2 (causal-bound allowances in the Genesis policy; an organization Party has no Instance, C6).

### Fixed

- **Breaking.** `cose::to_be_signed` returns `Result` and refuses a part above the profile limits with the new `CoseError::Encode`; it used to return an empty `Sig_structure`, so a signature over the empty byte string verified any detached payload above 64 KiB. `verify_sign1_with` and `sign_sign1` refuse such a payload (CR-10).

## 0.3.1

No changes; released with `esuiss-access-kernel` 0.3.1 (explanation scopes and the contribute intent in the Kernel).

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
