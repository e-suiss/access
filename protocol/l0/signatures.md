# L0 Signature Verification and Key Scope

This part defines how a verifier checks signatures on authority artifacts and how it decides that a signing key may sign for a domain. It covers verification only. A verifier holds no secrets: it verifies with public keys, and shared-secret MACs never authenticate an authority artifact.

An authority artifact is valid only if it is signed by an operational key that a binding key of the artifact's domain has scoped to that domain ([§5](#5-operational-key-scope)), or by such a binding key itself. An object signed with any other key, in any container, is not an authority artifact.

## 1. Algorithms

<a id="L0-SIG-1"></a>**L0-SIG-1. Identifiers.**

| Algorithm | COSE | JOSE `alg` | In L0 verification |
|---|---|---|---|
| Ed25519 | -19 | `Ed25519` | Yes |
| ESP256 (P-256 with SHA-256) | -9 | (JOSE `ES256` is already fully specified) | Yes |
| ES256 | -7 | `ES256` | Yes, when in the allowlist |
| EdDSA | -8 | `EdDSA` | Never in JWS; in COSE only for WebAuthn assertions with an Ed25519 key |
| ML-DSA-44 / -65 / -87 | -48 / -49 / -50 | `ML-DSA-44` / `-65` / `-87` | Off unless enabled by a profile |
| SHA-256 | -16 | — | Digest identifier ([L0-ENC-20](encoding.md#L0-ENC-20)) |

Artifacts produced by a domain use the fully specified identifiers: Ed25519 (-19) or ESP256 (-9) in COSE, `Ed25519` or `ES256` in JOSE. `none` is never supported. HMAC algorithms never sign an authority artifact. RSA is not part of L0 verification.

<a id="L0-SIG-2"></a>**L0-SIG-2. Allowlist.** The set of accepted algorithms comes only from the domain's Domain Metadata (`algorithms`) and the verifier's profile. The `alg` in an artifact's header only selects a value from that set. A header value outside the set is rejected, and a header never widens the set.

<a id="L0-SIG-3"></a>**L0-SIG-3. Ed25519 strict verification.** A verifier MUST verify Ed25519 signatures as follows, and MUST make these checks itself before calling any library:

1. The signature is exactly 64 bytes: `R` (32 bytes) ‖ `S` (32 bytes).
2. The public key `A` and `R` decode as points by [RFC 8032 §5.1.3](https://www.rfc-editor.org/rfc/rfc8032#section-5.1.3); a non-canonical encoding (y ≥ p, or x = 0 with the sign bit set) is rejected.
3. `S`, read as a little-endian integer, is less than `L`, the order of the base point.
4. Neither `A` nor `R` has small order: `[8]A` and `[8]R` are not the identity.
5. With `k = SHA-512(R ‖ A ‖ M) mod L`, the cofactorless equation `[S]B = R + [k]A` holds exactly. The cofactored form `[8][S]B = [8]R + [8][k]A` is not accepted.

Batch verification is not used.

Vectors: [`core/1/ed25519-strict.json`](../../conformance/vectors/core/1/ed25519-strict.json), operation `verify.ed25519`, cases `speccheck-0` to `speccheck-11`. Each case gives a public key, a message, a signature and the expected `result`. The `reason` label is informative.

<a id="L0-SIG-4"></a>**L0-SIG-4. P-256 public keys.** A P-256 public key is the 65-byte uncompressed SEC 1 point `0x04 ‖ x ‖ y`. It MUST be on the curve and in canonical form; any other key is rejected.

<a id="L0-SIG-5"></a>**L0-SIG-5. ECDSA signatures.** An ECDSA P-256 signature is exactly 64 bytes, `r ‖ s`, each a 32-byte big-endian integer. DER encoding and any other length are rejected. The verifier MUST check `0 < r < n` and `0 < s < n` before verification.

<a id="L0-SIG-6"></a>**L0-SIG-6. Low S.** Artifacts produced by a domain are signed with low-S ECDSA (`s ≤ n/2`). When verifying such an artifact, a signature with `s > n/2` is rejected. External ECDSA signatures (WebAuthn assertions, external issuers, client JWTs) MAY have high S and are accepted.

<a id="L0-SIG-7"></a>**L0-SIG-7. Key type matches algorithm.** The key MUST match the algorithm: Ed25519 (-19, and -8 where allowed) with an Ed25519 key; ESP256 (-9) and ES256 (-7) with a P-256 key; each ML-DSA identifier with an ML-DSA key of the same parameter set.

## 2. COSE_Sign1

<a id="L0-SIG-10"></a>**L0-SIG-10. Structure.** An authority artifact in COSE is a `COSE_Sign1` ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052)) with tag 18 as its outermost item. An untagged structure is rejected (reason `cbor`). `COSE_Sign` is not used. The whole structure, and the protected header bytes, MUST be deterministic CBOR ([L0-ENC-1](encoding.md#L0-ENC-1)).

<a id="L0-SIG-11"></a>**L0-SIG-11. Protected header.** The protected header is a map with integer labels drawn only from `1` (alg), `3` (content type) and `4` (kid), and all three MUST be present. Content type is a text string and `kid` a 32-byte string. A protected header that does not decode as a map, has any other label, lacks a label, or has a value of the wrong type is rejected (reason `header`). Two exceptions have their own reasons: `crit` ([L0-SIG-13](#L0-SIG-13)), and an `alg` that is not an integer or is not a recognised identifier (reason `algorithm`).

<a id="L0-SIG-12"></a>**L0-SIG-12. Unprotected header.** The unprotected header MUST be an empty map (reason `unprotected`).

<a id="L0-SIG-13"></a>**L0-SIG-13. Crit.** A protected header that contains `crit` (label 2) is always rejected (reason `crit`), whatever its value. The profile has no critical extensions.

<a id="L0-SIG-14"></a>**L0-SIG-14. Key identifier.** `kid` is the raw 32-byte RFC 7638 SHA-256 thumbprint of the signing key ([L0-SIG-66](#L0-SIG-66)). It is only an exact lookup key into the verifier's key set. An unknown `kid` is rejected (reason `unknown-kid`).

<a id="L0-SIG-15"></a>**L0-SIG-15. Algorithm.** `alg` MUST be in the allowlist ([L0-SIG-2](#L0-SIG-2)) (reason `algorithm`). The key found by `kid` MUST match `alg` ([L0-SIG-7](#L0-SIG-7)) (reason `key-type`).

<a id="L0-SIG-16"></a>**L0-SIG-16. Content type.** The content type MUST equal the content type expected for the artifact being verified, for example `application/access-receipt+cbor` (reason `content-type`). Content type, not a context string, separates artifact kinds.

<a id="L0-SIG-17"></a>**L0-SIG-17. Payload and signature input.** The payload is embedded; a detached payload is not used. `external_aad` is empty. The signed bytes are `dCBOR(["Signature1", protected, h'', payload])`, where `protected` is the protected header byte string as received. Ed25519 follows [L0-SIG-3](#L0-SIG-3); P-256 follows [L0-SIG-4](#L0-SIG-4) to [L0-SIG-6](#L0-SIG-6) (reasons `signature`, `high-s`).

<a id="L0-SIG-18"></a>**L0-SIG-18. Hybrid signatures.** A hybrid classical and post-quantum signature is two separate `COSE_Sign1` structures. The ML-DSA context string is empty.

<a id="L0-SIG-19"></a>**L0-SIG-19. WebAuthn.** In a WebAuthn assertion, COSE algorithm -8 is accepted only when the COSE key's `crv` is Ed25519.

<a id="L0-SIG-20"></a>**L0-SIG-20. Reason codes.** The COSE vectors use these reason codes:

| Reason | Check |
|---|---|
| `cbor` | Not tagged 18, not deterministic CBOR, or not a valid CBOR item |
| `shape` | Not a four-element array of protected bytes, unprotected map, payload bytes and signature bytes |
| `header` | Protected header is not a decodable map, has an unknown label, lacks a required one, or has a value of the wrong type |
| `crit` | Protected header contains `crit` |
| `unprotected` | Unprotected header not empty |
| `algorithm` | `alg` not an integer, not recognised, not in the allowlist, or disabled; or (excerpts only) not equal to the binding key's `alg` |
| `unknown-kid` | No key with this `kid` |
| `key-type` | Key does not match `alg` |
| `content-type` | Content type not the expected one |
| `high-s` | ECDSA high S on a domain-produced artifact |
| `signature` | Signature does not verify |

Vectors: [`core/1/cose.json`](../../conformance/vectors/core/1/cose.json), operation `verify.cose_sign1`. The file gives the expected content type, the allowlist (`[-19, -9]`) and a key set mapping `kid` to `public-key`. Valid cases (`valid-ed25519`, `valid-esp256`) give the expected `kid` and payload; the others give the expected reason. `two-faults-unprotected-and-unknown-label` and `two-faults-content-type-and-unknown-kid` each break two checks and test the order of [L0-SIG-21](#L0-SIG-21).

<a id="L0-SIG-21"></a>**L0-SIG-21. Several failures.** A structure that fails any check is rejected, and the first failing step decides the reason. For COSE_Sign1 the steps run in this order:

1. `cbor`
2. `shape`
3. `unprotected`
4. protected header, in this order: `crit` (`crit`), `alg` not an integer or not recognised (`algorithm`), unknown label (`header`), missing label (`header`); a header that is not a decodable map gives `header`
5. `algorithm` (allowlist)
6. `content-type`
7. `unknown-kid`
8. binding key `alg` match (`algorithm`; key excerpts only, [L0-SIG-63a](#L0-SIG-63a))
9. `key-type`
10. `signature`; the high-S check is part of this step (`high-s`)

Within the `cbor` step, the decoder reads the bytes in order and reports the first error it meets.

<a id="L0-SIG-21a"></a>**L0-SIG-21a. JWS rejection order.** The whole protected header is collected before any member is checked, so the order of members never changes the result. The first failing step decides the reason. The steps run in this order:

| # | Step | Result in the vectors |
|---|---|---|
| 1 | Format: size limits ([L0-ENC-15a](encoding.md#L0-ENC-15a)) and exactly three parts | `not a compact JWS` |
| 2 | Base64url of the header | `bad base64url` |
| 3 | Header JSON and its members: duplicate, unknown or non-text member | `header: duplicate member`, `header not in profile` |
| 4 | `alg` value | `algorithm not allowed` |
| 5 | `kid` decodes to 32 bytes, and `typ` is present | `header not in profile` |
| 6 | Base64url of the payload and the signature | `bad base64url` |
| 7 | `kid` present | `header not in profile` |
| 8 | `alg` in the allowlist | `algorithm not allowed` |
| 9 | `typ` equals the expected type | `unexpected typ` |
| 10 | `kid` known | `unknown kid` |
| 11 | Key type matches `alg` | `key type does not match algorithm` |
| 12 | Signature, including the length, scalar range and high-S checks | `signature: …` |

## 3. JWS compact

<a id="L0-SIG-30"></a>**L0-SIG-30. Serialization.** Only the JWS compact serialization ([RFC 7515](https://www.rfc-editor.org/rfc/rfc7515)) with exactly three parts is accepted. The JSON serialization, multiple signatures, five-part (JWE) tokens and nested JWTs are rejected.

<a id="L0-SIG-31"></a>**L0-SIG-31. Encoding.** Each part is strict base64url ([L0-ENC-16](encoding.md#L0-ENC-16)). The header and payload are parsed with the strict JSON profile ([L0-ENC-15](encoding.md#L0-ENC-15)); a duplicate member is rejected. The header MUST be a JSON object.

<a id="L0-SIG-32"></a>**L0-SIG-32. Required members.** The header MUST contain `alg`, `kid` and `typ`, each a string.

<a id="L0-SIG-33"></a>**L0-SIG-33. Closed header.** The header holds only `alg`, `kid` and `typ`. Any other member is rejected, including `jwk`, `jku`, `x5u`, `x5c`, `crit`, `b64` and `cty`. The verifier never fetches a key and never trusts a key or certificate carried in the token.

<a id="L0-SIG-34"></a>**L0-SIG-34. Algorithm.** `alg` MUST be in the allowlist. `none` in any letter case, `HS*` and `EdDSA` are always rejected. The key MUST match `alg`.

<a id="L0-SIG-35"></a>**L0-SIG-35. Key identifier.** The JOSE `kid` is the base64url text of the 32-byte key thumbprint. A `kid` that is not the base64url encoding of 32 bytes is rejected. An unknown `kid` is rejected.

<a id="L0-SIG-36"></a>**L0-SIG-36. Type.** `typ` MUST equal the type expected for the artifact, for example `access-receipt+jwt`. Each artifact kind has its own `typ`, so one kind cannot be presented as another.

<a id="L0-SIG-37"></a>**L0-SIG-37. Signature.** The signing input is the ASCII bytes `header ‖ "." ‖ payload`, exactly as received. Ed25519 follows [L0-SIG-3](#L0-SIG-3). `ES256` follows [L0-SIG-4](#L0-SIG-4) to [L0-SIG-6](#L0-SIG-6); high S is rejected on a domain-produced artifact.

<a id="L0-SIG-40"></a>**L0-SIG-40. Reason codes.** The JWS vectors expect these results:

| Expected | Cases |
|---|---|
| `accept` | `valid-ed25519`, `valid-es256` |
| `reject: algorithm not allowed` | `alg-none`, `alg-none-upper`, `alg-hs256`, `alg-eddsa` |
| `reject: key type does not match algorithm` | `key-type-mismatch` |
| `reject: not a compact JWS` | `five-parts` |
| `reject: header not in profile` | `embedded-jwk`, `jku`, `x5u`, `x5c`, `kid-path`, `kid-sql`, `crit`, `b64-false`, `cty-jwt`, `typ-missing`, `alg-not-string`, `header-not-object` |
| `reject: unknown kid` | `kid-unknown` |
| `reject: unexpected typ` | `typ-other` |
| `reject: header: duplicate member` | `duplicate-alg` |
| `reject: bad base64url` | `padded-signature` |
| `reject: signature: invalid signature` | `signature-bit-flip` |
| `reject: signature: ECDSA scalar out of range` | `psychic-signature` |
| `reject: signature: wrong length` | `der-signature` |

Vectors: [`core/1/jose-attack-classes.json`](../../conformance/vectors/core/1/jose-attack-classes.json), operation `verify.jws_compact`. The file gives the expected `typ` and a key set mapping base64url `kid` to the base64url public key. Each case names the attack-class row it covers.

<a id="L0-SIG-41"></a>**L0-SIG-41. Claims.** A JWT-carried authority artifact MUST contain `iss`, `aud` and `exp`. If `nbf` or `iat` is present it is checked. Current vectors do not exercise this rule.

<a id="L0-SIG-41a"></a>**L0-SIG-41a. JWT times.** JWT NumericDate values are in seconds. They are compared in milliseconds: the verifier multiplies the value by 1000, with checked arithmetic, and compares the result with `now` and the full `skew_ms` of the artifact class ([L0-VAL-14](validity.md#L0-VAL-14)). So `exp` is accepted while `now ≤ exp × 1000 + skew_ms`.

<a id="L0-SIG-42"></a>**L0-SIG-42. Attack classes.** Each of these attack classes MUST be rejected: `alg: none`; algorithm confusion (a public key used as an HMAC secret); a header `alg` choosing the accepted set; key type and algorithm mismatch; an embedded `jwk`; `jku` or `x5u` key URLs; an unanchored `x5c` chain; `kid` injection; an unknown `crit` extension; `b64: false`; an off-curve or non-canonical public key; ECDSA `r` or `s` equal to 0 or not less than `n`; DER or wrong-length ECDSA signatures; non-canonical or small-order Ed25519 values; JWE and nested JWT confusion; token type confusion; missing `iss`, `aud` or time claims; parser differentials (duplicate members, non-canonical base64url, invalid UTF-8).

## 4. SD-JWT

<a id="L0-SIG-50"></a>**L0-SIG-50. Profile.** SD-JWT artifacts follow [RFC 9901](https://www.rfc-editor.org/rfc/rfc9901) with these restrictions:

- the issuer-signed JWT follows [§3](#3-jws-compact);
- `_sd_alg`, if present, MUST be `sha-256`; if it is absent the RFC 9901 default `sha-256` applies and the SD-JWT is accepted. SD-JWTs produced by a domain always write it;
- disclosures are strict base64url and strict JSON;
- decoy digests MAY be present and MUST be accepted;
- an artifact bound to a holder MUST carry a Key Binding JWT, verified by RFC 9901 and [§3](#3-jws-compact);
- each artifact kind has its own `typ`.

Third-party vectors: [`vectors/external/rfc9901-disclosures.json`](../../conformance/vectors/external/rfc9901-disclosures.json). No core vector file exists yet.

## 5. Operational key scope

A domain has one or more binding keys. Binding keys sign the Domain Metadata and sign short-lived key excerpts. An excerpt declares one operational key, the domain it may sign for, its window and its usages. Artifacts carry the excerpt, so a verifier can build the chain without fetching current metadata.

`operational_key(metadata, domain, excerpt, usage, iat)` returns the operational key, or a rejection that names the failed step. Inputs:

| Input | Meaning |
|---|---|
| `metadata` | The `domain-metadata` payload |
| `domain` | The artifact's DomainID |
| `excerpt` | A `COSE_Sign1` whose payload is a `key-excerpt` |
| `usage` | The usage the artifact needs |
| `iat` | The artifact's signing time |

<a id="L0-SIG-60"></a>**L0-SIG-60. Metadata fields.** The verifier reads these authority fields of Domain Metadata: `domain`, `genesis`, `issued_at`, `binding` (each binding key's `kid`, `alg`, `key`, `scope` and optional `superseded`), `algorithms` (the single allowlist), `operational_window_max_ms` (at most 24 hours), `operational_keys`, `min_versions`, and optional `caps` and `hybrid`. `discovery` is opaque bytes and has no authority meaning.

<a id="L0-SIG-61"></a>**L0-SIG-61. Signers.** Only a binding key signs Domain Metadata and key excerpts. The excerpt's content type is `application/access-key-excerpt+cbor`; Domain Metadata uses `application/access-domain-metadata+cbor`.

<a id="L0-SIG-62"></a>**L0-SIG-62. Freshness is input.** The freshness of the Domain Metadata is established outside this operation and given as a prepared fact. The metadata's own `issued_at` alone is never proof of freshness.

The checks run in this order. Each failure is a local DENY that names its step.

<a id="L0-SIG-62a"></a>**L0-SIG-62a. Binding key identifiers.** Every binding key's `kid` MUST be the thumbprint of its own key ([L0-SIG-67](#L0-SIG-67)). Domain Metadata in which a binding key's `kid` does not match is not decoded, and the operation fails.

<a id="L0-SIG-63"></a>**L0-SIG-63. Step 1: excerpt signature.** The excerpt is verified as a `COSE_Sign1` ([§2](#2-cose_sign1)) with expected content type `application/access-key-excerpt+cbor`, the metadata `algorithms` as the allowlist, and the metadata binding keys as the key set. Reasons: `unknown-binding` (no binding key has the `kid`), `content-type`, `signature`, or the COSE reason.

Vectors: `binding-unknown`, `excerpt-content-type`, `binding-wrong-signer`.

<a id="L0-SIG-63a"></a>**L0-SIG-63a. Binding key algorithm.** As part of step 1, the `alg` in the excerpt's protected header MUST equal the binding key's own `alg` (reason `algorithm`). The allowlist alone is not enough. This check runs after the `kid` lookup and before the key-type check ([L0-SIG-21](#L0-SIG-21), step 8).

Vector: `binding-alg-mismatch`.

<a id="L0-SIG-64"></a>**L0-SIG-64. Step 2: not superseded.** The binding key MUST NOT carry `superseded` (reason `superseded`). Acceptance of artifacts signed by a superseded binding key with an inclusion proof is defined in a later version.

Vector: `binding-superseded`.

<a id="L0-SIG-65"></a>**L0-SIG-65. Step 3: binding scope.** The binding key's scope MUST include the artifact's domain (reason `outside-binding-scope`). Scope `"domain"` (the default) covers only the metadata's own `domain`. Scope `{provider: [DomainID…]}` covers exactly the listed domains. A key accepted outside its scope is the cross-tenant key confusion class known from the Storm-0558 incident.

Vectors: `valid-provider-scope`, `storm-0558-other-domain`, `provider-scope-out`.

<a id="L0-SIG-66"></a>**L0-SIG-66. Step 4: excerpt domain.** The excerpt's `domain` MUST equal the artifact's domain (reason `domain-mismatch`). The DomainID match is must-understand.

Vector: `excerpt-domain-mismatch`.

**Thumbprint.** A key's `kid` is the [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) SHA-256 thumbprint of its JWK, computed over the required members in lexicographic order with no whitespace:

| Key | JWK members |
|---|---|
| `ed25519` | `{"crv":"Ed25519","kty":"OKP","x":<base64url key>}` |
| `p256` | `{"crv":"P-256","kty":"EC","x":<base64url x>,"y":<base64url y>}` |
| `ml_dsa` | `{"alg":<ML-DSA-44, -65 or -87>,"kty":"AKP","pub":<base64url key>}`, as in RFC 9964 |

<a id="L0-SIG-67"></a>**L0-SIG-67. Step 5: thumbprint.** The verifier recomputes the thumbprint of the excerpt's key, which MUST equal the excerpt's `kid` (reason `thumbprint`).

Vector: `kid-not-thumbprint`.

<a id="L0-SIG-68"></a>**L0-SIG-68. Step 6: algorithm.** The excerpt key's `alg` MUST be in the metadata `algorithms` and MUST match the key type ([L0-SIG-7](#L0-SIG-7)) (reason `algorithm`).

Vectors: `alg-not-allowed`, `alg-key-type-mismatch`, `alg-es256-on-ed25519-key`.

<a id="L0-SIG-69"></a>**L0-SIG-69. Step 7: usage.** The requested usage MUST be in the excerpt key's `usage` (reason `usage`). The usage set is closed: `receipt`, `pap`, `token`, `checkpoint`, `set`, `status-list`.

Vector: `usage-not-declared`.

<a id="L0-SIG-70"></a>**L0-SIG-70. Step 8a: window shape.** `valid_from ≤ valid_until`, and `valid_until − valid_from ≤ operational_window_max_ms` (reason `window`).

Vectors: `window-inverted`, `window-too-long`, `window-over-24h`.

<a id="L0-SIG-71"></a>**L0-SIG-71. Step 8b: signing time.** `valid_from ≤ iat ≤ valid_until`; both ends are included (reason `window`). The window bounds the signing time; how long the artifact may then be relied on is set by [L0-VAL-10](validity.md#L0-VAL-10).

Vectors: `valid-window-start`, `valid-window-end`, `iat-before-window`, `iat-after-window`.

<a id="L0-SIG-72"></a>**L0-SIG-72. Checked arithmetic.** All arithmetic in this section is checked ([L0-ENC-7](encoding.md#L0-ENC-7)); an overflow is a rejection.

Vectors for this section: [`core/1/key-scope.json`](../../conformance/vectors/core/1/key-scope.json), operation `key_scope.operational_key`. Each case gives the metadata payload, the artifact domain, the excerpt, the usage and `iat`, and either the expected operational key or the expected reason. Valid cases: `valid-ed25519`, `valid-esp256`, `valid-window-start`, `valid-window-end`, `valid-provider-scope`.

<a id="L0-SIG-75"></a>**L0-SIG-75. Hybrid policy.** Whether a verifier requires the classical signature, the post-quantum signature or both is read from the Domain Metadata `hybrid` field, never from the artifact.

> **OPEN (O-23):** What do the values `classic`, `both` and `pq` require of a verifier?

<a id="L0-SIG-76"></a>**L0-SIG-76. Identity-plane keys.** Keys that sign identity tokens (OpenID Connect ID tokens, for example) are not operational keys and never sign an authority artifact. Matching their issuer, realm and `kid` is outside L0.
