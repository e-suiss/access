# L0 Encoding, Digests and Merkle Trees

This part defines the single byte encoding of every canonical value, the limits a decoder enforces, the strict JSON profile used for JOSE material, how digests are computed and separated by purpose, how log records commit to their fields, and the Merkle tree over records.

Every digest the protocol computes is computed over the encoding defined here. Two conformant implementations given the same value MUST produce the same bytes.

## 1. Deterministic CBOR

<a id="L0-ENC-1"></a>**L0-ENC-1. Core deterministic encoding.** A canonical value is encoded as CBOR ([RFC 8949](https://www.rfc-editor.org/rfc/rfc8949)) using the core deterministic encoding of RFC 8949 §4.2.1:

- every integer and every length uses the shortest form that can hold it;
- every array, map and string has a definite length;
- map keys are sorted by the bytewise lexicographic order of their encoded form;
- no map has two equal keys.

A decoder MUST reject input that breaks any of these rules. A decoder MAY check this by re-encoding the decoded value and comparing the bytes with the input; the two MUST be equal.

<a id="L0-ENC-2"></a>**L0-ENC-2. Allowed data items.** Canonical values use only unsigned and negative integers, byte strings, text strings, arrays, maps and the simple values `true` and `false`. Text strings MUST be valid UTF-8. A decoder MUST reject floating-point numbers, `null`, `undefined` and every other simple value.

<a id="L0-ENC-3"></a>**L0-ENC-3. Tags.** Canonical values carry no CBOR tags. The only tag that may appear is tag 18 as the outermost item of a `COSE_Sign1` structure ([L0-SIG-10](signatures.md#L0-SIG-10)). Bignums (tags 2 and 3) are not used. Times are untagged integers. A decoder MUST reject any other tag, including tag 18 anywhere inside a value.

<a id="L0-ENC-4"></a>**L0-ENC-4. Map keys.** Map keys in canonical values are short `snake_case` text strings, exactly as named in the CDDL. The only maps with integer keys are COSE header maps, which use the integer labels of [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052).

<a id="L0-ENC-5"></a>**L0-ENC-5. Absent and default fields.** An optional field that has no value is not written. A field whose value equals its default is not written, and a missing optional field means its default. There is no `null` placeholder. A required field is always written, even when its value is an empty array or an empty map. Together with [L0-ENC-6](#L0-ENC-6) this gives every value exactly one encoding.

Example: the minimal `canonical-authority` in `codec.json` writes `requirements: []` and `delegation: {}` because both fields are required, and omits `params`, `recipient`, `purpose`, `while` and `budget` because they are optional and unbounded.

<a id="L0-ENC-6"></a>**L0-ENC-6. Arrays that are sets.** An array that represents a set MUST be sorted by the bytewise order of the canonical encoding of each element, and MUST NOT contain two elements with the same encoding. A decoder MUST reject a set that is out of order or has a repeat.

Every array in the data model is a set, except these:

| Array | Kind | Order |
|---|---|---|
| `digest` (`[hash-alg, bytes]`) | tuple | positional |
| `time-window` (`[from, until]`) | tuple | positional |
| `ml_dsa` public key (`[alg, bytes]`) | tuple | positional |
| `resource-ref.path`, `structural-selector.prefix` | sequence | path order |
| `basis.hops` | sequence | hop 0 first, toward the root |
| `evaluation-input.bases` | sequence | as given by the caller |

So `resources`, `restrictions`, `blockers`, `proofs`, `budgets`, `capacities`, `enum` values, purpose lists, `while` and `budget` lists, requirement sets, `unmet`, `relied_on`, `usage`, `algorithms` and every other array are sets.

Because sets are sorted on the wire, two inputs that differ only in the order of a set's elements cannot be encoded differently. Vector note: in `cve-regressions.json`, `two-exclusions-reordered` has the same input bytes as `two-exclusions` for this reason.

<a id="L0-ENC-7"></a>**L0-ENC-7. Integer ranges.** Amounts and bounds (`amount`) are signed 64-bit integers. Counters, capacities, positions and TrustedTime values are unsigned 64-bit integers. A decoder MUST reject a value outside the range of its type. All arithmetic on these values is checked: an operation whose exact result does not fit its type MUST NOT wrap, saturate or be truncated. What a checked failure means depends on where it happens ([L0-EVAL-50](evaluation.md#L0-EVAL-50), [L0-VAL-20](validity.md#L0-VAL-20)).

<a id="L0-ENC-8"></a>**L0-ENC-8. No decimals.** There is no decimal or fractional number type. Every quantity is an integer counted in the smallest step of its unit. The action schema names the unit and its scale. Floating-point values never express an authority bound.

<a id="L0-ENC-9"></a>**L0-ENC-9. Unknown fields.** A map in new input that contains a key the CDDL does not define for that position, or a choice the CDDL does not define, MUST be rejected. Stored and external artifacts follow [L0-ALG-4](algebra.md#L0-ALG-4) instead.

<a id="L0-ENC-9a"></a>**L0-ENC-9a. Decoder reasons.** A deterministic CBOR decoder MUST consume the whole input as exactly one data item. It rejects with these reasons:

| Reason | Cause |
|---|---|
| `non-shortest` | An integer or a length not in its shortest form |
| `indefinite` | An indefinite-length string, array or map |
| `reserved` | A reserved additional-information value |
| `float` | A floating-point number of any width |
| `simple` | `null`, `undefined` or another simple value other than `true` and `false` |
| `tag` | Any tag |
| `utf8` | A text string that is not valid UTF-8 |
| `key-order` | Map keys out of order |
| `duplicate-key` | Two equal map keys |
| `depth` | Nesting deeper than allowed ([L0-ENC-10a](#L0-ENC-10a)) |
| `string-length` | A string longer than allowed ([L0-ENC-10b](#L0-ENC-10b)) |
| `items` | An array or map with too many elements |
| `truncated` | The input ends inside a data item, or is empty |
| `trailing-bytes` | Bytes remain after the data item |

The decoder reads the bytes in order and reports the first error it meets.

Vectors: [`core/1/cbor-decode.json`](../../conformance/vectors/core/1/cbor-decode.json), operation `dcbor.decode`. Each case gives input bytes and either `valid: true` or the expected reason. At this level the decoder checks only the generic rules; which keys and types a value may hold is checked against the CDDL afterwards, so integer map keys are allowed here.

Vectors for [L0-ENC-1](#L0-ENC-1) to [L0-ENC-9](#L0-ENC-9): [`core/1/codec.json`](../../conformance/vectors/core/1/codec.json), operation `codec.encode`. Each case is a canonical encoding. A conformant decoder accepts it, and re-encoding the decoded value gives the same bytes. Cases: `canonical_authority.full`, `canonical_authority.minimal`, `bound.range.negative`, `subject.public`, `digest`.

## 2. Structural limits

<a id="L0-ENC-10"></a>**L0-ENC-10. Limits.** A decoder enforces these ceilings:

| Limit | Ceiling |
|---|---|
| CBOR nesting depth | 16 |
| Elements in one array, or entries in one map | 256 |
| Length of one byte string or text string | 64 KB |
| JSON nesting depth | 32 |
| Hops in one basis | 16 |
| Conditions in one subject or resource selector | 32 |

The element limit applies to each array and each map on its own, not to the input as a whole.

<a id="L0-ENC-10a"></a>**L0-ENC-10a. Counting depth.** Only containers (arrays and maps) count toward nesting depth. The outermost container is level 1. Sixteen nested containers are accepted; seventeen are rejected. Scalars, and the tag of a `COSE_Sign1`, do not count.

Vectors: `cbor-decode.json`: `depth-16-containers`, `depth-16-with-scalar-leaf`, `depth-17-containers`.

<a id="L0-ENC-10b"></a>**L0-ENC-10b. Counting string length.** 64 KB is 65,536 bytes of encoded content. For a text string the UTF-8 bytes are counted.

Vectors: `cbor-decode.json`: `string-65536-bytes`, `string-65537-bytes`, `array-256-items`, `array-257-items`.

<a id="L0-ENC-11"></a>**L0-ENC-11. Lower limits only.** The ceilings in [L0-ENC-10](#L0-ENC-10) are fixed by the protocol. A caller MAY configure a lower limit for any of them. A caller MUST NOT configure a higher one.

<a id="L0-ENC-12"></a>**L0-ENC-12. Exceeding a limit.** Input that exceeds a limit is rejected. A rejection is not a decision ([L0-EVAL-60](evaluation.md#L0-EVAL-60)). A decoder MUST check depth before it descends into a nested item, and MUST check a length before it reads the item.

<a id="L0-ENC-13"></a>**L0-ENC-13. Selector conditions.** The conditions of a selector are the conjuncts of a `pred` subject selector and the entries of a structural resource selector's `where` map. A selector with more than 32 conditions is rejected.

## 3. Strict JSON and base64url

JSON appears in L0 only inside JOSE material: JWS protected headers, JWT payloads, SD-JWT payloads and disclosures. All other external JSON is outside L0.

<a id="L0-ENC-15"></a>**L0-ENC-15. Strict JSON profile.** A verifier parses L0 JSON with these rules:

- the text is I-JSON ([RFC 7493](https://www.rfc-editor.org/rfc/rfc7493));
- the bytes MUST be valid UTF-8;
- an object with two members of the same name MUST be rejected;
- nesting depth MUST NOT exceed 32;
- numbers MUST be integers, without a fraction or an exponent;
- the size of the input is bounded before parsing starts.

<a id="L0-ENC-15a"></a>**L0-ENC-15a. JOSE size limits.** These limits are applied before parsing:

| Item | Limit |
|---|---|
| JWS protected header | 2,048 bytes |
| JWS payload | 65,536 bytes |
| Compact JWS token | 98,304 bytes |
| Whole SD-JWT presentation | 262,144 bytes |
| Disclosures in one SD-JWT | 256 |

The values are policy defaults.

<a id="L0-ENC-16"></a>**L0-ENC-16. Strict base64url.** Base64url text uses the URL-safe alphabet of [RFC 4648 §5](https://www.rfc-editor.org/rfc/rfc4648#section-5) with no padding characters and no whitespace. The unused low bits of the last character MUST be zero. A verifier MUST reject text that breaks any of these rules.

<a id="L0-ENC-17"></a>**L0-ENC-17. JSON projections.** Where a canonical value is shown as JSON, the JSON is a one-to-one projection of the CBOR data model. Digests are always computed over the CBOR encoding, never over JSON. A JWS signature covers the JSON bytes exactly as received, and signed bytes are never re-encoded before verification.

## 4. Digests

<a id="L0-ENC-20"></a>**L0-ENC-20. Algorithm and form.** The only digest algorithm is SHA-256. A digest is written with its algorithm:

- in CBOR as `[-16, h'<32 bytes>']`, where -16 is the COSE identifier for SHA-256;
- in text as `sha-256:` followed by the base64url encoding of the 32 bytes ([L0-ENC-16](#L0-ENC-16)).

A decoder MUST reject a digest with any other algorithm identifier or a byte string that is not 32 bytes long.

<a id="L0-ENC-21"></a>**L0-ENC-21. Tagged everywhere.** Every digest that is stored, exported or carried in a protocol message is written in the tagged form of [L0-ENC-20](#L0-ENC-20). Raw 32-byte hashes appear only inside Merkle tree computations ([§6](#6-merkle-trees)) and as `field_root` in a leaf core.

<a id="L0-ENC-22"></a>**L0-ENC-22. Domain separation by context.** Each kind of value that is digested has a context string. The digest of a value `v` of kind `K` is:

```
SHA-256( context(K) ‖ 0x00 ‖ dCBOR(v) )
```

where `context(K)` is the UTF-8 bytes of the context string, followed by one zero byte, followed by the deterministic encoding of the value. The context strings defined in this version:

| Kind | Context string |
|---|---|
| Intent envelope | `access/intent/v1` |
| Genesis record (DomainID) | `access/genesis/v1` |

<a id="L0-ENC-22a"></a>**L0-ENC-22a. New digest kinds.** The context table is published with the CDDL. Each new digest kind receives a context string of the form `access/<kind>/v1` when the feature that produces it is adopted.

<a id="L0-ENC-23"></a>**L0-ENC-23. Intent digest.** The intent digest is the digest of the `intent-envelope` under the context `access/intent/v1`. It is computed from the envelope by the party that prepares the evaluation input, never taken from the requester. The request nonce is not part of the intent envelope; a signed actor statement binds the nonce and the intent digest separately.

<a id="L0-ENC-24"></a>**L0-ENC-24. Hash prefixes.** Hashes that are not value digests use a one-byte prefix instead of a context string:

| Prefix | Use |
|---|---|
| `0x00` | Merkle leaf |
| `0x01` | Merkle interior node |
| `0x02` | Field commitment |
| `0x03` | Body commitment |

## 5. Record envelope and commitments

A domain's log is a sequence of records. Each record is a `record-envelope`. The Merkle tree over the log commits to a `leaf-core` per record, which holds the record's address and ordering plus one root over its field commitments. Fields can then be disclosed or withheld one by one without changing the leaf.

<a id="L0-ENC-25"></a>**L0-ENC-25. Domain identifier.** A DomainID is the tagged digest ([L0-ENC-22](#L0-ENC-22)) of the canonical bytes of the genesis record's full `record-envelope`, under the context `access/genesis/v1`. The genesis envelope has no `domain` field ([L0-ENC-27](#L0-ENC-27)).

<a id="L0-ENC-26"></a>**L0-ENC-26. Record kinds.** A record's `kind` is one of `genesis`, `opening`, `decision` and `claim`. Checkpoints and their cosignatures are not records; they are separately signed artifacts over the log. A decision made in `check` mode is never written to the log.

<a id="L0-ENC-27"></a>**L0-ENC-27. Envelope core.** The genesis record has no `domain` field. Every later record MUST carry `domain`. The record at position 0 has no `prev` field. Every later record MUST carry `prev`, the tagged digest of the leaf hash of the record before it. `recorded_at` is a TrustedTime.

<a id="L0-ENC-28"></a>**L0-ENC-28. Field commitments.** Each entry in `fields` has its own 32-byte salt in `field_salt` under the same name, and `field_salt` has exactly the names of `fields`. Salts come from a cryptographically secure random source. The commitment to field `name` is:

```
FC(name) = SHA-256( 0x02 ‖ field_salt[name] ‖ dCBOR([name, fields[name]]) )
```

<a id="L0-ENC-29"></a>**L0-ENC-29. Field root and leaf hash.** `field_root` is the Merkle tree hash ([L0-ENC-30](#L0-ENC-30)) whose leaf inputs are the field commitments `FC(name)`, ordered by the UTF-8 bytes of `name`. The field root of an empty field set is `SHA-256("")`. The `leaf-core` is the envelope with `fields` and `field_salt` replaced by `field_root`. The record's leaf hash is:

```
SHA-256( 0x00 ‖ dCBOR(leaf-core) )
```

<a id="L0-ENC-29a"></a>**L0-ENC-29a. Body commitments.** A redactable body is committed as:

```
body_commit = SHA-256( 0x03 ‖ salt ‖ dCBOR(body) )
```

Each body has its own 32-byte salt and exactly one commitment.

## 6. Merkle trees

<a id="L0-ENC-30"></a>**L0-ENC-30. Tree hash.** The Merkle tree hash follows [RFC 9162 §2.1.1](https://www.rfc-editor.org/rfc/rfc9162#section-2.1.1). For a list `D[n]` of leaf inputs:

- `MTH({}) = SHA-256("")`;
- `MTH({d}) = SHA-256(0x00 ‖ d)`;
- for `n > 1`, let `k` be the largest power of two smaller than `n`; then `MTH(D[n]) = SHA-256(0x01 ‖ MTH(D[0:k]) ‖ MTH(D[k:n]))`.

Inputs and outputs inside the tree are raw bytes.

<a id="L0-ENC-31"></a>**L0-ENC-31. Inclusion proofs.** An inclusion proof for leaf `m` in a tree of size `n` is the audit path of RFC 9162 §2.1.3. A verifier recomputes the root as in RFC 9162 §2.1.3.2 and accepts only if it equals the expected root.

<a id="L0-ENC-32"></a>**L0-ENC-32. Consistency proofs.** A consistency proof between tree sizes `m` and `n` is the proof of RFC 9162 §2.1.4. A verifier checks it as in RFC 9162 §2.1.4.2.

<a id="L0-ENC-33"></a>**L0-ENC-33. Proof transport.** Inclusion and consistency proofs are carried as CBOR arrays of 32-byte byte strings, in the order RFC 9162 defines.

Vectors for [L0-ENC-30](#L0-ENC-30) to [L0-ENC-33](#L0-ENC-33): [`core/1/merkle.json`](../../conformance/vectors/core/1/merkle.json), operation `digest.merkle`. The file gives 8 leaf inputs, the root of every prefix of sizes 0 to 8, an inclusion path for every (index, size) pair, and a consistency path for every (first, second) pair.

The checkpoint format that signs a tree head is part of the record exchange (L2), not of L0.

## 7. Scalar types

<a id="L0-ENC-35"></a>**L0-ENC-35. TrustedTime.** A TrustedTime is the number of milliseconds since the Unix epoch, as an unsigned 64-bit integer, untagged.

<a id="L0-ENC-36"></a>**L0-ENC-36. Identifiers.** Identifiers (`id`, `party-ref`, `instance-ref`, `grant-id`, `policy-ref`) are opaque 16-byte strings. An implementation MUST NOT derive meaning from their content. Identifiers derived from content are tagged digests.

<a id="L0-ENC-37"></a>**L0-ENC-37. Version vectors.** `spec-versions` names the core semantics, meta-schema, profile and schema versions a value was produced under. It is distinct from the versions of the authority state read for one decision, which are not part of L0 input.
