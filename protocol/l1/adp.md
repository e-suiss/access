# L1 Access Decision Profile (ADP)

Status: first draft, profile version 1. Not yet adopted.

ADP carries an Access Exercise request and its decision over the OpenID AuthZEN Authorization API 1.0. Every AuthZEN member keeps its meaning, except `subject`, which Access derives from the Actor Intent Statement ([L2-AIS-1](../l2/README.md#L2-AIS-1)) and never reads from the request. The Access members travel in `context`.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119 and RFC 8174.

## 1. Transport

<a id="L1-ADP-1"></a>**L1-ADP-1. Binding.** ADP is served over HTTPS with JSON bodies (I-JSON, RFC 7493). The endpoints are:

| Endpoint | Purpose |
|---|---|
| `POST /access/v1/evaluation` | One request in `commit`, `continue` or `check` mode |
| `POST /access/v1/evaluations` | Up to 64 independent requests (L1-ADP-14) |
| `POST /access/v1/explain` | A hypothetical explanation (L1-ADP-15) |
| `POST /access/v1/search/{subject,resource,action}` | Advisory search (L1-ADP-16) |
| `POST /access/v1/search/{schema-publications,change-impact,revocation-impact,compromise-impact,bulk-impact,sources}` | Developer reports (L1-ADP-16) |
| `POST /access/v1/search/{roles,role,admin-grant,holdings,changes}` | Management reads (L1-ADP-16) |
| `POST /access/v1/publications`, `POST /access/v1/publications:status` | Schema publication (L1-ADP-18) |
| `GET /.well-known/authzen-configuration` | Discovery |

The CBOR form of a body is the dCBOR of the same members with media type `application/access-adp+cbor`.

<a id="L1-ADP-2"></a>**L1-ADP-2. PEP authentication.** The PEP authenticates the transport (mutual TLS or OAuth client authentication). Its authenticated identity is the request's `pep`. A request without an authenticated PEP is refused with 401 and is not evaluated. The PEP's identity never becomes the actor.

<a id="L1-ADP-3"></a>**L1-ADP-3. Status codes.** A decision, whatever its outcome, is 200. `decision` is `true` only for `allow`; `deny` and `require_action` are `false`. A protocol error (§2) is 400 with an RFC 9457 body whose `code` member names the error, and produces no record. A nonce bound to another intent or actor is 422. A refused or unavailable domain is 503. A request over a rate limit of the actor Instance, or of the PEP for an anonymous request, is 429 with the code `rate-limited`; it is not recorded and does not consume its nonce (§13.7.4). A PEP treats every response other than 200 as no `allow`.

<a id="L1-ADP-4"></a>**L1-ADP-4. Request id.** A request's `X-Request-ID` header is echoed in the response. It is not an authority input.

## 2. Request

<a id="L1-ADP-5"></a>**L1-ADP-5. Members.** A request is an AuthZEN evaluation request:

```json
{
  "subject": { "type": "access_actor", "id": "-" },
  "action": { "name": "read" },
  "resource": { "type": "shop", "id": "item-1" },
  "context": {
    "domain": "<base64url DomainID>",
    "mode": "commit",
    "nonce": "<base64url, 16 to 64 bytes>",
    "ais": "<base64url COSE_Sign1>",
    "basis": { "holding": { "grant": "<id>", "holder": "<id>", "since": 42 } },
    "capacity": "own",
    "intent": { "action": { "namespace": "shop", "name": "read", "major": 1, "schema": "<digest>" },
                "resources": [ { "namespace": "shop", "path": ["item-1"], "incarnation": 0 } ],
                "validity": { "from": 0, "until": 1000000 } }
  }
}
```

`subject` is required by AuthZEN and ignored by ADP. `action.name` MUST equal `context.intent.action.name`; `resource.type` and `resource.id` MUST equal the namespace and the `/`-joined path of the first intent resource. A mismatch is the protocol error `carrier`.

<a id="L1-ADP-6"></a>**L1-ADP-6. Encodings.** Binary values are base64url without padding. An id is 16 bytes. A digest is the 32 SHA-256 bytes; the algorithm is implied. Integers are JSON numbers inside the I-JSON range. Text is a JSON string.

<a id="L1-ADP-7"></a>**L1-ADP-7. Context members.**

| Member | Form | Required |
|---|---|---|
| `domain` | digest | always |
| `mode` | `"commit"`, `"continue"`, `"check"` | always |
| `nonce` | bytes, 16 to 64 | always |
| `ais` | bytes: the COSE_Sign1 exactly as the actor signed it | for an authenticated actor |
| `basis` | `{"anchor": id}`, `{"public": id}` or `{"holding": {"grant": id, "holder": id, "since": uint}}` | always |
| `capacity` | `"own"` or `{"for": id}` | always |
| `intent` | intent object (L1-ADP-8) | always |
| `payload` | bytes: dCBOR of the `meta-payload`, for a meta-action ([L0-META-2](../l0/meta.md#L0-META-2)) | meta-actions |
| `proofs` | array of 1 to 64 proof objects (L1-ADP-12) | no |
| `exercise` | digest: the ExerciseID continued | `continue` |
| `consistency_token` | text: a token from an earlier response; the answer is given at or after the position it names, else the domain answers 503 | no; ignored by `commit` and `continue` |
| `rate_context` | text, 1 to 96 of `A-Z a-z 0-9 - _ . :`: the PEP's pseudonymous context of the request, `ip:` and a keyed pseudonym of the client's IPv4 /24 or IPv6 /48, or `att:` and an attestation class; never an address | no |

A request without `ais` has an anonymous actor and can only use Public Grants. A `commit` or `continue` whose basis does not resolve (the actor is not the root or the holder, `since` does not match, or there is no such Grant) is a recorded `DENY` `no_covering_authority` that the actor resolves; the answer is the same in every case, so it does not say whether the Grant exists (OP-152 m.5 (a)).

<a id="L1-ADP-7a"></a>**L1-ADP-7a. Bootstrap rate.** An allowed Exercise of the Genesis bootstrap Grant (`party_register`, `instance_create`) draws on a recorded counter per PEP, `rate_context` and hour; the eleventh in one hour is a recorded `DENY` `restricted` / `policy:bootstrap-rate` that the actor resolves by waiting until the next hour. A request without `rate_context` is counted under its PEP alone (§13.7.4, OP-152 m.5 (b)). A malformed `rate_context` is the protocol error `rate_context`; an eligibility check never carries one.

<a id="L1-ADP-8"></a>**L1-ADP-8. Intent object.** The intent object has the members of `intent-envelope` with the same names. Their JSON forms:

| Member | Form |
|---|---|
| `action` | `{"namespace": text, "name": text, "major": uint, "schema": digest}` |
| `resources` | array of `{"namespace": text, "path": [text], "incarnation": uint}`, at least one |
| `params` | object of typed values: `{"enum": text}`, `{"eq": eq}`, `{"amount": {"value": int, "unit": text}}`, `{"count": uint}`, `{"interval": window}`, `{"resource": resource}`, `{"subject": id}`, `{"purpose": purpose}`, `{"flag": bool}`, `{"origin": {"origin": text, "access": "read" or "write"}}`; `eq` is a string, an integer, a boolean or `{"bytes": bytes}` |
| `opaque` | object of digests |
| `recipient` | id |
| `purpose` | `{"code": text}`, `{"work": digest}` or `{"aim": digest}` |
| `context` | `{"work"?, "commitment"?, "step"?, "upstream_exercise"?, "plan"?}`, each a digest |
| `provenance` | object naming members of `params`, each `"user"`, `"trusted"` or `"untrusted-external"` ([L0-ENC-23a](../l0/encoding.md#L0-ENC-23a)) |
| `validity` | window `{"from": uint, "until": uint}` |

Access computes the intent digest from the decoded envelope ([L0-ENC-23](../l0/encoding.md#L0-ENC-23)); a caller never supplies it.

<a id="L1-ADP-9"></a>**L1-ADP-9. Unknown members.** Unknown members of the AuthZEN carriers (`subject`, `action`, `resource` and their `properties`) are ignored. Every member of `context` and of the objects in it is must-understand: an unknown one is the protocol error `unknown-member`.

<a id="L1-ADP-12"></a>**L1-ADP-12. Proofs.** A proof object is one of `{"claim": bytes}`, a Claim's COSE_Sign1 ([L2-CLM-1](../l2/README.md#L2-CLM-1)); `{"claim_ref": id}`, a Claim already recorded; `{"contribution": digest}`, the ExerciseID of an allowed `contribute` ([L0-META-30](../l0/meta.md#L0-META-30)); `{"foreign_pap": {"metadata": bytes, "pap": bytes, "excerpt": bytes, "presentation": bytes, ?"status": {"list": bytes, "excerpt": bytes}}}`, a foreign domain's PAP ([L2-PAP-1](../l2/README.md#L2-PAP-1)) with that domain's binding-signed Domain Metadata, the key excerpt of the key that signed it and the holder's presentation, whose audience is this domain's DomainID in its text form ([L0-ENC-20](../l0/encoding.md#L0-ENC-20)) and whose nonce is the request's; it lets the actor hold a Grant whose holder is `ForeignAuthority(domain, class)` when a live `foreign-authority` Acceptance of that domain covers the class ([L0-META-27](../l0/meta.md#L0-META-27)). When the PAP's contract names a status entry, `status` carries the foreign domain's Token Status List ([L2-STL-2](../l2/README.md#L2-STL-2)) that holds it and the excerpt of the `status-list` key that signed the list; without a list signed at most one hour before the decision in which the entry is not set, the use is denied (`foreign-status`, `foreign-revoked`). A consumption-bearing action is covered only by a PAP whose contract carries the home domain's `offline_slice`; what this domain draws from each slice term is counted here and never exceeds the slice (§9.15A.3). A reference to nothing recorded is the protocol error `proof`. After `require_action`, the PEP sends the same nonce, intent and actor again with the proofs that were missing.

<a id="L1-ADP-13"></a>**L1-ADP-13. Continuation.** A `continue` request carries a new nonce and `exercise`, the ExerciseID of an allowed Exercise of the same intent digest and the same actor Instance; otherwise it is the protocol error `exercise`.

<a id="L1-ADP-14"></a>**L1-ADP-14. Batch.** A batch body has `evaluations`, an array of 1 to 64 requests, optional top-level `subject`, `action` and `resource` that an item without its own inherits, and optional `options.evaluations_semantic`. `context` is never inherited: every item carries its own nonce, AIS and intent. The items are independent; a batch is not atomic. `execute_all` (the default) answers every item. `deny_on_first_deny` and `permit_on_first_permit` stop at the first `false` or `true` decision and answer the rest `{"evaluated": false}`; they are allowed only when every item is in `check` mode, otherwise the whole batch is the protocol error `evaluations_semantic`. The response is 200 with `evaluations`, one entry per item in order: the item's decision as in §3, or `{"error": code}` for an item that got no decision. A rate limit is never an item's error: the first item over a limit makes the whole batch 429 and the rest are not evaluated; items committed before it are answered again when the PEP retries them with the same nonces.

<a id="L1-ADP-15"></a>**L1-ADP-15. Explain.** `POST /access/v1/explain` takes an evaluation request in `check` mode and answers it like a `check`, with `kind: "hypothetical"` in `context`; it is never recorded. A request whose `context` has `record`, the position of a decision record, explains that recorded decision instead: its `mode` is the recorded one, the record must be a decision of the same nonce and intent made for the same actor (else `explain-record`), and the evaluation is run again on the state just before the record, with the counters its earlier decisions consumed and the record's time. A rebuilt outcome that differs from the recorded one gives no explanation (`explain-mismatch`). The answer carries `kind: "recorded"` and `record`. `context.scope` chooses whose view it is: `requester` (the default; only the recorded actor, with the requester filter), `viewer` (a root or extensional holder in the lineage of the recorded basis; blockers keep their position and subcode except the subcode of a `restricted` blocker) or `audit` (the meta-anchor's root or the holder of a live Grant covering `access:audit`; unfiltered). Without that authority the request is the protocol error `explain-scope`. The evaluation always runs as the recorded actor with the recorded basis and capacity, which the request must repeat. Without `record`, a request in another mode than `check` is the protocol error `explain-mode`; `record` on any other endpoint is a protocol error. At `audit` scope the recorded explanation also carries `selection` (`grant`, `classes`, `since`), the second part of a two-part reason when the basis is a rule-shaped Grant, and `replay` (`match`, `differing`), the decision evaluated again; either is left out when the decision point does not give it. Any decision whose intent names an upstream Exercise carries `causal_binding: "audit-only"` (§9.9.2): the link is recorded for audit and detection; `enforced` is never claimed while no causal-bound allowance is evaluated.

<a id="L1-ADP-16"></a>**L1-ADP-16. Search.** A search body carries the reader's `context` as an evaluation in `check` mode whose intent's action is `access`/`search` and whose first resource is `access.search` with the path `[kind]`; the AIS makes the reader known. `context.query` is the search: `{"action", "resource"}` for `subject` (who can take the action on the resource), `{"party", "action"}` for `resource` and `{"party", "resource"}` for `action` (what that Party reaches). The `AuthZEN` carriers are not read. A next page is asked with `page.token`. The answer is `results`, `page.next_token` (empty at the end, opaque otherwise) and `context.advisory: true`; a search is never recorded and never a credential. The reader sees only what it may see: `subject` within an Anchor whose root it holds, `resource` and `action` for its own Party; anything else is an empty page, indistinguishable from nothing (OP-141 m.22 (j)). Pages hold at most 100 results. A page not found within 1 second is no answer (503), never a partial list. The developer kinds `schema-publications` (`{"namespace"}`), `change-impact` (`{"role", "from", "to"}` or `{"policy"?, "candidate"}`), `revocation-impact` (`{"grant"}` or `{"instance"}`, `"at"?`) and `compromise-impact` (one of `{"instance"}`, `{"issuer"}`, `{"key"}`, with `"window"`) answer one page holding one report, only to the domain's auditors (its meta-anchor root or a holder of a live Grant naming `access:audit_export`); anyone else gets an empty page. A report is advisory and carries no action: a domain accepts a published schema only by its own `acceptance.amend` with the exact fingerprint. `bulk-impact` (`{"revoke": [grant, …]}`, 1 to 100 Grants) answers the same readers with each Grant's revocation impact and their sum (subtree once, aftermath summed): the preview of a bulk revoke whose items are each an Exercise of their own (TN-125, E17). The management kinds answer the domain's auditors: `roles` (`{}`: every Named `AuthoritySet` and its latest version), `role` (`{"name", "version"?}`: one version in the JSON form of L1-ADP-17 with its computed "Not included" block, reserved actions of its prefix namespaces and actions accepted after its pinned catalog) and `admin-grant` (`{"grant"}`: the core meta-actions the Grant covers, one by one, reserved ones (`acceptance_*`, `anchor_*`) apart, each with its tier when widening and its quorums); `admin-grant` also answers the Grant's named holder. `holdings` (`{}`) answers any reader with its own live holdings, each `{grant, holder, since}` usable as an ADP `holding` basis, with the actions and resource it covers. `changes` (`{"before"?}`) is information only (no item claims an action): the allowed meta-Exercises before the given position, newest first, one result per object each changed (`{position, at, kind, id, version?, ended, own}`); an auditor sees every change, any other reader only changes its own Instance made or that changed its own Party, its own Instances or a Grant it holds by name. `sources` (`{}`) answers the domain's auditors with one report: every live Acceptance by its canonical use (`{acceptance, use, issuer: {party}|{foreign}, classes, namespace, since, protected, dependents}`, where `dependents` counts the live Grants that depend on it — by a holder condition or Claim requirement on one of its classes, as the partner they recognize, or naming an action it defines) and every partner domain with the ceilings of the live bridging Grants that recognize its authority (`{domain, acceptances, ceilings: [{grant, class, actions, resource, until}]}`); an acceptance for one use is not one for another (INV-15).

<a id="L1-ADP-17"></a>**L1-ADP-17. Meta payload JSON.** A management client that writes no CBOR names a meta payload ([L0-META-2](../l0/meta.md#L0-META-2)) in its JSON form: the `meta-payload` of `kernel.cddl` member for member, with an id, a key or other bytes as base64url text, a digest as base64url text of its 32 bytes, a `time-window` as `{"from", "until"}`, a holding as `{"grant", "holder", "since"}`, a disposition entry as `{"grant", "disposition"}`, an `ml_dsa` key as `{"alg", "key"}`, an equality value as a string, an integer, a boolean or `{"bytes": bytes}`, and every other map as an object with the same member names. A set is an array in any order without repeats. Every member is must-understand. The canonical dCBOR of a JSON payload is the Kernel's re-encoding of the value it decodes; its digest under `access/meta/v1` is `intent.opaque.payload`, and the `payload` member of a `commit` (L1-ADP-7) carries those bytes. `AuthoritySet` and `CanonicalAuthority` have the same form on their own. The JSON Schemas are the `MetaPayload`, `AuthoritySet` and `CanonicalAuthority` components of the product contract (`sdks/openapi/access-v1.json`); the round-trip vectors are [`conformance/vectors/management/1`](../../conformance/vectors/management/1).

<a id="L1-ADP-18"></a>**L1-ADP-18. Schema publication.** `POST /access/v1/publications` takes `{context, package, domains}`. `context` is a `check` context whose intent's action is `access`/`publish` on `access.publication` with the path `[namespace]` and whose `opaque.package` is `SHA-256("access/schema-package/v1" ‖ 0x00 ‖ JSON(package))`, where `JSON(package)` is the package with object members sorted by name and no insignificant whitespace; its AIS makes the publisher known, and a request without one is refused (401). `package` is a Schema Publication Package draft: `namespace`, `catalog_version`, `actions` (Action Schemas in the JSON form of L1-ADP-17), `classes` (`{action, parameter, class}` for every declared parameter, `class` one of `opaque`, `recipient`, `amount`, `count`, `choice`, `flag`), and optional `retirements`, `core_spec_min` and `compatibility` (`{from, relation}`). An authority-relevant parameter without a closed type refuses the package with its warnings (422, E12). The package is kept in the scope of each of the 1 to 16 named domains (TN-20); it changes none of them, and nothing here accepts it, not even for a publisher who administers a target domain: a domain accepts only with its own reserved `acceptance.amend` naming the exact fingerprint (X21). `POST /access/v1/publications:status` takes `{context, fingerprint, domains}`, a `check` of `access`/`read` on `access.publication:[namespace]`, and answers only the publication's publisher with `pending_acceptance` ("Pending acceptance in: …") and `accepted_in`; a domain that never accepted the publisher for the namespace is left out.

## 3. Response

<a id="L1-ADP-10"></a>**L1-ADP-10. Members.**

```json
{
  "decision": true,
  "context": {
    "outcome": "allow",
    "exercise": "<digest>",
    "basis_ref": "<opaque>",
    "versions": { "core": 1, "meta_schema": 1 }
  }
}
```

| Member | When |
|---|---|
| `outcome` | always: `"allow"`, `"deny"` or `"require_action"` |
| `advisory` | `check`: `true`, the decision is not recorded and is no promise |
| `exercise` | `allow` in `commit` and `continue` |
| `basis_ref` | recorded decisions: an opaque reference to the decision record, meaningful only to the domain; the position itself is never shown (TI-RT10) |
| `replayed` | a retry answered with the decision already recorded |
| `blockers`, `unmet`, `relied_on` | as in `decision-value`, binaries as in L1-ADP-6, through the requester's disclosure filter: a blocker carries no `subcode`, and its `position` only when it is a lineage hop (TI-20). With `outcome` they are the shared explanation format ([`explanation.cddl`](../../conformance/cddl/explanation.cddl)) |
| `consistency_token` | always: an opaque token of the head the answer was given at (OP-141 m.22 (f)) |
| `versions` | always |

## 4. Discovery

<a id="L1-ADP-11"></a>**L1-ADP-11. Configuration.** `GET /.well-known/authzen-configuration` returns `policy_decision_point`, the issuer the document was fetched from; `access_evaluation_endpoint`; `access_evaluations_endpoint`; and `capabilities` with `urn:suiss:access:adp:1`, `urn:suiss:access:explain:1` and `urn:suiss:access:consistency-token:1`.

## License

[Apache License 2.0](../../LICENSE).
