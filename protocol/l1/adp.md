# L1 Access Decision Profile (ADP)

Status: first draft, profile version 1. Not yet adopted.

ADP carries an Access Exercise request and its decision over the OpenID AuthZEN Authorization API 1.0. Every AuthZEN member keeps its meaning, except `subject`, which Access derives from the Actor Intent Statement ([L2-AIS-1](../l2/README.md#L2-AIS-1)) and never reads from the request. The Access members travel in `context`.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119 and RFC 8174.

## 1. Transport

<a id="L1-ADP-1"></a>**L1-ADP-1. Binding.** ADP is served over HTTPS with JSON bodies (I-JSON, RFC 7493). The endpoints are:

| Endpoint | Purpose |
|---|---|
| `POST /access/v1/evaluation` | One request in `commit`, `continue` or `check` mode |
| `GET /.well-known/authzen-configuration` | Discovery |

The CBOR form of a body is the dCBOR of the same members with media type `application/access-adp+cbor`.

<a id="L1-ADP-2"></a>**L1-ADP-2. PEP authentication.** The PEP authenticates the transport (mutual TLS or OAuth client authentication). Its authenticated identity is the request's `pep`. A request without an authenticated PEP is refused with 401 and is not evaluated. The PEP's identity never becomes the actor.

<a id="L1-ADP-3"></a>**L1-ADP-3. Status codes.** A decision, whatever its outcome, is 200. `decision` is `true` only for `allow`; `deny` and `require_action` are `false`. A protocol error (§2) is 400 with an RFC 9457 body whose `code` member names the error, and produces no record. A nonce bound to another intent or actor is 422. A refused or unavailable domain is 503. A PEP treats every response other than 200 as no `allow`.

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

A request without `ais` has an anonymous actor and can only use Public Grants.

<a id="L1-ADP-8"></a>**L1-ADP-8. Intent object.** The intent object has the members of `intent-envelope` with the same names. Their JSON forms:

| Member | Form |
|---|---|
| `action` | `{"namespace": text, "name": text, "major": uint, "schema": digest}` |
| `resources` | array of `{"namespace": text, "path": [text], "incarnation": uint}`, at least one |
| `params` | object of typed values: `{"enum": text}`, `{"eq": eq}`, `{"amount": {"value": int, "unit": text}}`, `{"count": uint}`, `{"interval": window}`, `{"resource": resource}`, `{"subject": id}`, `{"purpose": purpose}`, `{"flag": bool}`; `eq` is a string, an integer, a boolean or `{"bytes": bytes}` |
| `opaque` | object of digests |
| `recipient` | id |
| `purpose` | `{"code": text}`, `{"work": digest}` or `{"aim": digest}` |
| `context` | `{"work"?, "commitment"?, "step"?, "upstream_exercise"?}`, each a digest |
| `validity` | window `{"from": uint, "until": uint}` |

Access computes the intent digest from the decoded envelope ([L0-ENC-23](../l0/encoding.md#L0-ENC-23)); a caller never supplies it.

<a id="L1-ADP-9"></a>**L1-ADP-9. Unknown members.** Unknown members of the AuthZEN carriers (`subject`, `action`, `resource` and their `properties`) are ignored. Every member of `context` and of the objects in it is must-understand: an unknown one is the protocol error `unknown-member`.

## 3. Response

<a id="L1-ADP-10"></a>**L1-ADP-10. Members.**

```json
{
  "decision": true,
  "context": {
    "outcome": "allow",
    "exercise": "<digest>",
    "record": 17,
    "versions": { "core": 1, "meta_schema": 1 }
  }
}
```

| Member | When |
|---|---|
| `outcome` | always: `"allow"`, `"deny"` or `"require_action"` |
| `advisory` | `check`: `true`, the decision is not recorded and is no promise |
| `exercise` | `allow` in `commit` and `continue` |
| `record` | recorded decisions: position of the decision record |
| `replayed` | a retry answered with the decision already recorded |
| `blockers`, `unmet`, `relied_on` | as in `decision-value`, binaries as in L1-ADP-6 |
| `versions` | always |

## 4. Discovery

<a id="L1-ADP-11"></a>**L1-ADP-11. Configuration.** `GET /.well-known/authzen-configuration` returns `policy_decision_point`, the issuer the document was fetched from; `access_evaluation_endpoint`; and `capabilities` with `urn:esuiss:access:adp:1`.

## License

[Apache License 2.0](../../LICENSE).
