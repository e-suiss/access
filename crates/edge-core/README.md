# access-edge-core

The shared core of the Access protocol gateways (SAML, LDAP, Kerberos, RADIUS). A gateway is a
separate process that turns a legacy protocol exchange into an identity-plane authentication.
It is never an issuer, it writes no store and it never reaches the authority plane.

## Layers

| Layer | What it does |
|---|---|
| Realm | The gateway serves the one realm it is registered in; `hello` names it, any other is refused |
| Subject | Looks a user up by the identifier the protocol carried, over the edge channel |
| Claim | Reports an authentication; the realm issuer inside access-server signs the Claim |
| Keys | The gateway holds only its channel identity (client certificate and key); every signature is made by access-server |
| Audit | Event and outcome codes into the realm's audit log, never bodies |
| Governor | Token buckets per caller key; keys are kept as digests and a full table refuses new keys |
| Health | Counters labelled by call and outcome only, in the Prometheus text format |

## Edge channel

Each gateway has its own client certificate, issued by the operator's client CA, whose single
subjectAltName URI is `urn:suiss:access:gw:<kind>:<name>`. The realm registers the gateway (kind,
name and the certificate's SHA-256) with `idp.gateway.register`. access-server answers that
certificate on `/edge/v1/*` only (`hello`, `authenticate`, `issue_claim`, `subject_lookup`,
`session_attest`, `directory_read`, `audit`); every other route, the authority API included,
answers 403. Bodies are deterministic CBOR (`application/cbor`).

## Blast radius

A compromised gateway holds one client certificate and nothing else. With it, it can:

- look up subjects and report authentications in its own realm only;
- report only its kind's method (`ldap-bind` for LDAP, `kerberos` for Kerberos, `password` for
  RADIUS; a SAML gateway reports none), with an authentication time from the last five minutes,
  for an active subject; the resulting Claim is AAL1 with no assurance flag set;
- write event codes to its realm's audit log.

It cannot sign anything, reach another realm, write a store, call the authority API or raise an
authentication above AAL1. Retiring the gateway (`idp.gateway.retire`) or re-registering it with a
new certificate cuts the old certificate off at once.

## Parser worker

XML, DER and ASN.1 are never parsed in a gateway. `parser::ParserClient` sends them to the
`access-parser-worker` supervisor, whose pool (`pool`) keeps disposable worker processes with no
network, no file system, no key, 256 MiB of memory, 2 s of CPU and 5 s of wall clock per request.
A worker is replaced after 1000 requests or after any answer that is not a clean `ok`; a crash
answers `worker-failed` and touches nothing else.

## License

[Apache License 2.0](../../LICENSE).
