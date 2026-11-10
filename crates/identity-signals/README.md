# access-identity-signals

External signal sources of the Access identity plane: identity verification (KYC/IDV), device
management (MDM), risk and fraud engines, and data classification (DLP).

Every external signal is a Claim of a registered issuer. Registering a source
(`idp.signal.source_register`) only names that issuer; its Claims do something only once the
domain accepts them, with its own Acceptance, and then only through the domain's own policies.

## Claim classes

| Class | Body | Read as |
|---|---|---|
| `identity_proofing` | `{provider, method, ial \| loa_eidas, verified_at}` | a requirement input: the Claim carries `loa_eidas` 1–3 (IAL1–3) |
| `posture_mdm` | `{managed, compliant, provider, statement}` | restriction context `posture`: `none`, `compliant`, `unmanaged`, `noncompliant` |
| `risk_external` | `{level, reason_class}` | restriction context `risk`: `none`, `low`, `medium`, `high`, `critical` |
| `data_label` | `{label, scheme}` | restriction context `labels`: `scheme:label` of the labels the request carries |

Restriction policies only forbid or ask for more, so a signal can deny or require and never
allow. A body Access cannot read counts as the most severe statement of its class, a risk
Claim counts for at most a day after its issue, and a missing signal is `none`.

Biometrics, RASP and bot management engines send `risk_external` (or `posture_mdm` for device
checks) like any risk engine.

## Ingress

- **Claim Ingest**: the source signs its own Claims and sends the body beside them.
- **SSF**: CAEP `device-compliance-change` and `risk-level-change` map to the same bodies.
- **Call point**: a `post_login` hook's answer may carry `risk: {level, reason_class}`; a high
  or critical level refuses the sign-in.

## Vendor formats

Microsoft Intune `managedDevice`, Jamf Pro computer inventory, Okta's SSF transmitter, Onfido
checks and Persona inquiries map to the bodies above. Only the fields named in the code are
read; an answer that does not read is no signal.

## What Access does not do

Access reads no identity chip, matches no face and checks no liveness. Remote identity proofing
happens at the provider; its result is the provider's Claim.

## License

Apache-2.0
