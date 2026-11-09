# access-experience

The experience backend behind the Authority hub: it turns what Access recorded into the rows a person reads under "Acting for you", "Shared from you", "Your authority", "Activity" and "Changes".

It holds no authority and writes none. It reads Access only through the public endpoints any third-party experience would use, with the reader's own signed statement (AIS) from the reader's device, so a Suiss surface can do nothing a conformant third-party surface cannot. A revoke, a narrow or a suspend goes from the device to Access directly; this service only renders what Access recorded afterwards.

## Routes

The contract is [`sdks/openapi/experience-v1.json`](../../sdks/openapi/experience-v1.json), generated from `src/contract.rs` (`just experience-contract`).

| Route | What it does |
|---|---|
| `POST /experience/v1/hub/plan` | The search reads to sign, one per domain and kind (`inventory`, `activity`, `changes`), with the PEP name the AIS must carry. Reads and writes nothing. |
| `POST /experience/v1/hub` | Sends the signed reads to each domain's Access and assembles the hub. |
| `GET /experience/v1/stream` | Server-sent events `{kind, at_least}`: a hint to read again, never the data. Fed by polling the service's SSF stream at Access (`ACCESS_EXPERIENCE_SSF_POLL`, `ACCESS_EXPERIENCE_SSF_TOKEN`); the events themselves are never forwarded or trusted. |

## What a row always says

- **Owner and time.** Every row names whose record it is and when it was read. A domain that does not answer is shown as "Current status unknown", never as empty and never as pending.
- **Capacity.** Every holding says in whose name it is used ("for their own use", "on behalf of …"), apart from where it came from. Everything the reader gave shows in at least one group.
- **Limits.** An authority limit and a financial limit are two rows with two owners.
- **Actions.** A row shows the actions the reader can take, at most two steps away; one the reader cannot take is shown with who can.
- **Rule-shaped holdings.** A stale selection reads "Needs refresh — not removed"; an ended one reads "Removed since …", and a rejoin is a new selection, not the old one back.
- **Coverage.** The hub always says "Not shown: domains you haven't connected"; it never claims to be complete.
- **Changes are information.** No change asks for an action; there is no notification centre.

## Honest outcomes

`domain::honesty` holds the status rules a surface follows after it sends an authority-changing request: "Submitted" until Access answers with a position, "Not confirmed — checking" when no answer came, a retry with the same nonce while the signed intent is still valid, and "Not recorded — try again" only when no attempt was ever sent. An unknown outcome is never shown as confirmed or as not recorded.

## License

Apache-2.0.
