# access-witness

An open witness for Access domain logs. Anyone can run it for any domain: it does not need
Suiss, and it never connects to an Access database.

The witness keeps, for each domain it serves, the last checkpoint it cosigned. It cosigns a new
checkpoint only when

- the checkpoint is signed by an operational key of the domain's binding the witness was
  configured with, valid at the checkpoint's `issued_at` and declared for `checkpoint`, and
- an RFC 9162 consistency proof from its last cosigned checkpoint verifies.

When a domain changes its binding, by a handover to another provider or a re-anchor inside one,
the checkpoint that ends with the `domain_handover` record carries that record and its inclusion
proof. The witness cosigns it under the old binding, learns the new binding keys from the record,
and from then on cosigns nothing larger under the old binding (`fenced`); checkpoints under the
new binding extend the same chain. The learned keys and the fence are lines of its state file,
so a restart keeps them.

Its state is one append-only, hash-chained file per domain; a changed or missing line stops the
witness from starting. A cosignature is on disk before it is answered. A checkpoint with the
same size as the base but another root is refused and kept as evidence.

## Use

```sh
access-witness keygen /etc/access-witness/key.pk8 witness.example.org   # prints the vkey
access-witness serve /etc/access-witness/witness.conf                   # prints `listening <addr>`
access-witness monitor /etc/access-witness/monitor.conf                 # exit 3 on equivocation
access-witness fence /etc/access-witness/witness.conf <domain> <size>   # while stopped
```

`witness.conf`:

```text
name witness.example.org
key /etc/access-witness/key.pk8
state /var/lib/access-witness
listen 127.0.0.1:8484
operator Example Witness Ltd
log <domain, base64url> <binding public key, base64url>
```

`monitor.conf` names one domain and the witnesses to compare:

```text
domain <domain, base64url>
witness http://witness-a.example:8484 <vkey>
witness http://witness-b.example:8484 <vkey>
```

## Endpoints

| Method and path | Body | Answer |
|---|---|---|
| `POST /cosign` | `cosign-request` (CBOR) | `cosign-response` (CBOR) |
| `GET /gossip/{domain}` | | `gossip-entry` (CBOR) with the cosigned note |
| `GET /info` | | name, vkey and operator |

The CBOR shapes are in `conformance/cddl/witness.cddl`. Every answer is signed, so the witness
speaks plain HTTP; put TLS in front of it if you want transport privacy.

## Independence

A witness counts as independent of a provider only when its operator is not the provider's
operator. A provider never counts its own witness toward the "at least one independent witness"
a domain needs.
