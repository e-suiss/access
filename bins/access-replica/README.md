# access-replica

A copy of an Access domain's record kept outside the provider. The replica follows the domain's
mirror, checks every record against the Merkle tree it rebuilds and every checkpoint against
the domain's binding keys, keeps its own append-only copy, and acknowledges what it holds with
a signed `replica_ack`. A revocation or another high-consequence commit is only acknowledged
once a declared replica holds it and an independent witness has cosigned it.

```text
access-replica keygen <key file>                         new Ed25519 ack key (mode 0600)
access-replica key <key file>                            the public key the domain declares
access-replica follow <config>                           follow the mirror and serve reads
access-replica apply-redactions <config> [<position>…]   apply redactions to the local copy
access-replica --replay <config>                         replay the copy and declare what differs
```

## Running a replica

1. The replica operator's Party holds the domain's audit export Grant. It commits an
   `access.audit_export` Exercise with `stream: "mirror"` and `disclosure: "full"`, and starts
   the run with `POST /access/v1/domains/{domain}/exports`; the answer names the run.
2. `access-replica keygen` makes the ack key; the domain declares the replica's name and key.
3. `follow` reads a configuration file:

   ```text
   name acme-replica
   key /etc/access-replica/key.pk8
   state /var/lib/access-replica
   server http://127.0.0.1:8443
   domain <DomainID, base64url>
   export <run id, base64url>
   binding <Ed25519 binding key, base64url>
   listen 127.0.0.1:8485
   ```

   `server` is a local listener: a TLS client in front of the replica holds the client
   certificate the provider authenticates the run's PEP by. Keys are read from files only.

The replica prints `listening <addr>` when its read endpoint is up and `acked <size>` after each
acknowledgement the provider took.

## What it keeps

Under `state/<domain>/`, nothing is ever rewritten:

- `records`: each record with its fields withheld (its commitments, which keep the leaf), and
  the whole record sealed under a key of its own;
- `deks`: those keys;
- `checkpoints`, `acks`, `redactions`: what it accepted, acknowledged and applied.

Records and keys are on disk before the acknowledgement that covers them is sent. A copy that
was stopped resumes from its files.

## Redaction

A redaction at the provider does not change a copy by itself. The mirror delivers redaction
notices; `apply-redactions` overwrites the key of each record named, after which the record can
no longer be read from the copy while its leaf, commitments and the tree stay intact.

## Replay

`--replay` runs the open evaluator over the copy, from this build and not the provider's: the
records fold into state from Genesis and each decision is re-evaluated against the state just
before it, as far as the record carries its inputs. Every decision that changes authority is
re-evaluated; every other one at 1 in 100. Which ones is the replica's own deterministic choice:
its signature over the decision's id, which the provider cannot predict.

What does not replay is signed with the ack key, kept under `state/<domain>/divergence/` and
sent to the domain, where the root and its Security Party decide whether to quarantine it.
Nothing stops. The run prints `replayed <records> reevaluated <decisions> divergent <n>`, then
`declared …` for a new finding or `known` for one already sent.

## Reads are advisory

`GET /v1/head` and `GET /v1/records/{position}` answer with `advisory: true`. A replica never
answers a decision, and an Access PEP never takes an advisory answer as a decision.

## Choosing a replica

Run the replica under an operator other than the provider: the domain owner, an auditor or a
second hosting provider. A Suiss-hosted domain needs at least one declared replica and one
independent witness before high-consequence commits are acknowledged.
