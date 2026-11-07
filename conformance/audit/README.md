# Audit conformance

Two things live here: the vectors of the audit stream renderings, and how a third party checks a
Record Export Package without Suiss.

## Rendering vectors

[`vectors.json`](vectors.json) holds audit records and their expected OCSF event, CEF line and
SET claims. Every rendering of one record carries the same `txn`, event id and timestamps. Event
names and their OCSF and CAEP mapping come from
[`../catalog/audit-taxonomy.toml`](../catalog/audit-taxonomy.toml).

## Verifying an export without Suiss

An auditor first commits an `access:audit_export` intent through ADP with their own Actor
Intent Statement. Once it is allowed, `POST /access/v1/audit/export` with the same request
returns the package as a CBOR sequence (`application/cbor-seq`):

1. a head: `domain`, `range`, `prefix` (the Merkle frontier before the range), `versions`,
   `schemas`, `export_exercise`, `replay_coverage` and the counts of what follows;
2. one record disclosure per position in the range;
3. one digest per Claim ingested in the range;
4. the checkpoints: tree size, root and `recorded_at` at the end of the range.

To verify it with the open Kernel alone:

1. Check that the records are the positions of `range`, in order, and that each record's `prev`
   is the leaf hash of the one before it, in the same domain.
2. Recompute each leaf hash from the disclosure (opened fields are committed again, withheld
   fields are taken as their commitments).
3. Start an RFC 9162 frontier from `prefix` at size `range.from`, push every leaf, and compare
   the root and size with the last checkpoint.
4. With `replay_coverage: "full"` and a range from Genesis, fold the records into state; each
   decision can then be evaluated again at `q − 1`.
5. Compare the checkpoint with one you obtained independently (a witness, the domain's own copy,
   or the signed checkpoint the domain publishes).

A redacted package (`replay_coverage: "digest"`) opens only the version vectors; chain, order and
root verify, re-evaluation does not. Any difference is evidence, not an error to retry.
