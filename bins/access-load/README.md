# access-load

An open load harness for Access. It drives a running `access-server` with prepared requests and
prints one JSON report per run: what was sent, what answered, exact latency percentiles,
throughput and the environment the figures were measured in. A number without its environment is
not published, and an unmeasured number is not used (OP-61).

```text
access-load list
access-load run <scenario> <target> --requests <file> [--rate <per s>] [--seconds <n>]
    [--connections <n>] [--out <file>]
```

## Open loop

Request `i` is due at `start + i / rate`, whether or not earlier requests have answered. Its
latency counts from when it was due, so waiting for a connection or behind a slow request is part
of the figure (no coordinated omission). `late_starts` counts requests the harness itself started
more than a millisecond late; a run with many is not a measurement of the server.

## Requests

The requests file has one JSON object per line: `{"method", "path", "headers", "body"}`. `method`
defaults to `POST` and `path` to the scenario's route. A JSON body is sent as
`application/json`; a string body is sent as it is. Requests that carry signatures (an AIS, a
client assertion) are prepared by the caller, one per line, and used in turn.

The transport is HTTP/1.1 on keep-alive TCP connections. A cell that terminates TLS in front of
the server is measured behind its terminator; the report names the host it ran on
(`ACCESS_LOAD_HOST`).

## Scenarios and budgets

Each scenario carries its p99 budget; the report says whether the run was within it.

| Scenario | Route | p99 budget | Other target | Source | Status |
|---|---|---|---|---|---|
| `commit` | `/access/v1/evaluation` (commit) | 30 ms | ≥ 2 000 commits/s/domain; witness-before-ack ≤ 750 ms | OP-32, §17.5.1 | target, pending reproduction |
| `check` | `/access/v1/evaluation` (check) | 5 ms on a miss | 100 µs on a cache hit | P46, §9.7A.6 | target, pending reproduction |
| `search` | `/access/v1/search/{kind}` | 50 ms | hard deadline 1 s, at most 1 000 results | P46, §9.7A.5 | target, pending reproduction |
| `login` | `/login` | none | more logins/s at the same Argon2 cost; total/Argon2 CPU < 1.10 | MKT-8, OP-32 | target, pending reproduction |
| `refresh` | `/token` | 200 ms (layer B) | refresh is not starved by login | §12.2.1, §4.10 | target, pending reproduction |
| `introspection` | `/introspect` | 1 ms (layer A) | | §12.2.1, TN-38 | target, pending reproduction |
| `revocation` | `/access/v1/evaluation` (revoke) | 30 ms commit | fan-out is layer C, asynchronous through the outbox | §12.2.1 | target, pending reproduction |

The budgets are internal targets (CR-17, OP-72). A budget missed on the hardware measured is
reported with the measured value, never rounded to the target.

## Environment

The report's `environment` holds the OS, architecture, CPU model and core count read from the
machine, the git version (`GITHUB_SHA` or `git rev-parse HEAD`), and what only the deployment
knows: `ACCESS_LOAD_PG_VERSION` and `ACCESS_LOAD_SYNC_STANDBYS`. The nightly `bench-wallclock`
job publishes each report with the job's run as an artefact.

## Capacity planning with Little's law

Little's law ties the three quantities a run measures: the mean number of requests in the system
`L` equals the arrival rate `λ` times the mean time each spends there `W`:

```text
L = λ · W
```

To size a cell for a target arrival rate:

1. Measure `W` for the request type at a rate below saturation (the run's mean latency, or p99
   for a tail budget).
2. The concurrency the cell must hold is `L = λ · W`. For 2 000 commits/s at a five-millisecond mean commit (an example, pending reproduction),
   `L = 2 000 × 0.005 = 10` commits in flight; the sequencer pool, the PostgreSQL connections and
   the signer must each admit at least that many.
3. Leave headroom: plan for utilisation `ρ = λ / μ ≤ 0.7`, where `μ` is the measured saturation
   throughput (raise `--rate` until `throughput_per_s` stops following it or `late_starts` and p99
   climb). Queueing delay grows as `1 / (1 − ρ)`, so a cell at 0.9 waits three times longer than
   one at 0.7.
4. A domain's commits are serial (one leader, one head), so `μ` per domain bounds that domain no
   matter how many cells there are; capacity across domains adds up, capacity within one does
   not.
5. Do not plan on cache hits. Advisory cache hit rates are low in practice (well under 90 %), so
   `W` for checks is planned on a miss (§9.7A.4).

Re-measure after each release; the figures belong to the version and the hardware they were
measured on.
