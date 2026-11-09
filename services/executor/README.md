# access-executor

The Access Executor runs an agent's allowed Exercises for it: durably, one idempotent step at a time, so a job that takes days survives a crash and no external effect happens twice. After each step it reports what happened as a signed Claim. It never decides anything: every effect waits for a verified ALLOW from Access, asked with the agent's own signed statement, and Access does not depend on the executor.

It is its own process with its own database. It reaches Access only over Access's public listener with its client certificate, exactly as any third-party enforcement point does, and uses only the public crates (`esuiss-access-kernel`, `esuiss-access-sdk`, `esuiss-crypto`). Nothing in Access depends on it.

## Registered executors

Registered executors come in three kinds, `cloud`, `customer` and `local` (on the person's own device), and all follow the same rules: there is no kind-specific path in the code. An executor is an Instance of its operator's Party; its key signs its reports. The operator is never the actor: a job runs only under the agent's own `commit` statement, and every checkpoint after it needs one of the agent's own `continue` statements.

A Resource in the token vault lists the executors allowed to use its tokens by their client certificate thumbprint. The vault releases a token only for an Exercise that Access allowed with that executor as the enforcement point and only once for it, and the token lives in the executor's memory only. Upstream tokens of consequential actions never reach the agent.

## How a job runs

A job's history is an append-only list of events in PostgreSQL (`executor` schema). Its state is a fold over that list, so a restart replays the job exactly: every time, random value and upstream answer it relied on is in the history and is never read from the world again.

- **Before any effect, Access is asked.** At the start (`commit`), and again at every re-check point: before each later step, after a pause, a takeover or a restart, and when an upstream reports a changed state (`continue`). Anything but a verified ALLOW leaves the job without a further effect. A step outside the Exercise's intent envelope, or after its horizon, never runs.
- **Outbox first.** A request's outbox entry is committed before the request leaves. If a crash loses the answer, the request is sent again once, with the same key, only when the upstream honours idempotency keys; otherwise the step is `unknown`. Nothing is ever retried on its own after an unknown outcome.
- **Idempotency keys.** Every request carries `H(ExerciseID ‖ StepRef)` as `Idempotency-Key` (and in the MCP `_meta` for the MCP driver).
- **Delayed commit.** An `irreversible` step waits 15 seconds before it leaves and can be cancelled until then; a cancel stops the job.
- **People take over.** When an upstream blocks the agent, or Access asks for an approval, the job waits for a person for at most 10 minutes. Silence is not approval: when nobody answers, the job stops.
- **Pause and stop.** A pause or stop takes effect at the next step boundary and counts once the executor confirms it with an `executor_control` Claim (`paused`, `stopped_confirmed`). After a confirmed stop there is no further effect.

## Drivers

- **OAuth HTTP**: one request to an upstream API from the vault's catalogue, with the released token as `Authorization: Bearer`.
- **MCP client**: one `tools/call` on an official MCP server.

Every request names the executor as itself (`User-Agent: access-executor/1`) and carries a Web Bot Auth signature (RFC 9421) over `@authority` and `Signature-Agent` by the executor Instance's Ed25519 key. `Signature-Agent` names the Suiss directory, never the person. There is no disguise: no borrowed browser identity, no proxy rotation, no CAPTCHA solving.

## What an outcome says

An outcome is the executor's report, never the truth about the world: `done` (with at least one kind of evidence: an upstream confirmation, an independent recheck or a page observation), `not-done`, or `unknown` when the result could not be verified. Each one becomes an `effect_attestation` Claim through Access's Claim Ingest, with the digest of the upstream's answer as evidence reference; the answer itself never enters Access. A report never changes the decision it belongs to: an allowed Exercise whose effect did not happen stays allowed, with outcome `not-done`.

## Routes

The contract is [`sdks/openapi/executor-v1.json`](../../sdks/openapi/executor-v1.json), generated from `src/contract.rs` (`just executor-contract`).

| Route | What it does |
|---|---|
| `POST /executor/v1/jobs` | Starts a job for one Exercise of the calling agent Instance; only a verified ALLOW opens it. |
| `GET /executor/v1/jobs/{job}` | The job's state (`running`, `paused`, `stopped`, `unknown`, `completed`), whether a pause or stop is confirmed, and its steps. |
| `GET /executor/v1/jobs/{job}/steps` | Each step with its idempotency key, reported outcome and Claim. |
| `POST /executor/v1/jobs/{job}/pause`, `/stop` | Pause or stop at the next step. |
| `POST /executor/v1/jobs/{job}/resume` | Resumes with the agent's new `continue` statements; going on is a new Access decision. |
| `POST /executor/v1/jobs/{job}/steps/{step}/cancel` | Cancels an irreversible step inside its delayed-commit window. |

## Running it

`access-executor` reads its configuration from the environment; see `src/main.rs` for the variables (listen address, Access origin, client certificate, upstream roots, database URL, kind, operator Party and Instance ids, signing key, Web Bot Auth directory). On start it picks every open job up again and asks Access before its next effect.

## License

Apache-2.0.
