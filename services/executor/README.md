# access-executor

The Access Executor runs an agent's allowed Exercises for it: durably, one idempotent step at a time, so a job that takes days survives a crash and no external effect happens twice. After each step it reports what happened as a signed Claim. It never decides anything: every step is an Access decision, and Access does not depend on the executor.

Registered executors come in three kinds, `cloud`, `customer` and `local`, and all follow the same rules. An executor is an Instance of its operator's Party; the operator is never the actor.

## Routes

The contract is [`sdks/openapi/executor-v1.json`](../../sdks/openapi/executor-v1.json), generated from `src/contract.rs` (`just executor-contract`). Every route is declared and answers `501 not-yet-served` until it is served.

| Route | What it does |
|---|---|
| `POST /executor/v1/jobs` | Starts a job for one allowed Exercise of the calling agent Instance. |
| `GET /executor/v1/jobs/{job}` | The job's state (`running`, `paused`, `stopped`, `unknown`), whether a pause or stop is confirmed, and its steps. |
| `GET /executor/v1/jobs/{job}/steps` | Each step with its idempotency key and reported outcome. |
| `POST /executor/v1/jobs/{job}/pause`, `/resume`, `/stop` | Pause, resume or stop; a pause or stop counts once the executor confirms it with an `executor_control` Claim. Resuming is a new Access decision. |
| `POST /executor/v1/jobs/{job}/steps/{step}/cancel` | Cancels an irreversible step inside its delayed-commit window. Silence is not approval. |

## What an outcome says

An outcome is the executor's report, never the truth about the world: `done` (with at least one kind of evidence: an upstream confirmation, an independent recheck or a page observation), `not-done`, or `unknown` when the result could not be verified. An unknown step is never retried on its own; a person decides.

## License

Apache-2.0.
