# access-telemetry

The OpenTelemetry facade of Access. The rest of the code base logs and traces through `tracing` and records metrics through the typed constructors here; nothing else names an OpenTelemetry crate (`cargo xtask check` enforces it). Telemetry is minimised and pseudonymous, carries no request body or personal data, and is never an input to a decision: an exporter that fails is counted and dropped, and no code path waits on it.

- **Logs.** One JSON object per line on standard output: `timestamp`, `level`, `target`, `service`, `version`, `trace_id`, `span_id`, `event`, `outcome`, `message`, the event's own `fields` and the current `span`. `event` is a permanent name from `conformance/catalog/events.toml`; a published name is never renamed. `log_format = "text"` prints the same events for a terminal.
- **Traces.** `tracing` spans are bridged to OpenTelemetry and exported over OTLP/gRPC. A request continues a well-formed W3C `traceparent` and starts a new trace for anything else; its trace id is the response's `Request-Id`. The trace travels on outbound HTTP requests, on outbox rows (`trace_parent` column) to their consumers, and on signer requests. Sampling is decided from the trace id alone (`trace_sample_ratio`), so a caller cannot force sampling. Sampled traces are operator telemetry, never an authority record.
- **Metrics.** `Counter`, `Gauge` and `Histogram` take their label names from the closed `Label` set and their label values as `&'static str`, so no identifier, address, tenant, realm or domain can become a series. The same SDK pipeline is read by `/metrics` (Prometheus text) and pushed over OTLP.
- **Oracle watch.** Advisory `check` and explain volume per Instance is kept in a bounded per-process table, never as a label, and exported to security tooling at `/internal/v1/oracle-watch`.

## Configuration

`access-server` reads a `[telemetry]` section:

| Key | Default | Meaning |
|---|---|---|
| `log_format` | `json` | `json` or `text` |
| `otlp_endpoint` | none | `http://<host>:<port>` of a collector next to the process; none exports nothing and keeps the local metrics |
| `environment` | `unspecified` | `deployment.environment` resource attribute |
| `trace_sample_ratio` | `0.1` | share of traces kept, 0 to 1 |

`service.name` and `service.version` come from the binary. `OTEL_*` environment variables do not set resource attributes. The export starts inside the async runtime, after the runtime lockdown, and the lockdown allows a TCP connection to the collector's port only. The signers log and do not export.

## Metrics

Every metric name starts with `access_`. The section column is the row of the operation signals table it serves.

| Metric | Type | Labels | Signal |
|---|---|---|---|
| `access_commit_duration_seconds` | histogram | `outcome` | Commit latency p50/p99 |
| `access_commit_batch_size` | histogram | | Batch size |
| `access_validation_retries_total` | counter | `operation` | Validation retry rate |
| `access_leader_epoch_changes_total` | counter | `reason` | Leader epoch changes (alarm) |
| `access_sequencer_cas_failures_total` | counter | | CAS failures (alarm) |
| `access_sequencer_fence_events_total` | counter | `reason` | Fence events (alarm) |
| `access_ingest_claims_total` | counter | `outcome` | Quarantine rate |
| `access_ingest_lane_total` | counter | `kind`, `outcome` | Ingest turns by lane; narrowing Claims never wait behind the general lane |
| `access_claim_issuer_quota_reached_total` | counter | | Issuer quota |
| `access_status_list_iat_age_seconds` | gauge | | Status list `iat` age (alarm near the TTL) |
| `access_protocol_rejections_total` | counter | `surface`, `reason` | Protocol rejection rates |
| `access_decisions_total` | counter | `outcome` | DENY / REQUIRE_ACTION rates |
| `access_advisory_requests_total` | counter | `kind` | Advisory check / explain volume (per Instance: oracle watch) |
| `access_requester_throttled_total` | counter | `surface` | Requester throttling security event |
| `access_artifact_unknown_version_total` | counter | `kind`, `track` | Unknown version refusals |
| `access_epoch_cache_lookups_total` | counter | `outcome` | Epoch cache hit/miss |
| `access_outbox_consumer_lag_seconds` | gauge | `consumer` | Outbox consumer lag |
| `access_argon2_queue_depth` | gauge | | Argon2 semaphore queue depth |
| `access_argon2_wait_seconds` | histogram | | Argon2 permit wait |
| `access_http_responses_total` | counter | `status` | 503/429 rates |
| `access_db_pool_in_use`, `access_db_pool_idle`, `access_db_pool_max` | gauge | `pool` | Pool queue depth |
| `access_signer_call_duration_seconds` | histogram | `plane`, `outcome` | Signer queue latency (residual risk signal) |
| `access_sign_in_factor_total` | counter | `factor` | Factor distribution (residual risk signal) |
| `access_passkey_conditional_ui_total` | counter | `stage`, `outcome` | Passkey conditional UI (the `assertion` stage the server sees) |
| `access_ready`, `access_readiness_failures_total` | gauge, counter | `check` | Readiness |
| `access_traceparent_malformed_total` | counter | | Malformed incoming trace context |
| `access_telemetry_export_failures_total` | counter | `kind` | Dropped exports |
| `access_risk_assessments_total` | counter | `outcome`, `mode` | SL2 sign-in assessments by level and stage |
| `access_risk_signals_total` | counter | `kind` | SL2 risk signals that fired |
| `access_risk_fp_ratio_ppm` | gauge | | SL2 false-positive ratio over 30 days, parts per million (budget 5000) |
| `access_secret_memory_backend` | gauge | `kind` | A signer's key memory backend (`memfd_secret` or `mlock`); a signer without one does not start |

Tenant, realm and domain breakdowns come from the analytics summary tables, not from metric labels.

## Retention

Telemetry is kept for 90 days, advisory and explain volume included: run Prometheus with `--storage.tsdb.retention.time=90d` (VictoriaMetrics: `-retentionPeriod=90d`) and give the trace backend the same retention. The local stack under `deploy/compose` keeps one day in memory.
