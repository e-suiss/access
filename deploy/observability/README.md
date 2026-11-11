# Observability deployment files

- `alerts/access.yaml`: Prometheus alert rules for the operation signals that raise an alarm. Every rule carries a `severity` (`sev-1`, `page` or `ticket`) and a `runbook` label naming the operator runbook to follow. Load it with `rule_files`.
- `alertmanager.example.yaml`: an example routing by `severity`. The receivers are placeholders; the paging system and the on-call rotation are the operator's choice.

The local stack (`deploy/compose/compose.yaml`) loads the same rules into its Prometheus and provisions the "Access operation signals" Grafana dashboard.

## Endpoints

`access-server` serves `/livez`, `/readyz`, `/healthz`, `/metrics` and `/internal/v1/oracle-watch` on its internal listener only. `/readyz` answers 503 with the names of the failing checks until every database pool, signer and start-up step is ready. Scrape `/metrics` from the internal network, or receive the same metrics over OTLP through a collector.

## Retention

Keep metrics and traces for 90 days: `--storage.tsdb.retention.time=90d` for Prometheus, `-retentionPeriod=90d` for VictoriaMetrics, and the same for the trace backend. Advisory check and explain volume is part of it.
