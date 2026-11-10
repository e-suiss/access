# access-identity-export

Sends a realm's audit log to the tenant's SIEM, data lake or log pipeline. What leaves is a
**copy, not the record**: every exported event carries the label, and every audit question is
answered from Access's own record, which a changed or lost copy cannot affect.

Every audit event goes out, in the order the log integrated it. Nothing is sampled and no event
type is filtered. Each sink keeps a cursor: the cursor moves only after the sink accepted a
batch, so a sink that is down or refusing loses nothing and gets the backlog when it returns.

## Sinks

A realm administrator registers a sink with `POST /admin/v1/realms/{slug}/export-sinks`
(`idp.export.sink_register`, CT2), replaces it with `PUT …/export-sinks/{sink}`
(`idp.export.sink_update`, CT2) and retires it with `POST …/export-sinks/{sink}/retire`
(`idp.export.sink_retire`, CT1). Each change is a new version; nothing is deleted. The sink's
secret is write-only: it is sealed under the realm's key and never shown, logged or echoed in an
error.

| Adapter | `endpoint` | Settings | Secret |
|---|---|---|---|
| `s3_parquet` | the S3 endpoint, e.g. `https://s3.eu-central-1.amazonaws.com` | `bucket`, `region`, `access_key_id`, `prefix`?, `account_id`?, `path_style`? | the secret access key |
| `otlp` | the OTLP/HTTP logs URL, e.g. `https://otel.example/v1/logs` | `auth_header`? | optional bearer or header value |
| `collector` | the collector URL | `auth_header`? | optional bearer or header value |
| `collector` + `splunk` | the HEC event URL (`…/services/collector/event`) | `index`?, `source`?, `sourcetype`? | the HEC token |
| `collector` + `sentinel` | the data collection endpoint | `dcr_immutable_id`, `stream`, `tenant_id`, `client_id`, `token_url`? | the Entra client secret |
| `collector` + `datadog` | the Logs intake URL (`…/api/v2/logs`) | `service`?, `tags`? | the API key |
| `collector` + `elastic` | the cluster URL | `index` (the data stream) | the API key |
| `syslog` | `host:port` | `format` (`cef` or `leef`), `app_name`?, `hostname`? | none |

The presets are data presets of the HTTP collector, not separate integrations.

```json
{
  "name": "splunk",
  "adapter": "collector",
  "preset": "splunk",
  "endpoint": "https://http-inputs-acme.splunkcloud.com/services/collector/event",
  "settings": { "index": "access" },
  "secret": "…"
}
```

## Wire forms

- **OCSF.** Events are aligned with OCSF field names (the version is pinned to the audit
  taxonomy's `ocsf_version`, 1.3.0); the canonical schema stays Access's. What OCSF has no field
  for is under `unmapped`, where `access_record` is `copy`.
- **Parquet on S3 / Amazon Security Lake.** One Snappy-compressed Parquet file per batch, with
  OCSF column names and nesting, at
  `{prefix}region={region}/accountId={account}/eventDay={YYYYMMDD}/{realm}-{xid}-{id}.parquet`
  (`prefix` defaults to `ext/access/`). The `PUT` is signed with AWS Signature Version 4 over the
  body's SHA-256. A retried batch writes the same key.
- **OTLP logs.** One log record per event under the `access.audit` scope, the OCSF event as its
  body. This is the audit copy, separate from Access's own telemetry export.
- **HTTP collector.** A JSON array of OCSF events; the presets shape them as Splunk HEC,
  Microsoft Sentinel's Logs Ingestion API (with a client credentials token), Datadog Logs v2 and
  Elastic `_bulk` expect.
- **Syslog.** RFC 5424 messages, facility 13 (log audit), framed by octet counting over TLS
  (RFC 5425), with a CEF or LEEF 2.0 message. Port 6514 on public addresses.

Every HTTP request carries `x-access-record: copy`.

## Delivery

HTTPS goes through Access's guarded outbound client: public addresses on port 443 only, no
redirects, one deadline per exchange. A private or non-standard target, including a syslog
receiver on another port, must be one the operator declared. A refused batch is retried on the
next pass from the same cursor; after three refusals in a row the realm gets one
`export.sink_failed` event and audit entry until the sink accepts again. An accepted batch is
recorded as `export.batch_sent`.

## Testing

The `testing` feature has in-process twins: an HTTPS twin that plays S3 (it verifies each `PUT`'s
signature from the request as received), each collector preset and the Sentinel token endpoint,
and a TLS syslog receiver. CI also runs the S3 adapter against MinIO and the syslog adapter
against syslog-ng.
