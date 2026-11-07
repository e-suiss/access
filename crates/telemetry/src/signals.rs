//! The §17.8.2 operation signals and the §13.7 security counters as metrics. Each one names
//! its §17.8.2 row; none carries a tenant, realm or domain label (OP-47). Telemetry is never a
//! decision input (TI-18): recording returns nothing a caller could branch on.

use crate::metrics::{COUNT, Counter, Gauge, Histogram, LATENCY_SECONDS, Label};

/// §17.8.2 "Commit latency (p50/p99)": one sequencer batch commit, by `outcome`
/// (`ok`, `retry`, `error`, `replay`).
pub static COMMIT_DURATION: Histogram<1> = Histogram::new(
    "access_commit_duration_seconds",
    "Sequencer batch commit latency (OP-32)",
    [Label::Outcome],
    LATENCY_SECONDS,
);

/// §17.8.2 "batch boyutu": records per committed batch.
pub static COMMIT_BATCH_SIZE: Histogram<0> = Histogram::new(
    "access_commit_batch_size",
    "Records per sequencer batch (OP-32)",
    [],
    COUNT,
);

/// §17.8.2 "validation retry oranı": re-validations after the head moved, by `operation`
/// (`exercise`, `ingest`).
pub static VALIDATION_RETRIES: Counter<1> = Counter::new(
    "access_validation_retries_total",
    "Re-validations after the domain head moved (OP-32)",
    [Label::Operation],
);

/// §17.8.2 "Leader epoch değişimleri": leases taken, handed off or released, by `reason`
/// (`acquired`, `taken_over`, `handoff`, `released`, `lost`).
pub static LEADER_EPOCH_CHANGES: Counter<1> = Counter::new(
    "access_leader_epoch_changes_total",
    "Sequencer leader epoch changes (TI-2, FA-13)",
    [Label::Reason],
);

/// §17.8.2 "CAS hataları": a batch refused because the head moved under the leader.
pub static CAS_FAILURES: Counter<0> = Counter::new(
    "access_sequencer_cas_failures_total",
    "Batch commits refused because the domain head moved (TI-2)",
    [],
);

/// §17.8.2 "fence olayları": a leader fenced off, by `reason` (`renew_failed`, `lease_lost`).
pub static FENCE_EVENTS: Counter<1> = Counter::new(
    "access_sequencer_fence_events_total",
    "Sequencer fence events (TI-2, FA-13)",
    [Label::Reason],
);

/// §17.8.2 "quarantine oranı": ingested Claims by `outcome` (`indexed`, `quarantined`,
/// `held`).
pub static INGEST_CLAIMS: Counter<1> = Counter::new(
    "access_ingest_claims_total",
    "Ingested Claims by verdict (TI-18: telemetry, not a decision input)",
    [Label::Outcome],
);

/// §17.8.2 "Status list `iat` yaşı": seconds since the newest published list was issued.
pub static STATUS_LIST_IAT_AGE: Gauge<0> = Gauge::new(
    "access_status_list_iat_age_seconds",
    "Age of the newest published status list (SI-7)",
    [],
);

/// §17.8.2 "Rejection oranları (protocol)": protocol rejections by `surface` and `reason`
/// (the stable problem code).
pub static PROTOCOL_REJECTIONS: Counter<2> = Counter::new(
    "access_protocol_rejections_total",
    "Protocol rejections by surface and problem code (RR-8)",
    [Label::Surface, Label::Reason],
);

/// §17.8.2 "`DENY`/`REQUIRE_ACTION` oranları": decisions by `outcome` (`allow`, `deny`,
/// `require_action`). Telemetry, not canonical: the record answers audit questions (X22).
pub static DECISIONS: Counter<1> = Counter::new(
    "access_decisions_total",
    "Decisions by outcome (RR-8; telemetry, not canonical)",
    [Label::Outcome],
);

/// §17.8.2 "Advisory `check` / explain hacmi": by `kind` (`check`, `explain`). The per
/// Instance view is the oracle-watch table, never a label (SEC31, OP-47).
pub static ADVISORY_REQUESTS: Counter<1> = Counter::new(
    "access_advisory_requests_total",
    "Advisory check and explain requests (SEC31)",
    [Label::Kind],
);

/// §13.7.4: a requester throttled (security event), by `surface`.
pub static REQUESTER_THROTTLED: Counter<1> = Counter::new(
    "access_requester_throttled_total",
    "Requests refused by a requester rate limit (§13.7.4 security event)",
    [Label::Surface],
);

/// §17.8.2 "epoch cache hit/miss oranı": by `outcome` (`hit`, `miss`).
pub static EPOCH_CACHE: Counter<1> = Counter::new(
    "access_epoch_cache_lookups_total",
    "Session epoch cache lookups (OP-21)",
    [Label::Outcome],
);

/// §17.8.2 "outbox tüketici gecikmesi": age of the oldest event a consumer just handled, by
/// `consumer`.
pub static OUTBOX_LAG: Gauge<1> = Gauge::new(
    "access_outbox_consumer_lag_seconds",
    "Age of the last outbox event a consumer handled (OP-20)",
    [Label::Consumer],
);

/// §17.8.2 "Argon2 semafor kuyruk derinliği": hashes waiting for a permit.
pub static ARGON2_QUEUE_DEPTH: Gauge<0> = Gauge::new(
    "access_argon2_queue_depth",
    "Password hashes waiting for an Argon2 permit (OP-33)",
    [],
);

/// §17.8.2 OP-33: time a hash waited for its permit.
pub static ARGON2_WAIT: Histogram<0> = Histogram::new(
    "access_argon2_wait_seconds",
    "Time a password hash waited for an Argon2 permit (OP-33)",
    [],
    LATENCY_SECONDS,
);

/// §17.8.2 "503/429 oranları": HTTP responses by `status` class (`2xx`, `3xx`, `4xx`, `429`,
/// `5xx`, `503`).
pub static HTTP_RESPONSES: Counter<1> = Counter::new(
    "access_http_responses_total",
    "HTTP responses by status class (OP-35)",
    [Label::Status],
);

/// §17.8.2 "Havuz kuyruk derinliği": connections in use per pool role.
pub static POOL_IN_USE: Gauge<1> = Gauge::new(
    "access_db_pool_in_use",
    "Database connections in use per pool role (OP-53)",
    [Label::Pool],
);

/// §17.8.2 OP-53: idle connections per pool role.
pub static POOL_IDLE: Gauge<1> = Gauge::new(
    "access_db_pool_idle",
    "Idle database connections per pool role (OP-53)",
    [Label::Pool],
);

/// §17.8.2 OP-53: configured size per pool role.
pub static POOL_MAX: Gauge<1> = Gauge::new(
    "access_db_pool_max",
    "Configured database connections per pool role (OP-53)",
    [Label::Pool],
);

/// §13.9 "imza kuyruk gecikmesi": one signer call, by `plane` and `outcome`.
pub static SIGNER_CALL: Histogram<2> = Histogram::new(
    "access_signer_call_duration_seconds",
    "Signer call latency (§13.9 residual risk signal)",
    [Label::Plane, Label::Outcome],
    LATENCY_SECONDS,
);

/// §13.9 "faktör dağılımı": completed sign-ins by `factor`.
pub static SIGN_IN_FACTORS: Counter<1> = Counter::new(
    "access_sign_in_factor_total",
    "Completed sign-in steps by factor class (§13.9)",
    [Label::Factor],
);

/// TN-99: passkey conditional UI, by `stage` (`capability`, `focus`, `promise`) and `outcome`.
pub static PASSKEY_CONDITIONAL_UI: Counter<2> = Counter::new(
    "access_passkey_conditional_ui_total",
    "Passkey conditional UI stages seen by the server (TN-99)",
    [Label::Stage, Label::Outcome],
);

/// OP-67 m.3: readiness checks that failed, by `check`.
pub static READINESS_FAILURES: Counter<1> = Counter::new(
    "access_readiness_failures_total",
    "Readiness checks that failed (OP-67 m.3)",
    [Label::Check],
);

/// OP-67 m.3: 1 while the process is ready for traffic.
pub static READY: Gauge<0> = Gauge::new(
    "access_ready",
    "1 while the process is ready for traffic (OP-67 m.3, MD-8)",
    [],
);

/// OP-67 m.1: incoming `traceparent` values not well formed (a new trace was started).
pub static TRACEPARENT_MALFORMED: Counter<0> = Counter::new(
    "access_traceparent_malformed_total",
    "Incoming traceparent headers that were not well formed (OP-67 m.1)",
    [],
);

/// TI-18: telemetry exports that failed, by `kind`; nothing waits on them.
pub static TELEMETRY_EXPORT_FAILURES: Counter<1> = Counter::new(
    "access_telemetry_export_failures_total",
    "Telemetry exports that failed and were dropped (TI-18)",
    [Label::Kind],
);
