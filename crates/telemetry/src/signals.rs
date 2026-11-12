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

/// §17.8.2 "quarantine oranı": committed Claims by `outcome` (`admitted`, `quarantined`).
pub static INGEST_CLAIMS: Counter<1> = Counter::new(
    "access_ingest_claims_total",
    "Ingested Claims by verdict (TI-18: telemetry, not a decision input)",
    [Label::Outcome],
);

/// §17.8.2, OP-157 m.3 (p): ingest turns by lane (`kind`: `narrowing`, `general`) and
/// `outcome` (`taken`, `expired`). Telemetry, never a decision input (TI-18).
pub static INGEST_LANE: Counter<2> = Counter::new(
    "access_ingest_lane_total",
    "Claim ingest turns by lane and outcome (G44; TI-18: not a decision input)",
    [Label::Kind, Label::Outcome],
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

/// §13.9 "faktör dağılımı": submitted sign-in steps by `factor` class.
pub static SIGN_IN_FACTORS: Counter<1> = Counter::new(
    "access_sign_in_factor_total",
    "Submitted sign-in steps by factor class (§13.9)",
    [Label::Factor],
);

/// TN-99: passkey conditional UI, by `stage` and `outcome`. The server sees the `assertion`
/// stage; the browser's `capability`, `focus` and `promise` stages need a frontend contract
/// field to arrive.
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

/// §12.2.4, TN-46: SL2 sign-in assessments by `outcome` (the level: `low`, `medium`, `high`,
/// `unavailable`) and `mode` (the stage in force: `shadow`, `stepup`, `stepup_caep`).
pub static RISK_ASSESSMENTS: Counter<2> = Counter::new(
    "access_risk_assessments_total",
    "SL2 sign-in risk assessments by level and stage (TN-46; never a decision input, TI-18)",
    [Label::Outcome, Label::Mode],
);

/// IDP-39, TN-108: SL2 signals that fired, by `kind` (the signal name).
pub static RISK_SIGNALS: Counter<1> = Counter::new(
    "access_risk_signals_total",
    "SL2 risk signals that fired, by signal (IDP-39)",
    [Label::Kind],
);

/// §12.3.2, IDP-36, Ek B K06: recovery transitions by `kind` (the path class it started on) and
/// `outcome` (the state entered); success is `grace_period` over `requested`.
pub static RECOVERY_TRANSITIONS: Counter<2> = Counter::new(
    "access_recovery_transitions_total",
    "Account recovery transitions by path class and state entered (§12.3.2, IDP-36)",
    [Label::Kind, Label::Outcome],
);

/// TN-63, MKT-D13: recoveries started by an account that finished another within 30 days, by
/// `kind` (the path class): the re-trigger rate's numerator.
pub static RECOVERY_RETRIGGERS: Counter<1> = Counter::new(
    "access_recovery_retriggers_total",
    "Recoveries started again within 30 days of a finished one, by path class (TN-63)",
    [Label::Kind],
);

/// TN-53 rule 3, §18.4: the weakest recovery path class of each saved recovery configuration,
/// by `kind`; the console row reads its distribution.
pub static RECOVERY_WEAKEST_PATH: Counter<1> = Counter::new(
    "access_recovery_weakest_path_total",
    "Weakest recovery path class of each saved recovery configuration (TN-53)",
    [Label::Kind],
);

/// OP-151 m.3 (o): review items marked false positive per step-up request over the last 30
/// days, in parts per million; the FP budget is 5000 (0.5 %).
pub static RISK_FP_RATIO: Gauge<0> = Gauge::new(
    "access_risk_fp_ratio_ppm",
    "SL2 false-positive ratio of step-up requests over 30 days, parts per million (OP-151 m.3 (o))",
    [],
);

/// TN-81, OP-153 m.3 (h): registration requests by abuse score band (`low`, `medium`, `high`);
/// a score feeds step-up only, never a refusal.
pub static REGISTRATION_SCORES: Counter<1> = Counter::new(
    "access_registration_scores_total",
    "Registration requests by abuse score band (TN-81; step-up only, never a refusal)",
    [Label::Outcome],
);

/// TN-85, CR-37: accounts whose password is still a legacy hash waiting for lazy migration.
pub static LEGACY_HASH_ACCOUNTS: Gauge<0> = Gauge::new(
    "access_legacy_hash_accounts",
    "Accounts whose password is still an imported legacy hash (TN-85, CR-37)",
    [],
);

/// CR-34, RR-38: the signer's secret memory backend, by `kind` (`memfd_secret`, `mlock`); a
/// signer without one does not start.
pub static SECRET_MEMORY_BACKEND: Gauge<1> = Gauge::new(
    "access_secret_memory_backend",
    "Secret memory backend of a signer process (CR-34)",
    [Label::Kind],
);

/// §17.5.1, OP-32: a login process's CPU time over the CPU it spent hashing passwords, in
/// thousandths, over the last window (target below 1 100).
pub static LOGIN_CPU_RATIO: Gauge<0> = Gauge::new(
    "access_login_cpu_ratio_permille",
    "Process CPU over password hash CPU, thousandths (OP-32)",
    [],
);

/// §17.8.2 "Havuz kuyruk derinliği", OP-53, OP-158 m.3 (v): requests waiting in the
/// application for the `critical`, `admin` or `sequencer` pool; the back-pressure point.
pub static POOL_QUEUE_DEPTH: Gauge<1> = Gauge::new(
    "access_pool_queue_depth",
    "Requests waiting in the application for a pool (OP-53)",
    [Label::Pool],
);

/// §17.7.2, OP-45, OP-158 m.3 (s): seconds the identity database has not answered; 0 while it
/// answers. The degraded-mode alarm reads it (0–60 s alarm, > 300 s sev-1; PD).
pub static IDENTITY_DEGRADED: Gauge<0> = Gauge::new(
    "access_identity_degraded_seconds",
    "Seconds the identity database has not answered (OP-45)",
    [],
);

/// §17.4.4, §17.8.2, OP-158 m.3 (d), (i), (n): integrity events that page as sev-1, by `kind`
/// (`unfenced_promote`, `rebuild_diff`, `equivocation`).
pub static INTEGRITY_ALARMS: Counter<1> = Counter::new(
    "access_integrity_alarms_total",
    "Sev-1 integrity events by kind (U9, TI-RT1, FA-13)",
    [Label::Kind],
);

/// CR-12 m.3, OP-159 m.3 (t): TLS handshakes by `listener` (`public`, `mtls`), negotiated or
/// offered `group` (`x25519mlkem768`, `x25519`, `secp256r1`, `other`) and `outcome` (`ok`,
/// `failed`, `retry` after a `HelloRetryRequest`). No label comes from the request (TN-127).
pub static TLS_HANDSHAKES: Counter<3> = Counter::new(
    "access_tls_handshakes_total",
    "TLS handshakes by listener, key exchange group and outcome (CR-12)",
    [Label::Listener, Label::Group, Label::Outcome],
);
