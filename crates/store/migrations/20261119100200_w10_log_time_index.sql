-- OP-66, OP-138, OP-158 m.3 (u), (z): an as_of time is read through an index on the trusted time,
-- never by sorting a domain's whole log (the EXPLAIN plan gate). The parent index is created on
-- the partitioned table only; each partition's index is built concurrently and attached (OP-55).
SET LOCAL ROLE access_migrator;

CREATE INDEX authority_log_recorded
  ON ONLY access.authority_log (domain_id, recorded_at DESC, pos DESC);

RESET ROLE;
