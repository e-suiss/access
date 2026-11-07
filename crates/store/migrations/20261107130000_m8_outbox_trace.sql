-- OP-67 m.1, OP-151 m.3 (p): an outbox row carries the W3C trace context of the request that
-- wrote it, so its consumer continues the same trace. Telemetry only: no decision reads it
-- (TI-18). Existing rows have none.
SET LOCAL ROLE access_migrator;

ALTER TABLE access.identity_outbox
  ADD COLUMN trace_parent text
  CHECK (trace_parent IS NULL OR trace_parent ~ '^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$');

ALTER TABLE access.authority_outbox
  ADD COLUMN trace_parent text
  CHECK (trace_parent IS NULL OR trace_parent ~ '^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$');

RESET ROLE;
