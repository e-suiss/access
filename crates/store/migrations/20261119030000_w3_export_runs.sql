-- OP-158 m.3 (f), (g), AP-14, G28, SI-15: each Record Export and each Replica Mirror session is
-- started by an allowed access.audit.export Exercise; the run names that Exercise, its actor,
-- the PEP that may read the stream and what it covers. Reading a run's stream later is the same
-- recorded Exercise, never an unrecorded read. Rows are never changed or removed (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.export_runs (
  domain_id bytea NOT NULL CHECK (octet_length(domain_id) = 32),
  export_id bytea NOT NULL CHECK (octet_length(export_id) = 32),
  kind text NOT NULL CHECK (kind IN ('package', 'mirror')),
  party bytea NOT NULL CHECK (octet_length(party) = 16),
  instance bytea NOT NULL CHECK (octet_length(instance) = 16),
  pep text NOT NULL CHECK (char_length(pep) BETWEEN 1 AND 512),
  range_from bigint NOT NULL CHECK (range_from >= 0),
  range_to bigint CHECK (range_to >= range_from),
  coverage text NOT NULL CHECK (coverage IN ('full', 'digest')),
  started_at bigint NOT NULL CHECK (started_at >= 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((kind = 'mirror') = (range_to IS NULL)),
  PRIMARY KEY (domain_id, export_id),
  FOREIGN KEY (domain_id) REFERENCES access.domain_head (domain_id)
);

ALTER TABLE access.export_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.export_runs FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.export_runs FROM PUBLIC;
CREATE POLICY rows ON access.export_runs AS PERMISSIVE USING (true);
CREATE POLICY domain_scope ON access.export_runs AS RESTRICTIVE
  USING (domain_id = (SELECT access.domain_scope()))
  WITH CHECK (domain_id = (SELECT access.domain_scope()));
CREATE TRIGGER no_mutation BEFORE UPDATE OR DELETE ON access.export_runs
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.export_runs
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT, INSERT ON access.export_runs TO access_app;
GRANT SELECT ON access.export_runs TO access_sequencer;

RESET ROLE;
