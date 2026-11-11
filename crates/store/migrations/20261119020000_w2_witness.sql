-- CMP-6, T17, SEC23, SI-12, B13, U9, HL-7, OP-158 m.3 (c), (d): each witness cosignature also
-- names the witness's verifier key and whether its operator is independent of the provider's;
-- the equivocation evidence the checkpointer's monitor keeps is two cosigned notes of one size
-- with different roots. Rows are never changed or removed (OP-73).
SET LOCAL ROLE access_migrator;

ALTER TABLE access.witness_cosign
  ADD COLUMN vkey text NOT NULL CHECK (octet_length(vkey) BETWEEN 1 AND 1024),
  ADD COLUMN independent boolean NOT NULL;
CREATE INDEX witness_cosign_independent ON access.witness_cosign (domain_id, size) WHERE independent;

CREATE TABLE access.equivocation_evidence (
  domain_id bytea NOT NULL CHECK (octet_length(domain_id) = 32),
  size bigint NOT NULL CHECK (size > 0),
  root_a bytea NOT NULL CHECK (octet_length(root_a) = 32),
  root_b bytea NOT NULL CHECK (octet_length(root_b) = 32),
  note_a text NOT NULL CHECK (octet_length(note_a) <= 262144),
  note_b text NOT NULL CHECK (octet_length(note_b) <= 262144),
  source text NOT NULL CHECK (octet_length(source) <= 1024),
  detected_at bigint NOT NULL CHECK (detected_at >= 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (root_a <> root_b),
  PRIMARY KEY (domain_id, size, root_a, root_b),
  FOREIGN KEY (domain_id) REFERENCES access.domain_head (domain_id)
);

ALTER TABLE access.equivocation_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.equivocation_evidence FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.equivocation_evidence FROM PUBLIC;
CREATE POLICY rows ON access.equivocation_evidence AS PERMISSIVE USING (true);
CREATE POLICY domain_scope ON access.equivocation_evidence AS RESTRICTIVE
  USING (domain_id = (SELECT access.domain_scope()))
  WITH CHECK (domain_id = (SELECT access.domain_scope()));
CREATE TRIGGER no_mutation BEFORE UPDATE OR DELETE ON access.equivocation_evidence
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.equivocation_evidence
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT, INSERT ON access.equivocation_evidence TO access_sequencer;
GRANT SELECT ON access.equivocation_evidence TO access_app;

RESET ROLE;
