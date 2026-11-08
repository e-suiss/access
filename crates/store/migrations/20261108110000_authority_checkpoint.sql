-- CMP-6, T16, T20, OP-143 m.10: the signed checkpoints of each domain's log. The checkpointer of
-- the process that leads a domain signs its committed head at the cadence with the domain's
-- operational key (usage `checkpoint`) and appends the note with the key's excerpt; a quiet
-- domain gets one too (heartbeat). Rows are never changed or removed (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.authority_checkpoint (
  domain_id bytea NOT NULL CHECK (octet_length(domain_id) = 32),
  issued_at bigint NOT NULL CHECK (issued_at >= 0),
  size bigint NOT NULL CHECK (size > 0),
  root bytea NOT NULL CHECK (octet_length(root) = 32),
  note text NOT NULL CHECK (octet_length(note) <= 262144),
  excerpt bytea NOT NULL CHECK (octet_length(excerpt) <= 65536),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (domain_id, issued_at),
  FOREIGN KEY (domain_id) REFERENCES access.domain_head (domain_id)
);

ALTER TABLE access.authority_checkpoint ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.authority_checkpoint FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.authority_checkpoint FROM PUBLIC;
CREATE POLICY rows ON access.authority_checkpoint AS PERMISSIVE USING (true);
CREATE POLICY domain_scope ON access.authority_checkpoint AS RESTRICTIVE
  USING (domain_id = (SELECT access.domain_scope()))
  WITH CHECK (domain_id = (SELECT access.domain_scope()));
CREATE TRIGGER no_mutation BEFORE UPDATE OR DELETE ON access.authority_checkpoint
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.authority_checkpoint
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT, INSERT ON access.authority_checkpoint TO access_sequencer;
GRANT SELECT ON access.authority_checkpoint TO access_app;

RESET ROLE;
