-- OP-158 m.3 (c), (d), (e), SEC23, U9: the witness cosignatures of each domain's checkpoints, as
-- tlog-cosignature/v1 lines: the witness's key name, its timestamp in seconds and the Ed25519
-- signature. A SEC23 acknowledgement needs at least one from an independent witness. Rows are never
-- changed or removed (OP-73). Lane W2 writes them.
SET LOCAL ROLE access_migrator;

CREATE TABLE access.witness_cosign (
  domain_id bytea NOT NULL CHECK (octet_length(domain_id) = 32),
  size bigint NOT NULL CHECK (size > 0),
  root bytea NOT NULL CHECK (octet_length(root) = 32),
  witness text NOT NULL CHECK (char_length(witness) BETWEEN 1 AND 255),
  cosigned_at bigint NOT NULL CHECK (cosigned_at >= 0),
  signature bytea NOT NULL CHECK (octet_length(signature) = 64),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (domain_id, size, witness),
  FOREIGN KEY (domain_id) REFERENCES access.domain_head (domain_id)
);

ALTER TABLE access.witness_cosign ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.witness_cosign FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.witness_cosign FROM PUBLIC;
CREATE POLICY rows ON access.witness_cosign AS PERMISSIVE USING (true);
CREATE POLICY domain_scope ON access.witness_cosign AS RESTRICTIVE
  USING (domain_id = (SELECT access.domain_scope()))
  WITH CHECK (domain_id = (SELECT access.domain_scope()));
CREATE TRIGGER no_mutation BEFORE UPDATE OR DELETE ON access.witness_cosign
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.witness_cosign
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT, INSERT ON access.witness_cosign TO access_sequencer;
GRANT SELECT ON access.witness_cosign TO access_app;

RESET ROLE;
