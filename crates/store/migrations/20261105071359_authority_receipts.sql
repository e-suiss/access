-- §9.8, L2-RCP-2, OP-149 m.9: the receipt of each new ALLOW, kept so GET /access/v1/exercises/{id}
-- answers with what the decision point issued: its unsigned payload and, once the signer signed
-- it, the COSE_Sign1 with its key excerpt. Written by the leader after the commit; never changed
-- or deleted (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.authority_receipt (
  domain_id bytea NOT NULL,
  exercise_id bytea NOT NULL CHECK (octet_length(exercise_id) = 32),
  pos bigint NOT NULL CHECK (pos > 0),
  payload bytea NOT NULL CHECK (octet_length(payload) <= 65536),
  sign1 bytea CHECK (sign1 IS NULL OR octet_length(sign1) <= 65536),
  excerpt bytea CHECK (excerpt IS NULL OR octet_length(excerpt) <= 65536),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (domain_id, exercise_id),
  FOREIGN KEY (domain_id, pos) REFERENCES access.authority_log (domain_id, pos),
  CHECK ((sign1 IS NULL) = (excerpt IS NULL))
);

ALTER TABLE access.authority_receipt ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.authority_receipt FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.authority_receipt FROM PUBLIC;
CREATE POLICY rows ON access.authority_receipt AS PERMISSIVE USING (true);
CREATE POLICY domain_scope ON access.authority_receipt AS RESTRICTIVE
  USING (domain_id = (SELECT access.domain_scope()))
  WITH CHECK (domain_id = (SELECT access.domain_scope()));
CREATE TRIGGER no_mutation BEFORE UPDATE OR DELETE ON access.authority_receipt
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.authority_receipt
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT ON access.authority_receipt TO access_app, access_sequencer;
GRANT INSERT ON access.authority_receipt TO access_sequencer;

RESET ROLE;
