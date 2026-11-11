-- OP-158 m.3 (e), (f), SEC23, TI-13: the signed acknowledgements of each domain's declared
-- replicas: the replica holds the whole prefix up to `size` with `root`. A SEC23 acknowledgement
-- needs one that verifies. Rows are never changed or removed (OP-73). Lane W3 writes them.
SET LOCAL ROLE access_migrator;

CREATE TABLE access.replica_ack (
  domain_id bytea NOT NULL CHECK (octet_length(domain_id) = 32),
  replica text NOT NULL CHECK (char_length(replica) BETWEEN 1 AND 255),
  size bigint NOT NULL CHECK (size > 0),
  root bytea NOT NULL CHECK (octet_length(root) = 32),
  acked_at bigint NOT NULL CHECK (acked_at >= 0),
  signature bytea NOT NULL CHECK (octet_length(signature) = 64),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (domain_id, replica, size),
  FOREIGN KEY (domain_id) REFERENCES access.domain_head (domain_id)
);

ALTER TABLE access.replica_ack ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.replica_ack FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.replica_ack FROM PUBLIC;
CREATE POLICY rows ON access.replica_ack AS PERMISSIVE USING (true);
CREATE POLICY domain_scope ON access.replica_ack AS RESTRICTIVE
  USING (domain_id = (SELECT access.domain_scope()))
  WITH CHECK (domain_id = (SELECT access.domain_scope()));
CREATE TRIGGER no_mutation BEFORE UPDATE OR DELETE ON access.replica_ack
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.replica_ack
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT, INSERT ON access.replica_ack TO access_sequencer;
GRANT SELECT ON access.replica_ack TO access_app;

RESET ROLE;
