-- CR-45 RA-2, RA-3, RA-4, RA-6, OP-159 m.3 (g), m.4 (l), (n): the post-quantum re-anchor
-- checkpoints of each domain's log and their witnesses' post-quantum cosigns. A re-anchor
-- checkpoint is a tagged COSE_Sign1 over the byte-identical T16 note body, signed with an ML-DSA
-- operational key whose excerpt the binding signs; a cosign is a COSE_Sign1 over the note body and
-- the cosign time. `reason` is the RA-6 trigger: the first cadence checkpoint of a UTC day, an
-- operator request, or the step before a classical algorithm is retired. Rows are never changed
-- or removed (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.pq_checkpoints (
  domain_id bytea NOT NULL CHECK (octet_length(domain_id) = 32),
  issued_at bigint NOT NULL CHECK (issued_at >= 0),
  size bigint NOT NULL CHECK (size > 0),
  root bytea NOT NULL CHECK (octet_length(root) = 32),
  body text NOT NULL CHECK (octet_length(body) BETWEEN 1 AND 262144),
  sign1 bytea NOT NULL CHECK (octet_length(sign1) BETWEEN 1 AND 131072),
  excerpt bytea NOT NULL CHECK (octet_length(excerpt) BETWEEN 1 AND 16384),
  reason text NOT NULL CHECK (reason IN ('cadence', 'request', 'retirement')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (domain_id, issued_at),
  FOREIGN KEY (domain_id) REFERENCES access.domain_head (domain_id)
);

CREATE INDEX pq_checkpoints_size ON access.pq_checkpoints (domain_id, size);

ALTER TABLE access.pq_checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.pq_checkpoints FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.pq_checkpoints FROM PUBLIC;
CREATE POLICY rows ON access.pq_checkpoints AS PERMISSIVE USING (true);
CREATE POLICY domain_scope ON access.pq_checkpoints AS RESTRICTIVE
  USING (domain_id = (SELECT access.domain_scope()))
  WITH CHECK (domain_id = (SELECT access.domain_scope()));
CREATE TRIGGER no_mutation BEFORE UPDATE OR DELETE ON access.pq_checkpoints
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.pq_checkpoints
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT, INSERT ON access.pq_checkpoints TO access_sequencer;
GRANT SELECT ON access.pq_checkpoints TO access_app;

CREATE TABLE access.witness_pq_cosign (
  domain_id bytea NOT NULL CHECK (octet_length(domain_id) = 32),
  issued_at bigint NOT NULL CHECK (issued_at >= 0),
  witness text NOT NULL CHECK (char_length(witness) BETWEEN 1 AND 255),
  cosigned_at bigint NOT NULL CHECK (cosigned_at >= 0),
  sign1 bytea NOT NULL CHECK (octet_length(sign1) BETWEEN 1 AND 16384),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (domain_id, issued_at, witness),
  FOREIGN KEY (domain_id, issued_at) REFERENCES access.pq_checkpoints (domain_id, issued_at)
);

ALTER TABLE access.witness_pq_cosign ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.witness_pq_cosign FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.witness_pq_cosign FROM PUBLIC;
CREATE POLICY rows ON access.witness_pq_cosign AS PERMISSIVE USING (true);
CREATE POLICY domain_scope ON access.witness_pq_cosign AS RESTRICTIVE
  USING (domain_id = (SELECT access.domain_scope()))
  WITH CHECK (domain_id = (SELECT access.domain_scope()));
CREATE TRIGGER no_mutation BEFORE UPDATE OR DELETE ON access.witness_pq_cosign
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.witness_pq_cosign
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT, INSERT ON access.witness_pq_cosign TO access_sequencer;
GRANT SELECT ON access.witness_pq_cosign TO access_app;

RESET ROLE;
