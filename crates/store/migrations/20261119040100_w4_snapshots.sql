-- OP-158 m.3 (i), TI-RT4, OP-142: verified snapshots of a domain's folded state. A snapshot names
-- the record position, the tree root after it and the SHA-256 of its state, in a checkpoint
-- note the domain's signer signed; a cold start uses one only when its root is a known
-- checkpoint's and a sampled fold check passes, and folds from Genesis otherwise. Snapshots are
-- an accelerator, never canonical (TI-16), and are never changed or removed (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.snapshots (
  domain_id bytea NOT NULL CHECK (octet_length(domain_id) = 32),
  tenant_id uuid NOT NULL,
  pos bigint NOT NULL CHECK (pos >= 0),
  root bytea NOT NULL CHECK (octet_length(root) = 32),
  state_digest bytea NOT NULL CHECK (octet_length(state_digest) = 32),
  state bytea NOT NULL,
  note text NOT NULL CHECK (char_length(note) BETWEEN 1 AND 65536),
  taken_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (domain_id, pos),
  FOREIGN KEY (domain_id, pos) REFERENCES access.authority_log (domain_id, pos)
);

ALTER TABLE access.snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.snapshots FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.snapshots FROM PUBLIC;
CREATE POLICY rows ON access.snapshots AS PERMISSIVE USING (true);
CREATE POLICY domain_scope ON access.snapshots AS RESTRICTIVE
  USING (domain_id = (SELECT access.domain_scope()))
  WITH CHECK (domain_id = (SELECT access.domain_scope()));
CREATE TRIGGER no_mutation BEFORE UPDATE OR DELETE ON access.snapshots
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.snapshots
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT, INSERT ON access.snapshots TO access_app, access_sequencer;

RESET ROLE;
