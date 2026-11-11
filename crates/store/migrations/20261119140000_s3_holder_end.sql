-- OP-158 m.17 (g), G43, §9.9.3 k.6, §16.5.1: the end of each holder Instance a record ends,
-- written in the record's commit with the revocation of the holder's projection families. A list
-- is not built while an end at or before its position leaves a family of that holder on the list
-- live (a family opened before the end). Nothing is changed or deleted (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.holder_end (
  domain_id bytea NOT NULL,
  pos bigint NOT NULL CHECK (pos > 0),
  holder_id bytea NOT NULL CHECK (octet_length(holder_id) = 16),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (domain_id, pos, holder_id),
  FOREIGN KEY (domain_id, pos) REFERENCES access.authority_log (domain_id, pos)
);
CREATE INDEX holder_end_holder ON access.holder_end (domain_id, holder_id);
ALTER TABLE access.holder_end ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.holder_end FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.holder_end FROM PUBLIC;
CREATE POLICY rows ON access.holder_end AS PERMISSIVE USING (true);
CREATE POLICY domain_scope ON access.holder_end AS RESTRICTIVE
  USING (domain_id = (SELECT access.domain_scope()))
  WITH CHECK (domain_id = (SELECT access.domain_scope()));
CREATE TRIGGER no_mutation BEFORE UPDATE OR DELETE ON access.holder_end
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.holder_end
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
GRANT SELECT, INSERT ON access.holder_end TO access_sequencer;
GRANT SELECT ON access.holder_end TO access_app;

RESET ROLE;
