-- L2-REC-3, TI-RT1, OP-125 m.1: current state from decision effects, written in the commit
-- transaction; the fold from Genesis is its arbiter
SET LOCAL ROLE access_migrator;

CREATE TABLE access.authority_state (
  domain_id bytea NOT NULL,
  tenant_id uuid NOT NULL,
  key bytea NOT NULL CHECK (octet_length(key) BETWEEN 1 AND 512),
  value bytea,
  version bigint NOT NULL CHECK (version > 0),
  PRIMARY KEY (domain_id, key),
  FOREIGN KEY (domain_id, version) REFERENCES access.authority_log (domain_id, pos)
) WITH (fillfactor = 70);

ALTER TABLE access.authority_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.authority_state FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.authority_state FROM PUBLIC;
CREATE POLICY rows ON access.authority_state AS PERMISSIVE USING (true);
CREATE POLICY domain_scope ON access.authority_state AS RESTRICTIVE
  USING (domain_id = (SELECT access.domain_scope()))
  WITH CHECK (domain_id = (SELECT access.domain_scope()));

GRANT SELECT ON access.authority_state TO access_app, access_sequencer;
GRANT INSERT, UPDATE ON access.authority_state TO access_sequencer;

RESET ROLE;
