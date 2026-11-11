-- TI-RT3, OP-138, OP-73, OP-158 m.3 (u): the nonce archive. Nonce rows past the hot horizon are
-- copied, unchanged, into an append-only archive; every nonce lookup and the nonce sequence rule
-- read the hot rows and the archive together, so an archived nonce is never opened again. Nothing
-- is deleted or changed.
SET LOCAL ROLE access_migrator;

CREATE TABLE access.authority_nonce_archive (
  domain_id bytea NOT NULL,
  tenant_id uuid NOT NULL,
  nonce bytea NOT NULL CHECK (octet_length(nonce) BETWEEN 1 AND 64),
  actor bytea NOT NULL,
  intent_digest bytea NOT NULL CHECK (octet_length(intent_digest) = 32),
  decision_pos bigint NOT NULL CHECK (decision_pos > 0),
  outcome text NOT NULL CHECK (outcome IN ('allow', 'deny', 'require_action')),
  render_digest bytea CHECK (render_digest IS NULL OR octet_length(render_digest) = 32),
  tier smallint CHECK (tier IS NULL OR tier BETWEEN 0 AND 3),
  archived_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (domain_id, nonce, decision_pos),
  FOREIGN KEY (domain_id, decision_pos) REFERENCES access.authority_log (domain_id, pos)
);
CREATE INDEX authority_nonce_archive_intent
  ON access.authority_nonce_archive (domain_id, intent_digest, decision_pos DESC);

ALTER TABLE access.authority_nonce_archive ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.authority_nonce_archive FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.authority_nonce_archive FROM PUBLIC;
CREATE POLICY rows ON access.authority_nonce_archive AS PERMISSIVE USING (true);
CREATE POLICY domain_scope ON access.authority_nonce_archive AS RESTRICTIVE
  USING (domain_id = (SELECT access.domain_scope()))
  WITH CHECK (domain_id = (SELECT access.domain_scope()));
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.authority_nonce_archive
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.authority_nonce_archive
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
GRANT SELECT ON access.authority_nonce_archive TO access_app, access_sequencer;
GRANT SELECT, INSERT ON access.authority_nonce_archive TO access_archive;
GRANT SELECT ON access.authority_nonce TO access_archive;

-- TI-RT3: a nonce closed in the hot rows or the archive stays closed
CREATE OR REPLACE FUNCTION access.nonce_sequence() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM access.authority_nonce n
             WHERE n.domain_id = NEW.domain_id AND n.nonce = NEW.nonce
               AND (n.outcome <> 'require_action' OR n.actor <> NEW.actor
                    OR n.intent_digest <> NEW.intent_digest))
     OR EXISTS (SELECT 1 FROM access.authority_nonce_archive a
             WHERE a.domain_id = NEW.domain_id AND a.nonce = NEW.nonce
               AND (a.outcome <> 'require_action' OR a.actor <> NEW.actor
                    OR a.intent_digest <> NEW.intent_digest)) THEN
    RAISE EXCEPTION 'nonce closed or bound to another intent' USING ERRCODE = 'unique_violation';
  END IF;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION access.nonce_sequence() FROM PUBLIC;

RESET ROLE;
