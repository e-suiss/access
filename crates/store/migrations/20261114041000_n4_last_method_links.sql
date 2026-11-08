-- TN-68, OP-153 m.15 (g): a live linked sign-in is a usable method. The last-method rule counts
-- it next to active credentials and proven mailboxes, and ending the last live link of a live
-- account by unlinking is refused like revoking its last credential. A link a combination moves
-- to the surviving account is not a removal (OP-153 m.3 (m)).
SET LOCAL ROLE access_migrator;

CREATE OR REPLACE FUNCTION access.keep_last_method() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM access.identity_subjects s
              WHERE s.tenant_id = NEW.tenant_id AND s.realm_id = NEW.realm_id
                AND s.subject_id = NEW.subject_id AND s.status NOT IN ('tombstone', 'purging'))
     AND NOT EXISTS (SELECT 1 FROM access.identity_credentials c
                      WHERE c.tenant_id = NEW.tenant_id AND c.realm_id = NEW.realm_id
                        AND c.subject_id = NEW.subject_id AND c.status = 'active')
     AND NOT EXISTS (SELECT 1 FROM access.identity_mailboxes m
                       JOIN access.identity_identifiers i
                         ON i.tenant_id = m.tenant_id AND i.realm_id = m.realm_id
                        AND i.identifier_id = m.identifier_id
                      WHERE m.tenant_id = NEW.tenant_id AND m.realm_id = NEW.realm_id
                        AND m.subject_id = NEW.subject_id AND i.status = 'active')
     AND NOT EXISTS (SELECT 1 FROM access.identity_federated f
                      WHERE f.tenant_id = NEW.tenant_id AND f.realm_id = NEW.realm_id
                        AND f.subject_id = NEW.subject_id AND f.ended_ms IS NULL) THEN
    RAISE EXCEPTION 'the last authentication method stays (TN-68)'
      USING ERRCODE = 'check_violation', CONSTRAINT = 'keep_last_method';
  END IF;
  RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER keep_last_method AFTER UPDATE OF ended_ms ON access.identity_federated
  DEFERRABLE INITIALLY IMMEDIATE
  FOR EACH ROW WHEN (OLD.ended_ms IS NULL AND NEW.ended_ms IS NOT NULL
                     AND NEW.end_reason = 'unlinked')
  EXECUTE FUNCTION access.keep_last_method();

REVOKE ALL ON FUNCTION access.keep_last_method() FROM PUBLIC;

RESET ROLE;
