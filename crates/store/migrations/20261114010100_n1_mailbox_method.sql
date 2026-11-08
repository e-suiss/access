-- TN-64, TNI-5, TN-68, OP-153 m.3 (g): a proven mailbox is a usable method. When the owner of a
-- never-activated account proves the address, every credential set before the proof dies; the
-- account keeps its proven address as its method, so the last-method rule still holds.
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
                        AND m.subject_id = NEW.subject_id AND i.status = 'active') THEN
    RAISE EXCEPTION 'identity_credentials: the last authentication method stays (TN-68)'
      USING ERRCODE = 'check_violation', CONSTRAINT = 'keep_last_method';
  END IF;
  RETURN NULL;
END
$$;

REVOKE ALL ON FUNCTION access.keep_last_method() FROM PUBLIC;

RESET ROLE;
