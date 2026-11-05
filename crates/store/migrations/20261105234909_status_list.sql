-- OP-150 m.3 (a), (s), §11.20: the Token Status Lists of a domain and their entry counters. A
-- projection family takes the next entry of the newest list that has room; a full list is
-- followed by the next one. A family's entry is set when the family is revoked
-- (projection_family.revoked_pos), so a list's bits at a position are read from the families,
-- and nothing here is ever cleared (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.status_list (
  domain_id bytea NOT NULL,
  list_no bigint NOT NULL CHECK (list_no >= 0),
  uri text NOT NULL CHECK (octet_length(uri) BETWEEN 1 AND 2048),
  capacity bigint NOT NULL CHECK (capacity > 0 AND capacity <= 33554432),
  allocated bigint NOT NULL DEFAULT 0 CHECK (allocated >= 0 AND allocated <= capacity),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (domain_id, list_no),
  UNIQUE (domain_id, uri)
);

-- Only the counter changes, and only upwards: an entry is never handed out twice.
CREATE FUNCTION access.status_list_allocate() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' THEN
    RAISE EXCEPTION 'status_list: rows are never deleted (OP-73)' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF (to_jsonb(OLD) - 'allocated') IS DISTINCT FROM (to_jsonb(NEW) - 'allocated') OR NEW.allocated < OLD.allocated THEN
    RAISE EXCEPTION 'status_list: only allocated may grow' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION access.status_list_allocate() FROM PUBLIC;

ALTER TABLE access.status_list ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.status_list FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.status_list FROM PUBLIC;
CREATE POLICY rows ON access.status_list AS PERMISSIVE USING (true);
CREATE POLICY domain_scope ON access.status_list AS RESTRICTIVE
  USING (domain_id = (SELECT access.domain_scope()))
  WITH CHECK (domain_id = (SELECT access.domain_scope()));
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.status_list
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER allocate_only BEFORE UPDATE OR DELETE ON access.status_list
  FOR EACH ROW EXECUTE FUNCTION access.status_list_allocate();

-- The binding-signed excerpt of the key that signed a publication, served beside it (CR-58 m.1).
ALTER TABLE access.status_list_publication
  ADD COLUMN excerpt bytea CHECK (excerpt IS NULL OR octet_length(excerpt) <= 65536);

-- SSF 1.0 §8.1.4: a stream's verification SET is queued like any event under its SSF type.
ALTER TABLE access.event_delivery DROP CONSTRAINT event_delivery_event_type_check;
ALTER TABLE access.event_delivery ADD CONSTRAINT event_delivery_event_type_check
  CHECK (event_type ~ '^urn:suiss:access:event:[a-z][a-z0-9_.-]{0,63}$'
         OR event_type = 'https://schemas.openid.net/secevent/ssf/event-type/verification');

CREATE INDEX projection_family_revoked ON access.projection_family (domain_id, status_uri, revoked_pos)
  WHERE status_uri IS NOT NULL AND revoked_pos IS NOT NULL;

GRANT SELECT, INSERT ON access.status_list TO access_sequencer;
GRANT UPDATE (allocated) ON access.status_list TO access_sequencer;
GRANT SELECT ON access.status_list TO access_app;

RESET ROLE;
