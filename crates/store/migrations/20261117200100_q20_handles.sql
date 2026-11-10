-- OP-156 m.4 (Q20, appended), E56, Ek B 4330: handles. A claim names the person's Party, the
-- handle and the DID it must point at; a handle is claimed once per realm and never handed to
-- anyone else; a Suiss handle lives under its realm's own base, so no other realm can claim it
-- (TN-20: the only cross-tenant unique keys stay the global identifiers). Verification and retirement are rows of
-- their own; both tables only grow (OP-73). Host resolution reads the verified Suiss handles
-- across tenants for `/.well-known/access-handle`; nothing else.
SET LOCAL ROLE access_migrator;

CREATE TABLE access.handles (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  handle_id uuid NOT NULL DEFAULT uuidv7(),
  -- pii:none
  subject_id uuid NOT NULL,
  -- pii:none
  party bytea NOT NULL CHECK (octet_length(party) = 16),
  handle text NOT NULL CHECK (handle ~ '^[a-z0-9-]+(\.[a-z0-9-]+)+$' AND length(handle) <= 253),
  did text NOT NULL CHECK (did LIKE 'did:web:%' AND length(did) <= 512),
  kind text NOT NULL CHECK (kind IN ('suiss', 'own')),
  claimed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, handle_id),
  UNIQUE (tenant_id, realm_id, handle),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE INDEX handles_suiss ON access.handles (handle) WHERE kind = 'suiss';
CREATE INDEX handles_subject ON access.handles (tenant_id, realm_id, subject_id);

CREATE TABLE access.handle_events (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  handle_id uuid NOT NULL,
  event text NOT NULL CHECK (event IN ('verified', 'retired')),
  handle text NOT NULL,
  kind text NOT NULL CHECK (kind IN ('suiss', 'own')),
  at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, handle_id, event),
  FOREIGN KEY (tenant_id, realm_id, handle_id)
    REFERENCES access.handles (tenant_id, realm_id, handle_id)
);
CREATE INDEX handle_events_host ON access.handle_events (handle) WHERE kind = 'suiss';

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['handles', 'handle_events'] LOOP
    EXECUTE format('ALTER TABLE access.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE access.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON access.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY rows ON access.%I AS PERMISSIVE USING (true)', t);
    EXECUTE format('CREATE POLICY tenant_scope ON access.%I AS RESTRICTIVE TO access_app '
                   'USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope())) '
                   'WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))', t);
    EXECUTE format('CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.%I '
                   'FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation()', t);
    EXECUTE format('CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.%I '
                   'FOR EACH ROW EXECUTE FUNCTION access.reject_mutation()', t);
  END LOOP;
END
$$;

-- E56 (2): the router reads only Suiss handles
CREATE POLICY router_reads ON access.handles AS RESTRICTIVE TO access_router
  USING (kind = 'suiss') WITH CHECK (false);
CREATE POLICY router_reads ON access.handle_events AS RESTRICTIVE TO access_router
  USING (kind = 'suiss') WITH CHECK (false);

GRANT SELECT, INSERT ON access.handles, access.handle_events TO access_app;
GRANT SELECT (tenant_id, realm_id, handle_id, handle, did, kind) ON access.handles TO access_router;
GRANT SELECT (tenant_id, realm_id, handle_id, event, handle, kind) ON access.handle_events TO access_router;

RESET ROLE;
