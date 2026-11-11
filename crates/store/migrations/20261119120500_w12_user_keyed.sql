-- E52, E59, E66, OP-74, OP-78, Ek C C.1.1 (2): the operator's side of the user-keyed domain. The
-- person's KEK never reaches it; it keeps the wrapped class DEKs and record keys it holds, where
-- every other wrapped copy is (recovery vault, TEE jobs, devices), and the erasure_log. A copy is
-- destroyed by zeroing what is held and stamping it; it never returns and no row is deleted.
SET LOCAL ROLE access_migrator;

CREATE TABLE access.user_keyed_copies (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  subject_id uuid NOT NULL,
  class text NOT NULL CHECK (class ~ '^one_[a-z_]{1,40}$' AND class <> 'one_training_lineage'),
  record_key text NOT NULL DEFAULT '' CHECK (record_key ~ '^[A-Za-z0-9_-]{0,64}$'),
  holder text NOT NULL CHECK (holder IN ('server', 'vault', 'tee', 'device')),
  holder_id text NOT NULL DEFAULT '' CHECK (holder_id ~ '^[A-Za-z0-9_.:-]{0,128}$'),
  wrapped bytea CHECK (octet_length(wrapped) <= 1024),
  created_at timestamptz NOT NULL DEFAULT now(),
  destroyed_at timestamptz,
  CHECK (destroyed_at IS NULL OR wrapped IS NULL),
  CHECK (holder IN ('server', 'vault') OR wrapped IS NULL),
  CHECK (holder NOT IN ('server', 'vault') OR wrapped IS NOT NULL OR destroyed_at IS NOT NULL),
  PRIMARY KEY (tenant_id, realm_id, subject_id, class, record_key, holder, holder_id)
);

CREATE TABLE access.user_keyed_erasures (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  erasure_id uuid NOT NULL DEFAULT uuidv7(),
  subject_id uuid NOT NULL,
  target text NOT NULL CHECK (target IN ('record', 'class', 'account')),
  class text CHECK (class ~ '^one_[a-z_]{1,40}$'),
  record_key text CHECK (record_key ~ '^[A-Za-z0-9_-]{1,64}$'),
  state text NOT NULL CHECK (state IN ('applied', 'pending_devices', 'pending_hold')),
  waiting text[] NOT NULL DEFAULT '{}',
  requested_at timestamptz NOT NULL DEFAULT now(),
  closed_at timestamptz,
  CHECK ((state = 'applied') = (closed_at IS NOT NULL)),
  CHECK ((state = 'pending_devices') = (cardinality(waiting) > 0)),
  CHECK ((target = 'account') = (class IS NULL)),
  CHECK ((target = 'record') = (record_key IS NOT NULL)),
  PRIMARY KEY (tenant_id, realm_id, erasure_id)
);

-- OP-42, OP-78 m.2: a destroyed copy never returns; an entry only moves forward and closes once
CREATE FUNCTION access.user_keyed_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' THEN
    RAISE EXCEPTION '%: % is not allowed', TG_TABLE_NAME, TG_OP USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF TG_TABLE_NAME = 'user_keyed_copies' THEN
    IF ROW(NEW.tenant_id, NEW.realm_id, NEW.subject_id, NEW.class, NEW.record_key, NEW.holder, NEW.holder_id, NEW.created_at)
       IS DISTINCT FROM ROW(OLD.tenant_id, OLD.realm_id, OLD.subject_id, OLD.class, OLD.record_key, OLD.holder, OLD.holder_id, OLD.created_at)
       OR OLD.destroyed_at IS NOT NULL OR NEW.destroyed_at IS NULL THEN
      RAISE EXCEPTION 'user_keyed_copies: a copy is only destroyed, once' USING ERRCODE = 'insufficient_privilege';
    END IF;
  ELSE
    IF ROW(NEW.tenant_id, NEW.realm_id, NEW.erasure_id, NEW.subject_id, NEW.target, NEW.class, NEW.record_key, NEW.requested_at)
       IS DISTINCT FROM ROW(OLD.tenant_id, OLD.realm_id, OLD.erasure_id, OLD.subject_id, OLD.target, OLD.class, OLD.record_key, OLD.requested_at)
       OR OLD.state = 'applied'
       OR (OLD.state = 'pending_devices' AND NEW.state = 'pending_hold')
       OR (NEW.state = 'pending_devices' AND OLD.state = 'pending_devices' AND NOT (NEW.waiting <@ OLD.waiting)) THEN
      RAISE EXCEPTION 'user_keyed_erasures: an entry only moves forward' USING ERRCODE = 'insufficient_privilege';
    END IF;
  END IF;
  RETURN NEW;
END
$$;

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['user_keyed_copies', 'user_keyed_erasures'] LOOP
    EXECUTE format('ALTER TABLE access.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE access.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON access.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY rows ON access.%I AS PERMISSIVE USING (true)', t);
    EXECUTE format('CREATE POLICY tenant_scope ON access.%I AS RESTRICTIVE TO access_app '
                   'USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope())) '
                   'WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))', t);
    EXECUTE format('CREATE TRIGGER user_keyed_transition BEFORE UPDATE OR DELETE ON access.%I '
                   'FOR EACH ROW EXECUTE FUNCTION access.user_keyed_transition()', t);
    EXECUTE format('CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.%I '
                   'FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation()', t);
  END LOOP;
END
$$;
REVOKE ALL ON FUNCTION access.user_keyed_transition() FROM PUBLIC;
GRANT SELECT, INSERT ON access.user_keyed_copies, access.user_keyed_erasures TO access_app;
GRANT UPDATE (wrapped, destroyed_at) ON access.user_keyed_copies TO access_app;
GRANT UPDATE (state, waiting, closed_at) ON access.user_keyed_erasures TO access_app;

RESET ROLE;
