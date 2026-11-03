-- §10.1.7, MD-5, OP-12, OP-42, OP-73, OP-135, OP-137, OP-145, OP-146 m.1 (I2), IDP-2, TN-2, TN-49,
-- TN-50, TN-68: identity subjects, login identifiers and the credential store, realm-local
SET LOCAL ROLE access_migrator;

-- IDP-2, TN-49: the internal id is a UUIDv7; the external one is its OP-137 permutation, never stored.
-- The subject's DEK is wrapped by the realm KEK (OP-42, OP-135 m.1); shredding it erases every
-- credential below it (OP-145 m.3).
CREATE TABLE access.identity_subjects (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  subject_id uuid NOT NULL DEFAULT uuidv7(),
  status text NOT NULL DEFAULT 'staged'
    CHECK (status IN ('staged', 'pending_user_action', 'active', 'locked', 'suspended',
                      'deactivated', 'tombstone', 'purging')),
  session_epoch bigint NOT NULL DEFAULT 0 CHECK (session_epoch >= 0),
  kek_id text NOT NULL CHECK (kek_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
  wrapped_dek bytea,
  created_at timestamptz NOT NULL DEFAULT now(),
  status_at timestamptz NOT NULL DEFAULT now(),
  shredded_at timestamptz,
  CHECK ((shredded_at IS NULL) = (wrapped_dek IS NOT NULL)),
  CHECK (shredded_at IS NULL OR status = 'purging'),
  PRIMARY KEY (tenant_id, realm_id, subject_id),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id)
);

-- TN-49: the chain, enforced against every writer
CREATE FUNCTION access.subject_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' THEN
    RAISE EXCEPTION 'identity_subjects: % is not allowed', TG_OP USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.realm_id IS DISTINCT FROM OLD.realm_id
     OR NEW.subject_id IS DISTINCT FROM OLD.subject_id OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'identity_subjects: identity columns never change' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NEW.session_epoch < OLD.session_epoch THEN
    RAISE EXCEPTION 'identity_subjects: session_epoch only grows' USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.shredded_at IS NOT NULL AND NEW.shredded_at IS DISTINCT FROM OLD.shredded_at THEN
    RAISE EXCEPTION 'identity_subjects: a shredded key never returns' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NEW.status IS DISTINCT FROM OLD.status AND NOT (OLD.status, NEW.status) IN (
       ('staged', 'pending_user_action'), ('pending_user_action', 'active'),
       ('active', 'locked'), ('locked', 'active'), ('active', 'suspended'), ('suspended', 'active'),
       ('locked', 'suspended'),
       ('staged', 'deactivated'), ('pending_user_action', 'deactivated'), ('active', 'deactivated'),
       ('locked', 'deactivated'), ('suspended', 'deactivated'), ('deactivated', 'active'),
       ('deactivated', 'tombstone'), ('tombstone', 'purging')) THEN
    RAISE EXCEPTION 'identity_subjects: % -> % is not a TN-49 transition', OLD.status, NEW.status
      USING ERRCODE = 'check_violation', CONSTRAINT = 'subject_transition';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER subject_transition BEFORE UPDATE OR DELETE ON access.identity_subjects
  FOR EACH ROW EXECUTE FUNCTION access.subject_transition();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.identity_subjects
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

-- §17.2.2, §17.2.5, MD-5, TN-2: case-insensitive and realm-scoped; never a global UNIQUE.
-- A tombstoned subject keeps its identifiers reserved (§12.3.1); only `released` frees one.
CREATE TABLE access.identity_identifiers (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  identifier_id uuid NOT NULL DEFAULT uuidv7(),
  subject_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('username', 'email', 'phone')),
  value text NOT NULL CHECK (char_length(value) BETWEEN 1 AND 320),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'released')),
  created_at timestamptz NOT NULL DEFAULT now(),
  released_at timestamptz,
  CHECK ((status = 'released') = (released_at IS NOT NULL)),
  PRIMARY KEY (tenant_id, realm_id, identifier_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE UNIQUE INDEX identity_identifiers_live
  ON access.identity_identifiers (tenant_id, realm_id, lower(value)) WHERE status = 'active';
CREATE INDEX identity_identifiers_subject ON access.identity_identifiers (tenant_id, realm_id, subject_id);

CREATE TRIGGER append_only_row BEFORE DELETE ON access.identity_identifiers
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.identity_identifiers
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

-- §10.1.7, MD-3, CR-37, OP-145: `algorithm` from day one; the secret is sealed under its own DEK,
-- wrapped by the subject's DEK (`kek_id` names it). `pepper_version` is reserved (OP-146 m.5 (l)).
CREATE TABLE access.identity_credentials (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  credential_id uuid NOT NULL DEFAULT uuidv7(),
  subject_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('password', 'webauthn', 'totp', 'recovery_code')),
  algorithm text NOT NULL CHECK (algorithm ~ '^[a-z0-9][a-z0-9_.-]{0,31}$'),
  kek_id text NOT NULL CHECK (kek_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
  wrapped_dek bytea NOT NULL,
  nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
  ciphertext bytea NOT NULL,
  pepper_version smallint CHECK (pepper_version > 0),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  revoked_at timestamptz,
  CHECK ((status = 'revoked') = (revoked_at IS NOT NULL)),
  PRIMARY KEY (tenant_id, realm_id, credential_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE INDEX identity_credentials_subject
  ON access.identity_credentials (tenant_id, realm_id, subject_id) WHERE status = 'active';

CREATE FUNCTION access.credential_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' THEN
    RAISE EXCEPTION 'identity_credentials: % is not allowed', TG_OP USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.realm_id IS DISTINCT FROM OLD.realm_id
     OR NEW.credential_id IS DISTINCT FROM OLD.credential_id OR NEW.subject_id IS DISTINCT FROM OLD.subject_id
     OR NEW.kind IS DISTINCT FROM OLD.kind OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'identity_credentials: identity columns never change' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.status = 'revoked' AND (NEW.status <> 'revoked' OR NEW.ciphertext IS DISTINCT FROM OLD.ciphertext) THEN
    RAISE EXCEPTION 'identity_credentials: a revoked credential stays revoked' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER credential_transition BEFORE UPDATE OR DELETE ON access.identity_credentials
  FOR EACH ROW EXECUTE FUNCTION access.credential_transition();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.identity_credentials
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

-- TN-68, §12.3.3: the last usable method of a live account cannot be removed
CREATE FUNCTION access.keep_last_method() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM access.identity_subjects s
              WHERE s.tenant_id = NEW.tenant_id AND s.realm_id = NEW.realm_id
                AND s.subject_id = NEW.subject_id AND s.status NOT IN ('tombstone', 'purging'))
     AND NOT EXISTS (SELECT 1 FROM access.identity_credentials c
                      WHERE c.tenant_id = NEW.tenant_id AND c.realm_id = NEW.realm_id
                        AND c.subject_id = NEW.subject_id AND c.status = 'active') THEN
    RAISE EXCEPTION 'identity_credentials: the last authentication method stays (TN-68)'
      USING ERRCODE = 'check_violation', CONSTRAINT = 'keep_last_method';
  END IF;
  RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER keep_last_method AFTER UPDATE OF status ON access.identity_credentials
  DEFERRABLE INITIALLY IMMEDIATE
  FOR EACH ROW WHEN (OLD.status = 'active' AND NEW.status <> 'active')
  EXECUTE FUNCTION access.keep_last_method();

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['identity_subjects', 'identity_identifiers', 'identity_credentials'] LOOP
    EXECUTE format('ALTER TABLE access.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE access.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON access.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY rows ON access.%I AS PERMISSIVE USING (true)', t);
    EXECUTE format('CREATE POLICY tenant_scope ON access.%I AS RESTRICTIVE TO access_app '
                   'USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope())) '
                   'WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))', t);
  END LOOP;
END
$$;

REVOKE ALL ON FUNCTION access.subject_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.credential_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.keep_last_method() FROM PUBLIC;
GRANT SELECT, INSERT ON access.identity_subjects, access.identity_identifiers, access.identity_credentials
  TO access_app;
GRANT UPDATE (status, status_at, session_epoch, kek_id, wrapped_dek, shredded_at)
  ON access.identity_subjects TO access_app;
GRANT UPDATE (status, released_at) ON access.identity_identifiers TO access_app;
GRANT UPDATE (algorithm, kek_id, wrapped_dek, nonce, ciphertext, pepper_version, status, last_used_at, revoked_at)
  ON access.identity_credentials TO access_app;

RESET ROLE;
