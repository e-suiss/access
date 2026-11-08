-- OP-153 m.3 (aa), OP-42, OP-74, T31, TN-76, TN-77, U58: the identity plane's PII vault. Every
-- identifier and profile field is sealed under a DEK of its subject and retention class, wrapped
-- by the realm KEK; lookup and uniqueness use the realm's keyed blind index, which outlives the
-- DEK as the peppered tombstone (TN-76 m.5). The `credential` class key is the subject's own DEK
-- in `identity_subjects`. Nothing here is ever deleted (OP-73).
SET LOCAL ROLE access_migrator;

-- OP-74 m.1: one key per subject and class; shredding it leaves the row and its `kek_id`
CREATE TABLE access.identity_subject_keys (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  subject_id uuid NOT NULL,
  class text NOT NULL CHECK (class IN ('profile', 'contact', 'security_history')),
  kek_id text NOT NULL CHECK (kek_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
  wrapped_dek bytea,
  created_at timestamptz NOT NULL DEFAULT now(),
  shredded_at timestamptz,
  CHECK ((shredded_at IS NULL) = (wrapped_dek IS NOT NULL)),
  PRIMARY KEY (tenant_id, realm_id, subject_id, class),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);

CREATE FUNCTION access.subject_key_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' THEN
    RAISE EXCEPTION 'identity_subject_keys: % is not allowed', TG_OP USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.realm_id IS DISTINCT FROM OLD.realm_id
     OR NEW.subject_id IS DISTINCT FROM OLD.subject_id OR NEW.class IS DISTINCT FROM OLD.class
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'identity_subject_keys: identity columns never change' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.shredded_at IS NOT NULL THEN
    RAISE EXCEPTION 'identity_subject_keys: a shredded key never returns' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER subject_key_transition BEFORE UPDATE OR DELETE ON access.identity_subject_keys
  FOR EACH ROW EXECUTE FUNCTION access.subject_key_transition();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.identity_subject_keys
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

-- TN-76 m.3, m.5: the sealed identifier; `value` stays only on rows written before the vault,
-- until the retention job seals them
ALTER TABLE access.identity_identifiers
  ALTER COLUMN value DROP NOT NULL,
  -- pii:none
  ADD COLUMN value_index bytea CHECK (value_index IS NULL OR octet_length(value_index) = 32),
  ADD COLUMN pii_class text CHECK (pii_class IS NULL OR pii_class IN ('profile', 'contact')),
  ADD COLUMN nonce bytea CHECK (nonce IS NULL OR octet_length(nonce) = 12),
  -- pii:contact
  ADD COLUMN ciphertext bytea,
  ADD CONSTRAINT identity_identifiers_sealed CHECK (
    (value IS NOT NULL AND value_index IS NULL AND pii_class IS NULL AND nonce IS NULL AND ciphertext IS NULL)
    OR (value IS NULL AND value_index IS NOT NULL AND pii_class IS NOT NULL AND nonce IS NOT NULL
        AND ciphertext IS NOT NULL)) NOT VALID;
ALTER TABLE access.identity_identifiers VALIDATE CONSTRAINT identity_identifiers_sealed;

-- OP-153 m.3 (aa): no new plaintext identifier, from any writer
CREATE FUNCTION access.identifier_sealed() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF NEW.value IS NOT NULL THEN
    RAISE EXCEPTION 'identity_identifiers: a new identifier is sealed (OP-153 m.3 (aa))'
      USING ERRCODE = 'check_violation', CONSTRAINT = 'identifier_sealed';
  END IF;
  IF TG_OP = 'UPDATE' AND OLD.value IS NULL AND (NEW.value_index IS DISTINCT FROM OLD.value_index
       OR NEW.nonce IS DISTINCT FROM OLD.nonce OR NEW.ciphertext IS DISTINCT FROM OLD.ciphertext
       OR NEW.pii_class IS DISTINCT FROM OLD.pii_class) THEN
    RAISE EXCEPTION 'identity_identifiers: a sealed identifier never changes' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF TG_OP = 'UPDATE' AND (NEW.kind IS DISTINCT FROM OLD.kind OR NEW.subject_id IS DISTINCT FROM OLD.subject_id) THEN
    RAISE EXCEPTION 'identity_identifiers: identity columns never change' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER identifier_sealed BEFORE INSERT OR UPDATE ON access.identity_identifiers
  FOR EACH ROW EXECUTE FUNCTION access.identifier_sealed();

-- OP-153 m.3 (aa), (q): profile fields, sealed under the subject's `profile` key; a change
-- supersedes the live row and keeps it
CREATE TABLE access.identity_profile_fields (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  field_id uuid NOT NULL DEFAULT uuidv7(),
  subject_id uuid NOT NULL,
  field text NOT NULL
    CHECK (field IN ('name', 'given_name', 'family_name', 'birthdate', 'locale', 'zoneinfo')),
  pii_class text NOT NULL DEFAULT 'profile' CHECK (pii_class = 'profile'),
  nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
  -- pii:profile
  ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) <= 4096),
  set_at timestamptz NOT NULL DEFAULT now(),
  superseded_at timestamptz,
  PRIMARY KEY (tenant_id, realm_id, field_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE UNIQUE INDEX identity_profile_fields_live
  ON access.identity_profile_fields (tenant_id, realm_id, subject_id, field) WHERE superseded_at IS NULL;

CREATE FUNCTION access.profile_field_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' THEN
    RAISE EXCEPTION 'identity_profile_fields: % is not allowed', TG_OP USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.superseded_at IS NOT NULL OR NEW.superseded_at IS NULL
     OR (NEW.tenant_id, NEW.realm_id, NEW.field_id, NEW.subject_id, NEW.field, NEW.pii_class, NEW.nonce,
         NEW.ciphertext, NEW.set_at)
        IS DISTINCT FROM (OLD.tenant_id, OLD.realm_id, OLD.field_id, OLD.subject_id, OLD.field,
                          OLD.pii_class, OLD.nonce, OLD.ciphertext, OLD.set_at) THEN
    RAISE EXCEPTION 'identity_profile_fields: a field is only superseded' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER profile_field_transition BEFORE UPDATE OR DELETE ON access.identity_profile_fields
  FOR EACH ROW EXECUTE FUNCTION access.profile_field_transition();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.identity_profile_fields
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['identity_subject_keys', 'identity_profile_fields'] LOOP
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

REVOKE ALL ON FUNCTION access.subject_key_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.identifier_sealed() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.profile_field_transition() FROM PUBLIC;
GRANT SELECT, INSERT ON access.identity_subject_keys, access.identity_profile_fields TO access_app;
GRANT UPDATE (kek_id, wrapped_dek, shredded_at) ON access.identity_subject_keys TO access_app;
GRANT UPDATE (superseded_at) ON access.identity_profile_fields TO access_app;
GRANT UPDATE (value, value_index, pii_class, nonce, ciphertext) ON access.identity_identifiers TO access_app;

RESET ROLE;
