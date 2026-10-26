-- §17.1.4, T27, T39, CR-32, OP-73, OP-135: encrypted bodies, content-addressed; shredding
-- destroys the key, never the row
SET LOCAL ROLE access_migrator;

CREATE TABLE access.body_store (
  domain_id bytea NOT NULL,
  body_commit bytea NOT NULL CHECK (octet_length(body_commit) = 32),
  kek_id text NOT NULL CHECK (kek_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
  wrapped_dek bytea,
  nonce bytea,
  ciphertext bytea,
  stored_at timestamptz NOT NULL DEFAULT now(),
  shredded_at timestamptz,
  CHECK ((shredded_at IS NULL) = (wrapped_dek IS NOT NULL AND nonce IS NOT NULL AND ciphertext IS NOT NULL)),
  CHECK (shredded_at IS NOT NULL OR octet_length(nonce) = 12),
  PRIMARY KEY (domain_id, body_commit),
  FOREIGN KEY (domain_id) REFERENCES access.authority_domain (domain_id)
);

-- OP-73: only two changes are allowed: rewrapping under another KEK, and shredding once
CREATE FUNCTION access.body_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' THEN
    RAISE EXCEPTION 'body_store: % is not allowed', TG_OP USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.shredded_at IS NOT NULL
     OR NEW.domain_id IS DISTINCT FROM OLD.domain_id
     OR NEW.body_commit IS DISTINCT FROM OLD.body_commit
     OR NEW.stored_at IS DISTINCT FROM OLD.stored_at THEN
    RAISE EXCEPTION 'body_store: a shredded body or its identity never changes' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NEW.shredded_at IS NOT NULL THEN
    IF NEW.wrapped_dek IS NOT NULL OR NEW.nonce IS NOT NULL OR NEW.ciphertext IS NOT NULL THEN
      RAISE EXCEPTION 'body_store: shredding removes the key and the ciphertext' USING ERRCODE = 'insufficient_privilege';
    END IF;
  ELSIF NEW.nonce IS DISTINCT FROM OLD.nonce OR NEW.ciphertext IS DISTINCT FROM OLD.ciphertext THEN
    RAISE EXCEPTION 'body_store: rewrapping changes only the wrapped key' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER body_transition BEFORE UPDATE OR DELETE ON access.body_store
  FOR EACH ROW EXECUTE FUNCTION access.body_transition();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.body_store
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

ALTER TABLE access.body_store ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.body_store FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.body_store FROM PUBLIC;
CREATE POLICY rows ON access.body_store AS PERMISSIVE USING (true);
CREATE POLICY domain_scope ON access.body_store AS RESTRICTIVE
  USING (domain_id = (SELECT access.domain_scope()))
  WITH CHECK (domain_id = (SELECT access.domain_scope()));

REVOKE ALL ON FUNCTION access.body_transition() FROM PUBLIC;
GRANT SELECT ON access.body_store TO access_app, access_sequencer;
GRANT INSERT ON access.body_store TO access_sequencer;
GRANT UPDATE (kek_id, wrapped_dek, nonce, ciphertext, shredded_at) ON access.body_store TO access_sequencer;

RESET ROLE;
