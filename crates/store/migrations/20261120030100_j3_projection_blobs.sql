-- CR-43, OP-73, OP-159 m.3 (q), m.21 (g): projections larger than the 8192-byte header budget,
-- served by reference. A row is the artefact sealed under its own data key, which the domain's
-- token key wraps, with the audience the PEPs that may fetch it are checked against. When the
-- artefact expires its data key is destroyed and expired_at is set (crypto-shredding); the row
-- stays and the artefact can no longer be read.
SET LOCAL ROLE access_migrator;

CREATE TABLE access.projection_blobs (
  domain_id bytea NOT NULL CHECK (octet_length(domain_id) = 32),
  digest bytea NOT NULL CHECK (octet_length(digest) = 32),
  size bigint NOT NULL CHECK (size BETWEEN 1 AND 16777216),
  audience text[] NOT NULL CHECK (cardinality(audience) BETWEEN 1 AND 64),
  expires_at bigint NOT NULL CHECK (expires_at >= 0),
  wrapped_dek text CHECK (octet_length(wrapped_dek) BETWEEN 1 AND 256),
  nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
  -- pii:none
  ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) BETWEEN 17 AND 16777232),
  stored_at timestamptz NOT NULL DEFAULT now(),
  expired_at timestamptz,
  CHECK ((expired_at IS NULL) = (wrapped_dek IS NOT NULL)),
  PRIMARY KEY (domain_id, digest),
  FOREIGN KEY (domain_id) REFERENCES access.authority_domain (domain_id)
);

CREATE INDEX projection_blobs_live ON access.projection_blobs (domain_id, expires_at)
  WHERE expired_at IS NULL;

-- OP-73
CREATE FUNCTION access.projection_blob_expiry() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' THEN
    RAISE EXCEPTION 'projection_blobs: % is not allowed', TG_OP USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.expired_at IS NOT NULL
     OR NEW.expired_at IS NULL
     OR NEW.wrapped_dek IS NOT NULL
     OR NEW.domain_id IS DISTINCT FROM OLD.domain_id
     OR NEW.digest IS DISTINCT FROM OLD.digest
     OR NEW.size IS DISTINCT FROM OLD.size
     OR NEW.audience IS DISTINCT FROM OLD.audience
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
     OR NEW.nonce IS DISTINCT FROM OLD.nonce
     OR NEW.ciphertext IS DISTINCT FROM OLD.ciphertext
     OR NEW.stored_at IS DISTINCT FROM OLD.stored_at THEN
    RAISE EXCEPTION 'projection_blobs: only an expiry that destroys the data key is allowed' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER projection_blob_expiry BEFORE UPDATE OR DELETE ON access.projection_blobs
  FOR EACH ROW EXECUTE FUNCTION access.projection_blob_expiry();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.projection_blobs
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

ALTER TABLE access.projection_blobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.projection_blobs FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.projection_blobs FROM PUBLIC;
CREATE POLICY rows ON access.projection_blobs AS PERMISSIVE USING (true);
CREATE POLICY domain_scope ON access.projection_blobs AS RESTRICTIVE
  USING (domain_id = (SELECT access.domain_scope()))
  WITH CHECK (domain_id = (SELECT access.domain_scope()));

REVOKE ALL ON FUNCTION access.projection_blob_expiry() FROM PUBLIC;
GRANT SELECT, INSERT ON access.projection_blobs TO access_sequencer;
GRANT UPDATE (wrapped_dek, expired_at) ON access.projection_blobs TO access_sequencer;
GRANT SELECT ON access.projection_blobs TO access_app;

RESET ROLE;
