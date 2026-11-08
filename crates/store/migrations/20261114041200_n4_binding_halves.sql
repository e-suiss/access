-- §12.1.1, §12.1.3, TN-2, TN-65, MD-5, OP-153 m.3 (m): a cross-realm IdentityBinding is two
-- halves, each kept in its own realm and committed there; no row names the other realm's
-- account (no cross-tenant FK, rule 6). A half carries only digests of the secrets the person
-- carried between the realms. One half alone binds nothing. Nothing is deleted (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.identity_binding_halves (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  binding_id uuid NOT NULL,
  subject_id uuid NOT NULL,
  role text NOT NULL CHECK (role IN ('offer', 'accept')),
  proof text NOT NULL CHECK (proof IN ('invite_token', 'admin_exercise', 'verified_idp_subject')),
  -- pii:none
  secret_hash bytea NOT NULL CHECK (octet_length(secret_hash) = 32),
  -- pii:none
  peer_evidence bytea CHECK (octet_length(peer_evidence) = 32),
  state text NOT NULL CHECK (state IN ('offered', 'committed', 'ended')),
  created_ms bigint NOT NULL CHECK (created_ms > 0),
  expires_ms bigint NOT NULL,
  committed_ms bigint,
  ended_ms bigint,
  CHECK (expires_ms > created_ms AND expires_ms <= created_ms + 600000),
  CHECK (state <> 'offered' OR (committed_ms IS NULL AND ended_ms IS NULL)),
  CHECK ((committed_ms IS NULL) = (peer_evidence IS NULL)),
  CHECK (role = 'offer' OR state <> 'offered'),
  CHECK ((state = 'ended') = (ended_ms IS NOT NULL)),
  PRIMARY KEY (tenant_id, realm_id, binding_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE INDEX identity_binding_halves_subject
  ON access.identity_binding_halves (tenant_id, realm_id, subject_id);

CREATE FUNCTION access.identity_binding_half_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE'
     OR (NEW.tenant_id, NEW.realm_id, NEW.binding_id, NEW.subject_id, NEW.role, NEW.proof,
         NEW.secret_hash, NEW.created_ms, NEW.expires_ms)
        IS DISTINCT FROM (OLD.tenant_id, OLD.realm_id, OLD.binding_id, OLD.subject_id, OLD.role,
                          OLD.proof, OLD.secret_hash, OLD.created_ms, OLD.expires_ms)
     OR NOT ((OLD.state = 'offered' AND NEW.state IN ('committed', 'ended'))
             OR (OLD.state = 'committed' AND NEW.state = 'ended'))
     OR (OLD.state = 'committed'
         AND (NEW.peer_evidence, NEW.committed_ms) IS DISTINCT FROM (OLD.peer_evidence, OLD.committed_ms)) THEN
    RAISE EXCEPTION 'identity_binding_halves: a half is committed once and ends once'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER identity_binding_half_transition BEFORE UPDATE OR DELETE
  ON access.identity_binding_halves
  FOR EACH ROW EXECUTE FUNCTION access.identity_binding_half_transition();

ALTER TABLE access.identity_binding_halves ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.identity_binding_halves FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.identity_binding_halves FROM PUBLIC;
CREATE POLICY rows ON access.identity_binding_halves AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.identity_binding_halves AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()));
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.identity_binding_halves
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

REVOKE ALL ON FUNCTION access.identity_binding_half_transition() FROM PUBLIC;
GRANT SELECT, INSERT ON access.identity_binding_halves TO access_app;
GRANT UPDATE (peer_evidence, state, committed_ms, ended_ms) ON access.identity_binding_halves
  TO access_app;

RESET ROLE;
