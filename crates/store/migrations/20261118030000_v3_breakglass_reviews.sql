-- OP-157 m.3 (h), §12.3.8 (4), (5), TN-93: each use of a break-glass Grant and what became of
-- it. A use is recorded pending when its authority event arrives; it becomes overdue when no
-- other Party reviewed it within the realm's review window, and reviewed under a committed
-- idp.org.breakglass_review ALLOW that classifies it as a drill, an emergency or a misuse. Each
-- change is a new version of the use's row; nothing is deleted (OP-73). A review grants nothing.
SET LOCAL ROLE access_migrator;

CREATE TABLE access.breakglass_reviews (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  exercise bytea NOT NULL CHECK (octet_length(exercise) = 32),
  version bigint NOT NULL CHECK (version >= 1),
  state text NOT NULL CHECK (state IN ('pending', 'overdue', 'reviewed')),
  drill boolean NOT NULL,
  grant_id bytea NOT NULL CHECK (octet_length(grant_id) = 16),
  actor bytea NOT NULL CHECK (octet_length(actor) = 16),
  subject bytea CHECK (subject IS NULL OR octet_length(subject) = 16),
  used_at_ms bigint NOT NULL CHECK (used_at_ms >= 0),
  due_at_ms bigint NOT NULL CHECK (due_at_ms >= used_at_ms),
  classification text CHECK (classification IN ('drill', 'emergency', 'misuse')),
  reviewer bytea CHECK (reviewer IS NULL OR octet_length(reviewer) = 16),
  domain_id bytea,
  decision_pos bigint,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, exercise, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos),
  CHECK ((state = 'reviewed') = (classification IS NOT NULL AND reviewer IS NOT NULL
                                 AND domain_id IS NOT NULL AND decision_pos IS NOT NULL)),
  CHECK (reviewer IS NULL OR reviewer <> actor)
);
CREATE INDEX breakglass_reviews_due ON access.breakglass_reviews (tenant_id, realm_id, due_at_ms);

CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.breakglass_reviews
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.breakglass_reviews
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
ALTER TABLE access.breakglass_reviews ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.breakglass_reviews FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.breakglass_reviews FROM PUBLIC;
CREATE POLICY rows ON access.breakglass_reviews AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.breakglass_reviews AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()));
GRANT SELECT, INSERT ON access.breakglass_reviews TO access_app;

RESET ROLE;
