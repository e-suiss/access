-- OP-153 m.3 (bb), (cc), (dd), (ee); IDP-37, E60, TN-76, TN-78, OP-42, OP-74, OP-147: what the
-- identity plane keeps about privacy itself. Every table only grows (OP-73): a preference change
-- or acceptance is a new row, a deletion fact is written once and completed once, a data request
-- is answered once, a hold is lifted by its end time.
SET LOCAL ROLE access_migrator;

-- IDP-37, OP-153 m.3 (ee): one row per change; the latest per channel and topic is the state, the
-- rows are the history (Ek B 3849). Consent is never a decision input (IDP-37).
CREATE TABLE access.identity_preferences (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  change_id uuid NOT NULL DEFAULT uuidv7(),
  subject_id uuid NOT NULL,
  channel text NOT NULL CHECK (channel IN ('email', 'sms', 'call', 'push')),
  topic text NOT NULL CHECK (topic ~ '^[a-z][a-z0-9_.-]{0,63}$'),
  -- pii:none
  granted boolean NOT NULL,
  method text NOT NULL CHECK (method IN ('self_service', 'admin', 'import', 'app')),
  record_digest bytea NOT NULL CHECK (octet_length(record_digest) = 32),
  changed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, change_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE INDEX identity_preferences_subject
  ON access.identity_preferences (tenant_id, realm_id, subject_id, channel, topic, change_id);

-- IDP-37, E60, TN-132: a content-free acceptance of one document version; the text itself is
-- named by its digest only
CREATE TABLE access.identity_document_acceptances (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  acceptance_id uuid NOT NULL DEFAULT uuidv7(),
  subject_id uuid NOT NULL,
  document_type text NOT NULL CHECK (document_type ~ '^[a-z][a-z0-9_.-]{0,63}$'),
  version text NOT NULL CHECK (version ~ '^[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}$'),
  -- pii:none
  document_digest bytea NOT NULL CHECK (octet_length(document_digest) = 32),
  locale text NOT NULL CHECK (locale ~ '^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$'),
  method text NOT NULL CHECK (method IN ('click', 'checkbox', 'signature', 'import', 'app')),
  client text CHECK (client IS NULL OR char_length(client) BETWEEN 1 AND 255),
  record_digest bytea NOT NULL CHECK (octet_length(record_digest) = 32),
  accepted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, acceptance_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE INDEX identity_document_acceptances_subject
  ON access.identity_document_acceptances (tenant_id, realm_id, subject_id, document_type, acceptance_id);

-- OP-42, TN-78, OP-153 m.3 (bb): the one immutable deletion fact of a subject; the destruction
-- completes it once with its proof
CREATE TABLE access.identity_deletion_facts (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  -- pii:none
  subject_id uuid NOT NULL,
  source text NOT NULL CHECK (source IN ('admin', 'self_service', 'scim', 'inactivity')),
  requested_by text NOT NULL CHECK (char_length(requested_by) BETWEEN 1 AND 255),
  exercise_id bytea CHECK (exercise_id IS NULL OR octet_length(exercise_id) = 32),
  deleted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  destroy_after timestamptz NOT NULL,
  destroyed_at timestamptz,
  destruction_proof bytea CHECK (destruction_proof IS NULL OR octet_length(destruction_proof) = 32),
  CHECK (destroy_after >= deleted_at + interval '24 hours'),
  CHECK ((destroyed_at IS NULL) = (destruction_proof IS NULL)),
  PRIMARY KEY (tenant_id, realm_id, subject_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE INDEX identity_deletion_facts_due
  ON access.identity_deletion_facts (tenant_id, realm_id, destroy_after) WHERE destroyed_at IS NULL;

CREATE FUNCTION access.deletion_fact_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' THEN
    RAISE EXCEPTION 'identity_deletion_facts: % is not allowed', TG_OP USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.destroyed_at IS NOT NULL OR NEW.destroyed_at IS NULL
     OR (NEW.tenant_id, NEW.realm_id, NEW.subject_id, NEW.source, NEW.requested_by, NEW.exercise_id,
         NEW.deleted_at, NEW.destroy_after)
        IS DISTINCT FROM (OLD.tenant_id, OLD.realm_id, OLD.subject_id, OLD.source, OLD.requested_by,
                          OLD.exercise_id, OLD.deleted_at, OLD.destroy_after) THEN
    RAISE EXCEPTION 'identity_deletion_facts: a deletion fact is only completed, once' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER deletion_fact_transition BEFORE UPDATE OR DELETE ON access.identity_deletion_facts
  FOR EACH ROW EXECUTE FUNCTION access.deletion_fact_transition();

-- TN-78, KVKK m.13: a data subject request is answered within 30 days (Ek B 3953)
CREATE TABLE access.identity_data_requests (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  request_id uuid NOT NULL DEFAULT uuidv7(),
  -- pii:none
  subject_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('access', 'portability', 'erasure', 'rectification', 'objection')),
  received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  due_at timestamptz NOT NULL,
  answered_at timestamptz,
  outcome text CHECK (outcome IS NULL OR outcome IN ('fulfilled', 'partly_retained', 'refused')),
  CHECK (due_at > received_at AND due_at <= received_at + interval '30 days'),
  CHECK ((answered_at IS NULL) = (outcome IS NULL)),
  PRIMARY KEY (tenant_id, realm_id, request_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE INDEX identity_data_requests_open
  ON access.identity_data_requests (tenant_id, realm_id, due_at) WHERE answered_at IS NULL;

CREATE FUNCTION access.data_request_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' THEN
    RAISE EXCEPTION 'identity_data_requests: % is not allowed', TG_OP USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.answered_at IS NOT NULL OR NEW.answered_at IS NULL
     OR (NEW.tenant_id, NEW.realm_id, NEW.request_id, NEW.subject_id, NEW.kind, NEW.received_at, NEW.due_at)
        IS DISTINCT FROM (OLD.tenant_id, OLD.realm_id, OLD.request_id, OLD.subject_id, OLD.kind,
                          OLD.received_at, OLD.due_at) THEN
    RAISE EXCEPTION 'identity_data_requests: a request is only answered, once' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER data_request_transition BEFORE UPDATE OR DELETE ON access.identity_data_requests
  FOR EACH ROW EXECUTE FUNCTION access.data_request_transition();

-- OP-74 m.3, OP-147 m.2: litigation, regulator and law-enforcement holds; a hold ends by its
-- `until`, never by removal
CREATE TABLE access.retention_holds (
  tenant_id uuid NOT NULL,
  hold_id uuid NOT NULL DEFAULT uuidv7(),
  scope text NOT NULL CHECK (scope IN ('subject', 'classes', 'tenant')),
  realm_id uuid,
  subject_id uuid,
  classes text[] NOT NULL DEFAULT '{}',
  kind text NOT NULL CHECK (kind IN ('litigation', 'regulator', 'law_enforcement')),
  suspicious_activity boolean NOT NULL DEFAULT false,
  placed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  until timestamptz,
  CHECK ((scope = 'subject') = (subject_id IS NOT NULL AND realm_id IS NOT NULL)),
  CHECK (scope = 'classes' OR cardinality(classes) = 0),
  PRIMARY KEY (tenant_id, hold_id),
  FOREIGN KEY (tenant_id) REFERENCES access.tenants (tenant_id)
);

CREATE FUNCTION access.hold_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' THEN
    RAISE EXCEPTION 'retention_holds: % is not allowed', TG_OP USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.until IS NOT NULL
     OR (NEW.tenant_id, NEW.hold_id, NEW.scope, NEW.realm_id, NEW.subject_id, NEW.classes, NEW.kind,
         NEW.suspicious_activity, NEW.placed_at)
        IS DISTINCT FROM (OLD.tenant_id, OLD.hold_id, OLD.scope, OLD.realm_id, OLD.subject_id,
                          OLD.classes, OLD.kind, OLD.suspicious_activity, OLD.placed_at) THEN
    RAISE EXCEPTION 'retention_holds: a hold only gains its end, once' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER hold_transition BEFORE UPDATE OR DELETE ON access.retention_holds
  FOR EACH ROW EXECUTE FUNCTION access.hold_transition();

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['identity_preferences', 'identity_document_acceptances',
                           'identity_deletion_facts', 'identity_data_requests'] LOOP
    EXECUTE format('ALTER TABLE access.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE access.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON access.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY rows ON access.%I AS PERMISSIVE USING (true)', t);
    EXECUTE format('CREATE POLICY tenant_scope ON access.%I AS RESTRICTIVE TO access_app '
                   'USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope())) '
                   'WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))', t);
    EXECUTE format('CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.%I '
                   'FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation()', t);
  END LOOP;
END
$$;

CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.identity_preferences
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.identity_document_acceptances
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

ALTER TABLE access.retention_holds ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.retention_holds FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.retention_holds FROM PUBLIC;
CREATE POLICY rows ON access.retention_holds AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.retention_holds AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope())
         AND (realm_id IS NULL OR (SELECT access.realm_scope()) IS NULL OR realm_id = (SELECT access.realm_scope())))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope())
              AND (realm_id IS NULL OR realm_id = (SELECT access.realm_scope())));
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.retention_holds
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

REVOKE ALL ON FUNCTION access.deletion_fact_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.data_request_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.hold_transition() FROM PUBLIC;
GRANT SELECT, INSERT ON access.identity_preferences, access.identity_document_acceptances,
  access.identity_deletion_facts, access.identity_data_requests, access.retention_holds TO access_app;
GRANT UPDATE (destroyed_at, destruction_proof) ON access.identity_deletion_facts TO access_app;
GRANT UPDATE (answered_at, outcome) ON access.identity_data_requests TO access_app;
GRANT UPDATE (until) ON access.retention_holds TO access_app;

RESET ROLE;
