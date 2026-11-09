-- OP-154 m.3 (c), (e), (g), AG-20, AG-41: the identity plane's agent records. An agent is its own
-- Party of the realm's governing domain (actor_kind agent); these rows are what the identity
-- plane needs to export it as Claims, keep its human sponsors and list it in the registry. They
-- hold no authority (AG-19). Nothing is deleted (OP-73): a sponsorship ends by its end time, an
-- agent is suspended or retired, a template gets a new version.
SET LOCAL ROLE access_migrator;

-- OP-154 m.3 (c), AG-20
CREATE TABLE access.agents (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  party bytea NOT NULL CHECK (octet_length(party) = 16),
  operator bytea NOT NULL CHECK (octet_length(operator) = 16),
  agent_kind text NOT NULL CHECK (agent_kind IN ('cloud', 'local', 'enterprise', 'robot')),
  display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 128),
  description text CHECK (description IS NULL OR char_length(description) <= 1024),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'retired')),
  registered_exercise bytea NOT NULL CHECK (octet_length(registered_exercise) = 32),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  status_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, party)
);

-- AG-41, OP-154 m.3 (e), SI-21: one row per sponsorship episode
CREATE TABLE access.agent_sponsors (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  sponsorship_id uuid NOT NULL DEFAULT uuidv7(),
  agent bytea NOT NULL CHECK (octet_length(agent) = 16),
  subject_id uuid NOT NULL,
  assigned_exercise bytea NOT NULL CHECK (octet_length(assigned_exercise) = 32),
  assigned_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  ended_at timestamptz,
  ended_by text CHECK (ended_by IS NULL OR ended_by IN ('remove', 'account', 'retire')),
  ended_exercise bytea CHECK (ended_exercise IS NULL OR octet_length(ended_exercise) = 32),
  CHECK ((ended_at IS NULL) = (ended_by IS NULL)),
  PRIMARY KEY (tenant_id, realm_id, sponsorship_id),
  FOREIGN KEY (tenant_id, realm_id, agent) REFERENCES access.agents (tenant_id, realm_id, party),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE UNIQUE INDEX agent_sponsors_open
  ON access.agent_sponsors (tenant_id, realm_id, agent, subject_id) WHERE ended_at IS NULL;
CREATE INDEX agent_sponsors_subject
  ON access.agent_sponsors (tenant_id, realm_id, subject_id) WHERE ended_at IS NULL;

-- OP-154 m.3 (g), §13.7.6: a template is versioned; a new definition is a new version
CREATE TABLE access.agent_templates (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  name text NOT NULL CHECK (name ~ '^[a-z][a-z0-9_-]{0,63}$'),
  version bigint NOT NULL CHECK (version >= 1),
  content bytea NOT NULL CHECK (octet_length(content) BETWEEN 1 AND 65536),
  defined_exercise bytea NOT NULL CHECK (octet_length(defined_exercise) = 32),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, name, version)
);

-- OP-73: an episode only ends, once
CREATE FUNCTION access.agent_sponsor_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF OLD.ended_at IS NOT NULL THEN
    RAISE EXCEPTION 'sponsorship transition not allowed' USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER agent_sponsor_transition BEFORE UPDATE ON access.agent_sponsors
  FOR EACH ROW EXECUTE FUNCTION access.agent_sponsor_transition();

-- OP-73: a retired agent stays retired
CREATE FUNCTION access.agent_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF OLD.status = 'retired' THEN
    RAISE EXCEPTION 'agent transition not allowed' USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER agent_transition BEFORE UPDATE ON access.agents
  FOR EACH ROW EXECUTE FUNCTION access.agent_transition();

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['agents', 'agent_sponsors', 'agent_templates'] LOOP
    EXECUTE format('ALTER TABLE access.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE access.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON access.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY rows ON access.%I AS PERMISSIVE USING (true)', t);
    EXECUTE format('CREATE POLICY tenant_scope ON access.%I AS RESTRICTIVE TO access_app '
                   'USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope())) '
                   'WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))', t);
    EXECUTE format('CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.%I '
                   'FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation()', t);
    EXECUTE format('CREATE TRIGGER no_delete BEFORE DELETE ON access.%I '
                   'FOR EACH ROW EXECUTE FUNCTION access.reject_mutation()', t);
  END LOOP;
END
$$;

REVOKE ALL ON FUNCTION access.agent_sponsor_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.agent_transition() FROM PUBLIC;
GRANT SELECT, INSERT ON access.agents, access.agent_sponsors, access.agent_templates TO access_app;
GRANT UPDATE (display_name, description, status, status_at) ON access.agents TO access_app;
GRANT UPDATE (ended_at, ended_by, ended_exercise) ON access.agent_sponsors TO access_app;

RESET ROLE;
