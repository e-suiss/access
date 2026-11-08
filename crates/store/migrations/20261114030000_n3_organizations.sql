-- TN-5, TN-89, TN-90, TN-91, OP-153 m.3 (b), (o), (p): the identity plane's side of B2B
-- organizations. An organization is a Party of the realm's governing domain with an Anchor; these
-- tables hold what the identity plane needs to route, invite and verify. Nothing is deleted
-- (OP-73): a membership, invitation, domain claim or organization ends by its end time.
SET LOCAL ROLE access_migrator;

-- TN-5, TN-3, OP-153 m.3 (b): routing is by organization id, never by e-mail domain
CREATE TABLE access.organizations (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  org_id uuid NOT NULL DEFAULT uuidv7(),
  party bytea NOT NULL CHECK (octet_length(party) = 16),
  display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 128),
  created_exercise bytea NOT NULL CHECK (octet_length(created_exercise) = 32),
  hrd boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  ended_at timestamptz,
  PRIMARY KEY (tenant_id, realm_id, org_id),
  UNIQUE (tenant_id, realm_id, party)
);

-- §12.3.8, TN-91, OP-153 m.3 (p): one row per membership episode; an owner is a root member
CREATE TABLE access.org_memberships (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  membership_id uuid NOT NULL DEFAULT uuidv7(),
  org_id uuid NOT NULL,
  subject_id uuid NOT NULL,
  source text NOT NULL CHECK (source IN ('founder', 'invite', 'scim', 'jit', 'domain_autojoin')),
  owner boolean NOT NULL DEFAULT false,
  role_name text CHECK (role_name IS NULL OR char_length(role_name) BETWEEN 1 AND 128),
  role_version bigint CHECK (role_version IS NULL OR role_version >= 1),
  grant_id bytea CHECK (grant_id IS NULL OR octet_length(grant_id) = 16),
  joined_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  ended_at timestamptz,
  ended_by text CHECK (ended_by IS NULL OR ended_by IN ('remove', 'scim', 'sweep', 'delete', 'leave')),
  CHECK ((ended_at IS NULL) = (ended_by IS NULL)),
  CHECK ((role_name IS NULL) = (role_version IS NULL)),
  PRIMARY KEY (tenant_id, realm_id, membership_id),
  FOREIGN KEY (tenant_id, realm_id, org_id)
    REFERENCES access.organizations (tenant_id, realm_id, org_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE UNIQUE INDEX org_memberships_open
  ON access.org_memberships (tenant_id, realm_id, org_id, subject_id) WHERE ended_at IS NULL;

-- TN-91, OP-153 m.3 (p): an Anchor without an owner cannot be expressed, so on every path
-- (SCIM, sweep, delete, removal) the last active owner's membership does not end or lose its
-- ownership while the organization lives; only the columns that end an episode may change
CREATE FUNCTION access.org_membership_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'memberships are never deleted' USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.ended_at IS NOT NULL
     OR NEW.org_id <> OLD.org_id OR NEW.subject_id <> OLD.subject_id OR NEW.source <> OLD.source
     OR NEW.joined_at <> OLD.joined_at OR (NEW.owner AND NOT OLD.owner) THEN
    RAISE EXCEPTION 'membership transition not allowed' USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.owner AND (NEW.ended_at IS NOT NULL OR NOT NEW.owner)
     AND NOT EXISTS (
       SELECT 1 FROM access.org_memberships m
       WHERE m.tenant_id = OLD.tenant_id AND m.realm_id = OLD.realm_id AND m.org_id = OLD.org_id
         AND m.membership_id <> OLD.membership_id AND m.owner AND m.ended_at IS NULL)
     AND EXISTS (
       SELECT 1 FROM access.organizations o
       WHERE o.tenant_id = OLD.tenant_id AND o.realm_id = OLD.realm_id AND o.org_id = OLD.org_id
         AND o.ended_at IS NULL) THEN
    RAISE EXCEPTION 'last-owner' USING ERRCODE = 'check_violation', CONSTRAINT = 'org_last_owner';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER org_membership_transition BEFORE UPDATE OR DELETE ON access.org_memberships
  FOR EACH ROW EXECUTE FUNCTION access.org_membership_transition();

-- TN-89, OP-153 m.3 (o): the token and the magic code are kept as SHA-256 only; the invitee is
-- named by the realm's keyed blind index of the NFKC-folded identifier; the role comes from the
-- row, never from the link
CREATE TABLE access.org_invitations (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  invitation_id uuid NOT NULL DEFAULT uuidv7(),
  org_id uuid NOT NULL,
  token_hash bytea NOT NULL CHECK (octet_length(token_hash) = 32),
  code_hash bytea NOT NULL CHECK (octet_length(code_hash) = 32),
  -- pii:none
  invitee_index bytea NOT NULL CHECK (octet_length(invitee_index) = 32),
  invitee_domain text NOT NULL CHECK (invitee_domain ~ '^[a-z0-9.-]{1,253}$'),
  inviter_party bytea NOT NULL CHECK (octet_length(inviter_party) = 16),
  role_name text NOT NULL CHECK (char_length(role_name) BETWEEN 1 AND 128),
  role_version bigint NOT NULL CHECK (role_version >= 1),
  created_exercise bytea CHECK (created_exercise IS NULL OR octet_length(created_exercise) = 32),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  scanner_clicks integer NOT NULL DEFAULT 0 CHECK (scanner_clicks >= 0),
  accepted_at timestamptz,
  accepted_subject uuid,
  revoked_at timestamptz,
  CHECK (expires_at > created_at AND expires_at <= created_at + interval '30 days'),
  CHECK ((accepted_at IS NULL) = (accepted_subject IS NULL)),
  CHECK (accepted_at IS NULL OR revoked_at IS NULL),
  PRIMARY KEY (tenant_id, realm_id, invitation_id),
  UNIQUE (tenant_id, realm_id, token_hash),
  FOREIGN KEY (tenant_id, realm_id, org_id)
    REFERENCES access.organizations (tenant_id, realm_id, org_id)
);
CREATE INDEX org_invitations_org ON access.org_invitations (tenant_id, realm_id, org_id, created_at);

-- an invitation is accepted or revoked once; scanner clicks only grow
CREATE FUNCTION access.org_invitation_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'invitations are never deleted' USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.accepted_at IS NOT NULL OR OLD.revoked_at IS NOT NULL
     OR NEW.scanner_clicks < OLD.scanner_clicks
     OR NEW.token_hash <> OLD.token_hash OR NEW.code_hash <> OLD.code_hash
     OR NEW.invitee_index <> OLD.invitee_index OR NEW.role_name <> OLD.role_name
     OR NEW.role_version <> OLD.role_version OR NEW.expires_at <> OLD.expires_at
     OR NEW.inviter_party <> OLD.inviter_party THEN
    RAISE EXCEPTION 'invitation transition not allowed' USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER org_invitation_transition BEFORE UPDATE OR DELETE ON access.org_invitations
  FOR EACH ROW EXECUTE FUNCTION access.org_invitation_transition();

-- TN-90, OP-153 m.3 (o): a domain claim and its verification; the `domain_verification` Claim is
-- the realm issuer's, this row is what the identity plane watches (re-verify, MX and RDAP)
CREATE TABLE access.org_domains (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  claim_id uuid NOT NULL DEFAULT uuidv7(),
  org_id uuid NOT NULL,
  domain text NOT NULL CHECK (domain ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'),
  method text NOT NULL CHECK (method IN ('dns_txt', 'https', 'idp')),
  challenge_hash bytea NOT NULL CHECK (octet_length(challenge_hash) = 32),
  claimed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  verified_at timestamptz,
  reverify_by timestamptz,
  mx_digest bytea CHECK (mx_digest IS NULL OR octet_length(mx_digest) = 32),
  rdap_digest bytea CHECK (rdap_digest IS NULL OR octet_length(rdap_digest) = 32),
  changed_at timestamptz,
  autojoin boolean NOT NULL DEFAULT false,
  released_at timestamptz,
  CHECK ((verified_at IS NULL) = (reverify_by IS NULL)),
  CHECK (NOT autojoin OR verified_at IS NOT NULL),
  PRIMARY KEY (tenant_id, realm_id, claim_id),
  FOREIGN KEY (tenant_id, realm_id, org_id)
    REFERENCES access.organizations (tenant_id, realm_id, org_id)
);
CREATE UNIQUE INDEX org_domains_open
  ON access.org_domains (tenant_id, realm_id, org_id, domain) WHERE released_at IS NULL;
CREATE INDEX org_domains_domain ON access.org_domains (tenant_id, realm_id, domain) WHERE released_at IS NULL;

-- TN-90: an access request is an identity plane object an organization admin approves once
CREATE TABLE access.org_access_requests (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  request_id uuid NOT NULL DEFAULT uuidv7(),
  org_id uuid NOT NULL,
  subject_id uuid NOT NULL,
  requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  decided_at timestamptz,
  decision text CHECK (decision IS NULL OR decision IN ('approved', 'denied')),
  CHECK ((decided_at IS NULL) = (decision IS NULL)),
  PRIMARY KEY (tenant_id, realm_id, request_id),
  FOREIGN KEY (tenant_id, realm_id, org_id)
    REFERENCES access.organizations (tenant_id, realm_id, org_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE UNIQUE INDEX org_access_requests_open
  ON access.org_access_requests (tenant_id, realm_id, org_id, subject_id) WHERE decided_at IS NULL;

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['organizations', 'org_memberships', 'org_invitations', 'org_domains',
                           'org_access_requests'] LOOP
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

CREATE TRIGGER no_delete BEFORE DELETE ON access.organizations
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_delete BEFORE DELETE ON access.org_domains
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_delete BEFORE DELETE ON access.org_access_requests
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

REVOKE ALL ON FUNCTION access.org_membership_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.org_invitation_transition() FROM PUBLIC;
GRANT SELECT, INSERT ON access.organizations, access.org_memberships, access.org_invitations,
  access.org_domains, access.org_access_requests TO access_app;
GRANT UPDATE (display_name, hrd, ended_at) ON access.organizations TO access_app;
GRANT UPDATE (owner, role_name, role_version, grant_id, ended_at, ended_by)
  ON access.org_memberships TO access_app;
GRANT UPDATE (scanner_clicks, accepted_at, accepted_subject, revoked_at)
  ON access.org_invitations TO access_app;
GRANT UPDATE (verified_at, reverify_by, mx_digest, rdap_digest, changed_at, autojoin, released_at)
  ON access.org_domains TO access_app;
GRANT UPDATE (decided_at, decision) ON access.org_access_requests TO access_app;

RESET ROLE;
