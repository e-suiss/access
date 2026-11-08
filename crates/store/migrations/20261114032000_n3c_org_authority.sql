-- TN-89, TN-90, TN-91, TN-109, TN-120, E53, OP-153 m.3 (o), (p), (q): the rest of the identity
-- plane's side of B2B organizations and households. Nothing is deleted (OP-73): a transfer,
-- draft, guardianship or consent ends by its end time; a membership's role Grant moves only
-- forward from pending.
SET LOCAL ROLE access_migrator;

-- OP-153 m.3 (b), (p): the Anchor `party_register` opened for an organization Party, so the
-- identity plane can tell an `anchor_transfer` of this organization from any other
CREATE TABLE access.org_party_anchors (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  party bytea NOT NULL CHECK (octet_length(party) = 16),
  anchor bytea NOT NULL CHECK (octet_length(anchor) = 16),
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, party)
);

-- TN-90: the daily watch's bookkeeping and the contested lock's alarm time
ALTER TABLE access.org_domains
  ADD COLUMN created_exercise bytea CHECK (created_exercise IS NULL OR octet_length(created_exercise) = 32),
  ADD COLUMN checked_at timestamptz,
  ADD COLUMN contested_at timestamptz,
  ADD COLUMN claim_issued_at timestamptz,
  ADD COLUMN claim_retracted_at timestamptz;

-- TN-89 (3), OP-153 m.3 (o): the role Grant of a membership is issued by a `grant_issue` the
-- inviter's own client signs and the domain decides against the inviter's authority at that time;
-- until then it is pending, a DENY makes it denied, and neither ever goes back
ALTER TABLE access.org_memberships
  ADD COLUMN inviter_party bytea CHECK (inviter_party IS NULL OR octet_length(inviter_party) = 16),
  ADD COLUMN grant_state text CHECK (grant_state IS NULL OR grant_state IN ('pending', 'issued', 'denied')),
  ADD COLUMN grant_exercise bytea CHECK (grant_exercise IS NULL OR octet_length(grant_exercise) = 32),
  ADD COLUMN cooling_until timestamptz,
  ADD COLUMN claim_queued_at timestamptz,
  ADD CONSTRAINT org_membership_grant_state CHECK (
    (role_name IS NULL AND grant_state IS NULL)
    OR (role_name IS NOT NULL AND grant_state IS NOT NULL)
    OR source = 'founder') NOT VALID,
  ADD CONSTRAINT org_membership_grant_issued CHECK (
    (grant_state = 'issued') = (grant_id IS NOT NULL AND grant_exercise IS NOT NULL)
    OR grant_state IS NULL) NOT VALID;

-- TN-91: a completed transfer ends the recipient's episode and opens it again as an owner, so
-- ownership is never gained by an update
ALTER TABLE access.org_memberships
  DROP CONSTRAINT org_memberships_ended_by_check,
  ADD CONSTRAINT org_memberships_ended_by_check CHECK (
    ended_by IS NULL OR ended_by IN ('remove', 'scim', 'sweep', 'delete', 'leave', 'transfer'))
    NOT VALID;

CREATE FUNCTION access.org_membership_grant() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF OLD.grant_state IS DISTINCT FROM NEW.grant_state
     AND NOT (OLD.grant_state = 'pending' AND NEW.grant_state IN ('issued', 'denied')) THEN
    RAISE EXCEPTION 'role grant transition not allowed' USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.grant_id IS NOT NULL AND NEW.grant_id IS DISTINCT FROM OLD.grant_id THEN
    RAISE EXCEPTION 'role grant transition not allowed' USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.inviter_party IS DISTINCT FROM OLD.inviter_party
     OR (OLD.cooling_until IS NOT NULL AND NEW.cooling_until IS DISTINCT FROM OLD.cooling_until) THEN
    RAISE EXCEPTION 'membership transition not allowed' USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER org_membership_grant BEFORE UPDATE ON access.org_memberships
  FOR EACH ROW EXECUTE FUNCTION access.org_membership_grant();

-- TN-91, TN-92, OP-153 m.3 (p): an ownership transfer is the organization Anchor's
-- `anchor_transfer`: CT3, held by the domain's time-lock of at least 24 hours, completed only
-- after the recipient's contribution, cancellable by any root or the recipient until it commits
CREATE TABLE access.org_transfers (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  transfer_id uuid NOT NULL DEFAULT uuidv7(),
  org_id uuid NOT NULL,
  from_subject uuid NOT NULL,
  to_subject uuid NOT NULL,
  to_party bytea NOT NULL CHECK (octet_length(to_party) = 16),
  nonce bytea NOT NULL CHECK (octet_length(nonce) BETWEEN 16 AND 64),
  payload_digest bytea NOT NULL CHECK (octet_length(payload_digest) = 32),
  proposed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  effective_at timestamptz NOT NULL,
  dns_recovery boolean NOT NULL DEFAULT false,
  contributed_at timestamptz,
  cancelled_at timestamptz,
  cancelled_by uuid,
  completed_at timestamptz,
  completed_exercise bytea CHECK (completed_exercise IS NULL OR octet_length(completed_exercise) = 32),
  CHECK (effective_at >= proposed_at + interval '24 hours'),
  CHECK (from_subject <> to_subject),
  CHECK ((cancelled_at IS NULL) = (cancelled_by IS NULL)),
  CHECK ((completed_at IS NULL) = (completed_exercise IS NULL)),
  CHECK (cancelled_at IS NULL OR completed_at IS NULL),
  CHECK (completed_at IS NULL OR contributed_at IS NOT NULL),
  PRIMARY KEY (tenant_id, realm_id, transfer_id),
  FOREIGN KEY (tenant_id, realm_id, org_id)
    REFERENCES access.organizations (tenant_id, realm_id, org_id),
  FOREIGN KEY (tenant_id, realm_id, from_subject)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id),
  FOREIGN KEY (tenant_id, realm_id, to_subject)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE UNIQUE INDEX org_transfers_open ON access.org_transfers (tenant_id, realm_id, org_id)
  WHERE cancelled_at IS NULL AND completed_at IS NULL;

CREATE FUNCTION access.org_transfer_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF OLD.cancelled_at IS NOT NULL OR OLD.completed_at IS NOT NULL
     OR (OLD.contributed_at IS NOT NULL AND NEW.contributed_at IS DISTINCT FROM OLD.contributed_at)
     OR NEW.nonce <> OLD.nonce OR NEW.payload_digest <> OLD.payload_digest
     OR NEW.effective_at <> OLD.effective_at OR NEW.to_subject <> OLD.to_subject
     OR NEW.from_subject <> OLD.from_subject OR NEW.org_id <> OLD.org_id THEN
    RAISE EXCEPTION 'transfer transition not allowed' USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER org_transfer_transition BEFORE UPDATE ON access.org_transfers
  FOR EACH ROW EXECUTE FUNCTION access.org_transfer_transition();

-- TN-120, OP-153 m.3 (p): what the enterprise connection manager drafts; only an
-- `idp.upstream.register` (CT3) at the organization's root puts a draft into effect
CREATE TABLE access.org_sso_drafts (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  draft_id uuid NOT NULL DEFAULT uuidv7(),
  org_id uuid NOT NULL,
  protocol text NOT NULL CHECK (protocol IN ('oidc')),
  issuer text NOT NULL CHECK (char_length(issuer) <= 2048 AND issuer ~ '^https://[^\s#?]+$'),
  client_id text NOT NULL CHECK (char_length(client_id) BETWEEN 1 AND 256),
  drafted_by bytea NOT NULL CHECK (octet_length(drafted_by) = 16),
  created_exercise bytea NOT NULL CHECK (octet_length(created_exercise) = 32),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  withdrawn_at timestamptz,
  PRIMARY KEY (tenant_id, realm_id, draft_id),
  FOREIGN KEY (tenant_id, realm_id, org_id)
    REFERENCES access.organizations (tenant_id, realm_id, org_id)
);

-- E53, OP-153 m.3 (q): a guardian's standing for a ward; its `guardianship` Claim is the realm
-- issuer's and is effective only through an Acceptance; it ends at majority by the country table
CREATE TABLE access.guardianships (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  guardianship_id uuid NOT NULL DEFAULT uuidv7(),
  guardian_subject uuid NOT NULL,
  ward_subject uuid NOT NULL,
  basis text NOT NULL CHECK (basis IN ('parent', 'legal_guardian')),
  country text NOT NULL CHECK (country ~ '^[A-Z]{2}$'),
  majority_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  ended_at timestamptz,
  ended_by text CHECK (ended_by IS NULL OR ended_by IN ('majority', 'revoked')),
  CHECK ((ended_at IS NULL) = (ended_by IS NULL)),
  CHECK (guardian_subject <> ward_subject),
  PRIMARY KEY (tenant_id, realm_id, guardianship_id),
  FOREIGN KEY (tenant_id, realm_id, guardian_subject)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id),
  FOREIGN KEY (tenant_id, realm_id, ward_subject)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE UNIQUE INDEX guardianships_open ON access.guardianships
  (tenant_id, realm_id, guardian_subject, ward_subject) WHERE ended_at IS NULL;

-- E53, E47, OP-153 m.3 (q): a parent consent asked for a ward's request, valid 72 hours;
-- silence is not consent, an expired request is declined by time
CREATE TABLE access.parent_consents (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  consent_id uuid NOT NULL DEFAULT uuidv7(),
  guardianship_id uuid NOT NULL,
  purpose_digest bytea NOT NULL CHECK (octet_length(purpose_digest) = 32),
  requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  decided_at timestamptz,
  decision text CHECK (decision IS NULL OR decision IN ('approved', 'declined')),
  CHECK ((decided_at IS NULL) = (decision IS NULL)),
  CHECK (expires_at > requested_at AND expires_at <= requested_at + interval '72 hours'),
  CHECK (decided_at IS NULL OR decided_at <= expires_at),
  PRIMARY KEY (tenant_id, realm_id, consent_id),
  FOREIGN KEY (tenant_id, realm_id, guardianship_id)
    REFERENCES access.guardianships (tenant_id, realm_id, guardianship_id)
);

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['org_party_anchors', 'org_transfers', 'org_sso_drafts', 'guardianships',
                           'parent_consents'] LOOP
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

CREATE TRIGGER no_mutation BEFORE UPDATE ON access.org_party_anchors
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

REVOKE ALL ON FUNCTION access.org_membership_grant() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.org_transfer_transition() FROM PUBLIC;
GRANT SELECT, INSERT ON access.org_party_anchors, access.org_transfers, access.org_sso_drafts,
  access.guardianships, access.parent_consents TO access_app;
GRANT UPDATE (checked_at, contested_at, claim_issued_at, claim_retracted_at)
  ON access.org_domains TO access_app;
GRANT UPDATE (grant_state, grant_exercise, claim_queued_at) ON access.org_memberships TO access_app;
GRANT UPDATE (contributed_at, cancelled_at, cancelled_by, completed_at, completed_exercise)
  ON access.org_transfers TO access_app;
GRANT UPDATE (withdrawn_at) ON access.org_sso_drafts TO access_app;
GRANT UPDATE (ended_at, ended_by) ON access.guardianships TO access_app;
GRANT UPDATE (decided_at, decision) ON access.parent_consents TO access_app;

RESET ROLE;
