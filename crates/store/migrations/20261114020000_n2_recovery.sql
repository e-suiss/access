-- OP-153 m.2 N2, m.3 (c)–(f); TN-52–TN-62, INV-40, SEC18: account recovery as a typed state
-- machine. The data model is §12.3.2's: `recovery_method`, `notification_address`,
-- `recovery_attempt` and `account_recovery_policy`, keyed by (tenant_id, realm_id, user) (TN-19).
-- An attempt is written once; its states are append-only transition rows, and the transition
-- that opens authority consumes its evidence in the same transaction (TN-54). Nothing here is
-- ever deleted (OP-73).
SET LOCAL ROLE access_migrator;

-- TN-53 rule 1: the order aal1 < aal2 < aal3 is a deliberate schema contract
CREATE TYPE access.aal AS ENUM ('aal1', 'aal2', 'aal3');

-- TN-57: where the account's notices go. The recovery channel of a recovery is never its notice
-- channel: an address that is a recovery target is never the account's only notice address,
-- which the deferred constraint trigger below enforces at commit
CREATE TABLE access.notification_addresses (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  address_id uuid NOT NULL DEFAULT uuidv7(),
  subject_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('email', 'phone')),
  identifier_id uuid,
  nonce bytea CHECK (nonce IS NULL OR octet_length(nonce) = 12),
  -- pii:contact
  ciphertext bytea,
  recovery_target boolean NOT NULL,
  recovery_contact boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  retired_at timestamptz,
  CHECK ((identifier_id IS NULL) = (ciphertext IS NOT NULL)),
  CHECK ((nonce IS NULL) = (ciphertext IS NULL)),
  CHECK (NOT recovery_contact OR recovery_target),
  PRIMARY KEY (tenant_id, realm_id, address_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id),
  FOREIGN KEY (tenant_id, realm_id, identifier_id)
    REFERENCES access.identity_identifiers (tenant_id, realm_id, identifier_id)
);
CREATE INDEX notification_addresses_subject
  ON access.notification_addresses (tenant_id, realm_id, subject_id) WHERE retired_at IS NULL;

CREATE FUNCTION access.notification_address_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' THEN
    RAISE EXCEPTION 'notification_addresses: % is not allowed', TG_OP USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.retired_at IS NOT NULL
     OR (NEW.tenant_id, NEW.realm_id, NEW.address_id, NEW.subject_id, NEW.kind, NEW.identifier_id,
         NEW.nonce, NEW.ciphertext, NEW.recovery_target, NEW.recovery_contact, NEW.created_at)
        IS DISTINCT FROM (OLD.tenant_id, OLD.realm_id, OLD.address_id, OLD.subject_id, OLD.kind,
                          OLD.identifier_id, OLD.nonce, OLD.ciphertext, OLD.recovery_target,
                          OLD.recovery_contact, OLD.created_at) THEN
    RAISE EXCEPTION 'notification_addresses: an address only gains its retirement, once' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER notification_address_transition BEFORE UPDATE OR DELETE ON access.notification_addresses
  FOR EACH ROW EXECUTE FUNCTION access.notification_address_transition();

-- TN-57 (şemada zorunlu): a live recovery target needs another live address that is not one
CREATE FUNCTION access.recovery_target_not_sole() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM access.notification_addresses t
              WHERE t.tenant_id = NEW.tenant_id AND t.realm_id = NEW.realm_id
                AND t.subject_id = NEW.subject_id AND t.recovery_target AND t.retired_at IS NULL)
     AND NOT EXISTS (SELECT 1 FROM access.notification_addresses n
                      WHERE n.tenant_id = NEW.tenant_id AND n.realm_id = NEW.realm_id
                        AND n.subject_id = NEW.subject_id AND NOT n.recovery_target
                        AND n.retired_at IS NULL) THEN
    RAISE EXCEPTION 'notification_addresses: a recovery target is never the only notice address'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NULL;
END
$$;
CREATE CONSTRAINT TRIGGER recovery_target_not_sole
  AFTER INSERT OR UPDATE ON access.notification_addresses
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION access.recovery_target_not_sole();

-- TN-52, TN-53 rule 1, OP-153 m.3 (d): a configured recovery method and its assurance label
CREATE TABLE access.recovery_methods (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  method_id uuid NOT NULL DEFAULT uuidv7(),
  subject_id uuid NOT NULL,
  class text NOT NULL CHECK (class IN ('registered_code', 'sent_code', 'recovery_contact',
                                       'second_authenticator', 'identity_reproofing')),
  assurance access.aal NOT NULL,
  address_id uuid,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  retired_at timestamptz,
  CHECK ((class IN ('sent_code', 'recovery_contact')) = (address_id IS NOT NULL)),
  PRIMARY KEY (tenant_id, realm_id, method_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id),
  FOREIGN KEY (tenant_id, realm_id, address_id)
    REFERENCES access.notification_addresses (tenant_id, realm_id, address_id)
);
CREATE INDEX recovery_methods_subject
  ON access.recovery_methods (tenant_id, realm_id, subject_id) WHERE retired_at IS NULL;

CREATE FUNCTION access.recovery_method_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' THEN
    RAISE EXCEPTION 'recovery_methods: % is not allowed', TG_OP USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.retired_at IS NOT NULL
     OR (NEW.tenant_id, NEW.realm_id, NEW.method_id, NEW.subject_id, NEW.class, NEW.assurance,
         NEW.address_id, NEW.created_at)
        IS DISTINCT FROM (OLD.tenant_id, OLD.realm_id, OLD.method_id, OLD.subject_id, OLD.class,
                          OLD.assurance, OLD.address_id, OLD.created_at) THEN
    RAISE EXCEPTION 'recovery_methods: a method only gains its retirement, once' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER recovery_method_transition BEFORE UPDATE OR DELETE ON access.recovery_methods
  FOR EACH ROW EXECUTE FUNCTION access.recovery_method_transition();

-- TN-60, TN-55: the account's own recovery settings; each change is a new row, the latest is
-- the state
CREATE TABLE access.account_recovery_policies (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  change_id uuid NOT NULL DEFAULT uuidv7(),
  subject_id uuid NOT NULL,
  assisted_recovery boolean NOT NULL,
  permanent_loss_acknowledged_at timestamptz,
  high_value boolean NOT NULL DEFAULT false,
  changed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (assisted_recovery OR permanent_loss_acknowledged_at IS NOT NULL),
  PRIMARY KEY (tenant_id, realm_id, change_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE INDEX account_recovery_policies_subject
  ON access.account_recovery_policies (tenant_id, realm_id, subject_id, change_id);

-- TN-55, OP-153 m.3 (e): the realm's cooling table and recovery options, each change bound to the
-- committed `idp.account.recovery_policy` or `recovery_policy_loosen` decision; the latest is the
-- policy, and an attempt keeps the cooling it started with
CREATE TABLE access.recovery_realm_policies (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  change_id uuid NOT NULL DEFAULT uuidv7(),
  policy bytea NOT NULL CHECK (octet_length(policy) BETWEEN 1 AND 4096),
  domain_id bytea NOT NULL CHECK (octet_length(domain_id) = 32),
  decision_pos bigint NOT NULL CHECK (decision_pos >= 0),
  changed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, change_id)
);
CREATE INDEX recovery_realm_policies_latest
  ON access.recovery_realm_policies (tenant_id, realm_id, change_id);

-- TN-54: one recovery attempt, written once. `subject_id` is NULL when the identifier named no
-- account: the attempt answers exactly as a real one and can never be proved (CR-40, X34)
CREATE TABLE access.recovery_attempts (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  attempt_id uuid NOT NULL DEFAULT uuidv7(),
  subject_id uuid,
  handle_hash bytea NOT NULL CHECK (octet_length(handle_hash) = 32),
  path text NOT NULL CHECK (path IN ('registered_code', 'sent_code', 'recovery_contact',
                                     'second_authenticator', 'identity_reproofing', 'reset_intent',
                                     'temporary_access_pass')),
  required_aal access.aal NOT NULL,
  cooling bytea NOT NULL CHECK (octet_length(cooling) BETWEEN 2 AND 1024),
  high_value boolean NOT NULL DEFAULT false,
  opened_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, attempt_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);
CREATE UNIQUE INDEX recovery_attempts_handle
  ON access.recovery_attempts (tenant_id, realm_id, handle_hash);
CREATE INDEX recovery_attempts_subject
  ON access.recovery_attempts (tenant_id, realm_id, subject_id, attempt_id);

-- TN-54, TN-53 rule 1: the append-only transition record. A state past the evidence carries an
-- achieved AAL at least the required one; the unconditional form would either block every row or
-- pass silently on NULL (§12.3.2)
CREATE TABLE access.recovery_transitions (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  attempt_id uuid NOT NULL,
  seq integer NOT NULL CHECK (seq >= 0),
  state text NOT NULL CHECK (state IN ('requested', 'throttled', 'locked', 'denied',
                                       'evidence_met', 'cooling_down', 'rebind_open',
                                       'grace_period', 'closed')),
  required_aal access.aal,
  achieved_aal access.aal,
  evidence text[] NOT NULL DEFAULT '{}',
  reason text NOT NULL CHECK (reason ~ '^[a-z][a-z0-9_]{0,63}$'),
  until timestamptz,
  at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (state IN ('requested', 'throttled', 'locked', 'denied')
         OR (achieved_aal IS NOT NULL AND required_aal IS NOT NULL
             AND achieved_aal >= required_aal)),
  CHECK ((state IN ('throttled', 'cooling_down', 'grace_period')) = (until IS NOT NULL)),
  PRIMARY KEY (tenant_id, realm_id, attempt_id, seq),
  FOREIGN KEY (tenant_id, realm_id, attempt_id)
    REFERENCES access.recovery_attempts (tenant_id, realm_id, attempt_id)
);

-- TN-59, OP-153 m.3 (d): a code sent for an attempt; consumed once, at most five tries
CREATE TABLE access.recovery_evidence (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  evidence_id uuid NOT NULL DEFAULT uuidv7(),
  attempt_id uuid NOT NULL,
  class text NOT NULL CHECK (class IN ('sent_code', 'recovery_contact')),
  code_hash bytea NOT NULL CHECK (octet_length(code_hash) = 32),
  address_id uuid,
  tries_left smallint NOT NULL CHECK (tries_left BETWEEN 0 AND 5),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, evidence_id),
  FOREIGN KEY (tenant_id, realm_id, attempt_id)
    REFERENCES access.recovery_attempts (tenant_id, realm_id, attempt_id),
  FOREIGN KEY (tenant_id, realm_id, address_id)
    REFERENCES access.notification_addresses (tenant_id, realm_id, address_id)
);
CREATE INDEX recovery_evidence_attempt
  ON access.recovery_evidence (tenant_id, realm_id, attempt_id) WHERE consumed_at IS NULL;

CREATE FUNCTION access.recovery_evidence_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' THEN
    RAISE EXCEPTION 'recovery_evidence: % is not allowed', TG_OP USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.consumed_at IS NOT NULL OR NEW.tries_left > OLD.tries_left
     OR (NEW.tenant_id, NEW.realm_id, NEW.evidence_id, NEW.attempt_id, NEW.class, NEW.code_hash,
         NEW.address_id, NEW.expires_at, NEW.created_at)
        IS DISTINCT FROM (OLD.tenant_id, OLD.realm_id, OLD.evidence_id, OLD.attempt_id, OLD.class,
                          OLD.code_hash, OLD.address_id, OLD.expires_at, OLD.created_at) THEN
    RAISE EXCEPTION 'recovery_evidence: evidence is spent once and its tries only fall' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER recovery_evidence_transition BEFORE UPDATE OR DELETE ON access.recovery_evidence
  FOR EACH ROW EXECUTE FUNCTION access.recovery_evidence_transition();

-- TN-61, TN-62, TN-59: the single-use secrets that open a credential-only window. A reset intent
-- and a temporary access pass are issued by an Exercise; the rebind token is what an attempt's
-- REBIND_OPEN hands the browser; a link code is a cross-device code, never e-mailed. Each is
-- stored by digest only and used at most once (`uses` counts a multi-use pass)
CREATE TABLE access.recovery_tokens (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  token_id uuid NOT NULL DEFAULT uuidv7(),
  subject_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('reset_intent', 'temporary_access_pass', 'rebind', 'link_code')),
  token_hash bytea NOT NULL CHECK (octet_length(token_hash) = 32),
  attempt_id uuid,
  exercise_id bytea CHECK (exercise_id IS NULL OR octet_length(exercise_id) = 32),
  address_id uuid,
  entropy_bits smallint NOT NULL CHECK (entropy_bits >= 40),
  one_time boolean NOT NULL DEFAULT true,
  uses integer NOT NULL DEFAULT 0 CHECK (uses >= 0),
  issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  revoked_at timestamptz,
  CHECK (expires_at > issued_at),
  CHECK (kind <> 'rebind' OR attempt_id IS NOT NULL),
  CHECK (kind NOT IN ('reset_intent', 'temporary_access_pass') OR exercise_id IS NOT NULL),
  CHECK (kind <> 'link_code' OR expires_at <= issued_at + interval '10 minutes'),
  CHECK (kind <> 'reset_intent' OR expires_at <= issued_at + interval '24 hours'),
  CHECK (kind <> 'temporary_access_pass' OR expires_at <= issued_at + interval '30 days'),
  PRIMARY KEY (tenant_id, realm_id, token_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id),
  FOREIGN KEY (tenant_id, realm_id, attempt_id)
    REFERENCES access.recovery_attempts (tenant_id, realm_id, attempt_id),
  FOREIGN KEY (tenant_id, realm_id, address_id)
    REFERENCES access.notification_addresses (tenant_id, realm_id, address_id)
);
CREATE UNIQUE INDEX recovery_tokens_hash ON access.recovery_tokens (tenant_id, realm_id, token_hash);
-- TN-62: one live pass per user
CREATE UNIQUE INDEX recovery_tokens_one_pass
  ON access.recovery_tokens (tenant_id, realm_id, subject_id)
  WHERE kind = 'temporary_access_pass' AND used_at IS NULL AND revoked_at IS NULL;

CREATE FUNCTION access.recovery_token_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' THEN
    RAISE EXCEPTION 'recovery_tokens: % is not allowed', TG_OP USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.used_at IS NOT NULL OR OLD.revoked_at IS NOT NULL OR NEW.uses < OLD.uses
     OR (NEW.tenant_id, NEW.realm_id, NEW.token_id, NEW.subject_id, NEW.kind, NEW.token_hash,
         NEW.attempt_id, NEW.exercise_id, NEW.address_id, NEW.entropy_bits, NEW.one_time,
         NEW.issued_at, NEW.expires_at)
        IS DISTINCT FROM (OLD.tenant_id, OLD.realm_id, OLD.token_id, OLD.subject_id, OLD.kind,
                          OLD.token_hash, OLD.attempt_id, OLD.exercise_id, OLD.address_id,
                          OLD.entropy_bits, OLD.one_time, OLD.issued_at, OLD.expires_at) THEN
    RAISE EXCEPTION 'recovery_tokens: a token is used or revoked once' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER recovery_token_transition BEFORE UPDATE OR DELETE ON access.recovery_tokens
  FOR EACH ROW EXECUTE FUNCTION access.recovery_token_transition();

-- OP-153 m.3 (c): a self-signed `instance_recover` the identity plane forwarded, kept so that it
-- can be forwarded again once the domain's CT3 time-lock has run
CREATE TABLE access.recovery_rebinds (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  attempt_id uuid NOT NULL,
  subject_id uuid NOT NULL,
  predecessor uuid NOT NULL,
  nonce bytea NOT NULL CHECK (octet_length(nonce) BETWEEN 16 AND 64),
  public_key bytea NOT NULL CHECK (octet_length(public_key) BETWEEN 32 AND 65),
  key_type text NOT NULL CHECK (key_type IN ('OKP', 'EC2')),
  valid_from bigint NOT NULL,
  valid_until bigint NOT NULL,
  ais bytea NOT NULL CHECK (octet_length(ais) BETWEEN 1 AND 8192),
  claim_id bytea CHECK (claim_id IS NULL OR octet_length(claim_id) = 16),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (valid_until > valid_from),
  PRIMARY KEY (tenant_id, realm_id, attempt_id),
  FOREIGN KEY (tenant_id, realm_id, attempt_id)
    REFERENCES access.recovery_attempts (tenant_id, realm_id, attempt_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['notification_addresses', 'recovery_methods', 'account_recovery_policies',
                           'recovery_realm_policies', 'recovery_attempts', 'recovery_transitions',
                           'recovery_evidence', 'recovery_tokens', 'recovery_rebinds'] LOOP
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
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.account_recovery_policies
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.recovery_realm_policies
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.recovery_attempts
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.recovery_transitions
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.recovery_rebinds
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

REVOKE ALL ON FUNCTION access.notification_address_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.recovery_target_not_sole() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.recovery_method_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.recovery_evidence_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.recovery_token_transition() FROM PUBLIC;
GRANT USAGE ON TYPE access.aal TO access_app;
GRANT SELECT, INSERT ON access.notification_addresses, access.recovery_methods,
  access.account_recovery_policies, access.recovery_realm_policies, access.recovery_attempts,
  access.recovery_transitions, access.recovery_evidence, access.recovery_tokens,
  access.recovery_rebinds TO access_app;
GRANT UPDATE (retired_at) ON access.notification_addresses, access.recovery_methods TO access_app;
GRANT UPDATE (tries_left, consumed_at) ON access.recovery_evidence TO access_app;
GRANT UPDATE (uses, used_at, revoked_at) ON access.recovery_tokens TO access_app;
RESET ROLE;
