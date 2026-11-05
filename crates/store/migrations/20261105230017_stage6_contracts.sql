-- OP-150 m.2 (L0): the tables of Stage 6. Ids, digests and positions only; personal data stays in
-- the identity plane and the PII vault. Nothing is deleted (OP-73): a row that ends gets an end
-- time once, and claim_ingest is a protocol-ephemeral table (OP-146 m.5 (f)).
--
-- claim_ingest (CMP-8): the submission digests of one day, hash-only, so a resubmitted carrier
--   artefact is recognised before it reaches the sequencer. The Claim itself goes to the log.
-- claim_quarantine (§9.13 rule 3, L2-CLM-3): the recorded Claims that are held, by record.
-- issuer_quota (G44, §16.7): one row per issuer and quota window that reached its limit, and when
--   the issuer was told.
-- realm_domain_binding (TN-4, §12.1.1): the N:M realm-to-domain map; a domain that consumes a
--   realm's Claims names the Acceptance it does so through.
-- status_list_publication (OP-150 m.3 (a), (s), T24): each signed Token Status List, with the
--   position and recorded_at it reflects.
-- offline_report (§9.12.2, L2-RPT-2): each recorded Offline Exercise Report and its chain.
-- verifier_profile (§9.12.1): each recorded Verifier Profile body, by its digest.
-- projection_family (§9.9.3 k.6, P50): an authority token's refresh family and its status entry.
SET LOCAL ROLE access_migrator;

CREATE TABLE access.claim_ingest (
  domain_id bytea NOT NULL,
  day integer NOT NULL CHECK (day >= 0),
  submission_hash bytea NOT NULL CHECK (octet_length(submission_hash) = 32),
  carrier text NOT NULL CHECK (carrier IN ('cose', 'pep', 'scim', 'webauthn', 'oidc', 'set')),
  PRIMARY KEY (domain_id, day, submission_hash)
) PARTITION BY RANGE (day);

CREATE TABLE access.claim_quarantine (
  domain_id bytea NOT NULL,
  pos bigint NOT NULL CHECK (pos > 0),
  claim_id bytea NOT NULL CHECK (octet_length(claim_id) = 16),
  issuer_id bytea NOT NULL CHECK (octet_length(issuer_id) = 16),
  class text NOT NULL CHECK (class ~ '^[a-z][a-z0-9_]{0,62}$'),
  reason text NOT NULL CHECK (reason IN ('source-not-accepted', 'future', 'quota')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (domain_id, pos),
  FOREIGN KEY (domain_id, pos) REFERENCES access.authority_log (domain_id, pos)
);
CREATE INDEX claim_quarantine_claim ON access.claim_quarantine (domain_id, claim_id);

CREATE TABLE access.issuer_quota (
  domain_id bytea NOT NULL,
  issuer_id bytea NOT NULL CHECK (octet_length(issuer_id) = 16),
  window_start_ms bigint NOT NULL CHECK (window_start_ms >= 0),
  window_s integer NOT NULL CHECK (window_s > 0),
  reached_pos bigint NOT NULL CHECK (reached_pos > 0),
  notified_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (domain_id, issuer_id, window_start_ms),
  FOREIGN KEY (domain_id, reached_pos) REFERENCES access.authority_log (domain_id, pos)
);

CREATE TABLE access.realm_domain_binding (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  domain_id bytea NOT NULL,
  role text NOT NULL CHECK (role IN ('governing', 'consuming')),
  acceptance_id bytea CHECK (acceptance_id IS NULL OR octet_length(acceptance_id) = 16),
  created_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz,
  PRIMARY KEY (tenant_id, realm_id, domain_id),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id) REFERENCES access.authority_domain (tenant_id, domain_id),
  CHECK (role = 'governing' OR acceptance_id IS NOT NULL)
);
CREATE UNIQUE INDEX realm_domain_binding_governing ON access.realm_domain_binding (tenant_id, realm_id)
  WHERE role = 'governing' AND retired_at IS NULL;

CREATE TABLE access.status_list_publication (
  domain_id bytea NOT NULL,
  list_uri text NOT NULL CHECK (octet_length(list_uri) BETWEEN 1 AND 2048),
  seq bigint NOT NULL CHECK (seq >= 0),
  applied_pos bigint NOT NULL CHECK (applied_pos >= 0),
  iat_ms bigint NOT NULL CHECK (iat_ms >= 0),
  entries bigint NOT NULL CHECK (entries >= 0),
  token bytea NOT NULL CHECK (octet_length(token) <= 16777216),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (domain_id, list_uri, seq)
);

CREATE TABLE access.offline_report (
  domain_id bytea NOT NULL,
  pos bigint NOT NULL CHECK (pos > 0),
  claim_id bytea NOT NULL CHECK (octet_length(claim_id) = 16),
  exercise_id bytea NOT NULL CHECK (octet_length(exercise_id) = 32),
  previous bytea CHECK (previous IS NULL OR octet_length(previous) = 32),
  first_seq bigint NOT NULL CHECK (first_seq >= 0),
  next_seq bigint NOT NULL CHECK (next_seq >= first_seq),
  head bytea NOT NULL CHECK (octet_length(head) = 32),
  period_from_ms bigint NOT NULL CHECK (period_from_ms >= 0),
  period_until_ms bigint NOT NULL CHECK (period_until_ms >= period_from_ms),
  body bytea NOT NULL CHECK (octet_length(body) <= 1048576),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (domain_id, pos),
  FOREIGN KEY (domain_id, pos) REFERENCES access.authority_log (domain_id, pos),
  CHECK ((previous IS NULL) = (first_seq = 0))
);
CREATE INDEX offline_report_chain ON access.offline_report (domain_id, exercise_id, first_seq);

CREATE TABLE access.verifier_profile (
  domain_id bytea NOT NULL,
  pos bigint NOT NULL CHECK (pos > 0),
  profile_digest bytea NOT NULL CHECK (octet_length(profile_digest) = 32),
  claim_id bytea NOT NULL CHECK (octet_length(claim_id) = 16),
  body bytea NOT NULL CHECK (octet_length(body) <= 65536),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (domain_id, pos),
  FOREIGN KEY (domain_id, pos) REFERENCES access.authority_log (domain_id, pos)
);
CREATE INDEX verifier_profile_digest ON access.verifier_profile (domain_id, profile_digest);

CREATE TABLE access.projection_family (
  domain_id bytea NOT NULL,
  family_id bytea NOT NULL CHECK (octet_length(family_id) = 16),
  client_id text NOT NULL CHECK (octet_length(client_id) BETWEEN 1 AND 128),
  holder_id bytea NOT NULL CHECK (octet_length(holder_id) = 16),
  root_exercise bytea NOT NULL CHECK (octet_length(root_exercise) = 32),
  status_uri text CHECK (status_uri IS NULL OR octet_length(status_uri) BETWEEN 1 AND 2048),
  status_idx bigint CHECK (status_idx IS NULL OR status_idx >= 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  revoked_pos bigint CHECK (revoked_pos IS NULL OR revoked_pos > 0),
  PRIMARY KEY (domain_id, family_id),
  CHECK ((status_uri IS NULL) = (status_idx IS NULL)),
  CHECK ((revoked_at IS NULL) = (revoked_pos IS NULL))
);
CREATE UNIQUE INDEX projection_family_status ON access.projection_family (domain_id, status_uri, status_idx)
  WHERE status_uri IS NOT NULL;

-- A row that ends is ended once: only the named end columns change, and only from NULL.
CREATE FUNCTION access.end_once() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' THEN
    RAISE EXCEPTION '%: rows are never deleted (OP-73)', TG_TABLE_NAME USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF (to_jsonb(OLD) - TG_ARGV) IS DISTINCT FROM (to_jsonb(NEW) - TG_ARGV) THEN
    RAISE EXCEPTION '%: only % may change', TG_TABLE_NAME, TG_ARGV USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF to_jsonb(OLD) -> TG_ARGV[0] <> 'null'::jsonb THEN
    RAISE EXCEPTION '%: already ended', TG_TABLE_NAME USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION access.end_once() FROM PUBLIC;

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['claim_ingest', 'claim_quarantine', 'issuer_quota', 'status_list_publication',
                           'offline_report', 'verifier_profile', 'projection_family'] LOOP
    EXECUTE format('ALTER TABLE access.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE access.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON access.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY rows ON access.%I AS PERMISSIVE USING (true)', t);
    EXECUTE format('CREATE POLICY domain_scope ON access.%I AS RESTRICTIVE '
                   'USING (domain_id = (SELECT access.domain_scope())) '
                   'WITH CHECK (domain_id = (SELECT access.domain_scope()))', t);
    EXECUTE format('CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.%I '
                   'FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation()', t);
  END LOOP;
  FOREACH t IN ARRAY ARRAY['claim_ingest', 'claim_quarantine', 'status_list_publication', 'offline_report',
                           'verifier_profile'] LOOP
    EXECUTE format('CREATE TRIGGER no_mutation BEFORE UPDATE OR DELETE ON access.%I '
                   'FOR EACH ROW EXECUTE FUNCTION access.reject_mutation()', t);
  END LOOP;
END
$$;

ALTER TABLE access.realm_domain_binding ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.realm_domain_binding FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.realm_domain_binding FROM PUBLIC;
CREATE POLICY rows ON access.realm_domain_binding AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.realm_domain_binding AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()));
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.realm_domain_binding
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

CREATE TRIGGER end_once BEFORE UPDATE OR DELETE ON access.issuer_quota
  FOR EACH ROW EXECUTE FUNCTION access.end_once('notified_at');
CREATE TRIGGER end_once BEFORE UPDATE OR DELETE ON access.realm_domain_binding
  FOR EACH ROW EXECUTE FUNCTION access.end_once('retired_at');
CREATE TRIGGER end_once BEFORE UPDATE OR DELETE ON access.projection_family
  FOR EACH ROW EXECUTE FUNCTION access.end_once('revoked_at', 'revoked_pos');

-- OP-146 m.5 (f): no default partition; a day nobody opened refuses the submission
CREATE FUNCTION access.open_claim_ingest_day(d integer) RETURNS text
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog
  AS $$
DECLARE
  name text := format('claim_ingest_d%s', d);
BEGIN
  IF d < 0 THEN
    RAISE EXCEPTION 'negative day' USING ERRCODE = 'check_violation';
  END IF;
  IF to_regclass(format('access.%I', name)) IS NOT NULL THEN
    RETURN name;
  END IF;
  EXECUTE format('CREATE TABLE access.%I PARTITION OF access.claim_ingest FOR VALUES FROM (%s) TO (%s)',
                 name, d, d + 1);
  EXECUTE format('ALTER TABLE access.%I ENABLE ROW LEVEL SECURITY', name);
  EXECUTE format('ALTER TABLE access.%I FORCE ROW LEVEL SECURITY', name);
  EXECUTE format('CREATE POLICY rows ON access.%I AS PERMISSIVE USING (true)', name);
  EXECUTE format('CREATE POLICY domain_scope ON access.%I AS RESTRICTIVE '
                 'USING (domain_id = (SELECT access.domain_scope())) '
                 'WITH CHECK (domain_id = (SELECT access.domain_scope()))', name);
  EXECUTE format('CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.%I '
                 'FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation()', name);
  RETURN name;
END
$$;
REVOKE ALL ON FUNCTION access.open_claim_ingest_day(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION access.open_claim_ingest_day(integer) TO access_archive;

GRANT SELECT, INSERT ON access.claim_ingest TO access_app;
GRANT SELECT, INSERT ON access.claim_quarantine, access.offline_report, access.verifier_profile,
  access.status_list_publication TO access_sequencer;
GRANT SELECT ON access.claim_quarantine, access.offline_report, access.verifier_profile,
  access.status_list_publication TO access_app;
GRANT SELECT, INSERT ON access.issuer_quota, access.projection_family TO access_sequencer;
GRANT SELECT ON access.issuer_quota, access.projection_family TO access_app;
GRANT UPDATE (notified_at) ON access.issuer_quota TO access_app;
GRANT UPDATE (revoked_at, revoked_pos) ON access.projection_family TO access_sequencer;
GRANT SELECT, INSERT ON access.realm_domain_binding TO access_app;
GRANT UPDATE (retired_at) ON access.realm_domain_binding TO access_app;

RESET ROLE;
