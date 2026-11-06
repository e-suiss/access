-- OP-150 L8: the authority side of offline and cross-domain projections. Nothing is deleted
-- (OP-73): every row is appended once.
--
-- projection_contract (§9.12, §9.12.2, §13.7.4): the ValidityContract of each allowed
--   `projection.issue`, by its ExerciseID, with what the issuance limits and the offline
--   reconciliation read it by: holder, class, variant, horizon, audiences, action namespaces.
--   The contract bytes are the PAP's `validity` as signed; the digest is `access/validity/v1`.
-- offline_reconciliation (§7.9.4.1, §9.12.2): what each recorded Offline Exercise Report came to
--   against its projection: whether it continues the chain and names the issued contract, how
--   many entries lie inside and outside the contract, whether it arrived after horizon + 24 h,
--   and the unused slice it declares. Derived state; it changes no counter.
-- verifier_profile.verifier, valid_until_ms (§9.12.1): the verifier an accepted profile names and
--   the Claim's validity end, so `projection.issue` can find the audience's profile.
SET LOCAL ROLE access_migrator;

ALTER TABLE access.verifier_profile
  ADD COLUMN verifier text CHECK (verifier IS NULL OR octet_length(verifier) BETWEEN 1 AND 255),
  ADD COLUMN valid_until_ms bigint CHECK (valid_until_ms IS NULL OR valid_until_ms >= 0);
CREATE INDEX verifier_profile_verifier ON access.verifier_profile (domain_id, verifier, pos DESC)
  WHERE verifier IS NOT NULL;

CREATE TABLE access.projection_contract (
  domain_id bytea NOT NULL,
  exercise_id bytea NOT NULL CHECK (octet_length(exercise_id) = 32),
  pos bigint NOT NULL CHECK (pos > 0),
  holder_id bytea NOT NULL CHECK (octet_length(holder_id) = 16),
  pep text NOT NULL CHECK (octet_length(pep) BETWEEN 1 AND 255),
  class text NOT NULL CHECK (class IN ('online', 'intermittent', 'offline', 'long-running')),
  variant text NOT NULL CHECK (variant IN ('online-strict', 'bounded-staleness', 'revalidate-on-reconnect',
                                           'checkpointed-offline', 'checkpoint-continuation')),
  iat_ms bigint NOT NULL CHECK (iat_ms >= 0),
  horizon_ms bigint NOT NULL CHECK (horizon_ms >= iat_ms),
  audiences text[] NOT NULL CHECK (cardinality(audiences) >= 1),
  namespaces text[] NOT NULL,
  slice boolean NOT NULL,
  contract_digest bytea NOT NULL CHECK (octet_length(contract_digest) = 32),
  contract bytea NOT NULL CHECK (octet_length(contract) <= 65536),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (domain_id, exercise_id),
  FOREIGN KEY (domain_id, pos) REFERENCES access.authority_log (domain_id, pos)
);
CREATE INDEX projection_contract_holder ON access.projection_contract (domain_id, holder_id, iat_ms);
CREATE INDEX projection_contract_horizon ON access.projection_contract (domain_id, horizon_ms);

CREATE TABLE access.offline_reconciliation (
  domain_id bytea NOT NULL,
  pos bigint NOT NULL CHECK (pos > 0),
  claim_id bytea NOT NULL CHECK (octet_length(claim_id) = 16),
  exercise_id bytea NOT NULL CHECK (octet_length(exercise_id) = 32),
  bound boolean NOT NULL,
  continuous boolean NOT NULL,
  late boolean NOT NULL,
  in_contract integer NOT NULL CHECK (in_contract >= 0),
  out_of_contract integer NOT NULL CHECK (out_of_contract >= 0),
  slice_unused bytea NOT NULL CHECK (octet_length(slice_unused) <= 65536),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (domain_id, pos),
  FOREIGN KEY (domain_id, pos) REFERENCES access.authority_log (domain_id, pos)
);
CREATE INDEX offline_reconciliation_exercise ON access.offline_reconciliation (domain_id, exercise_id, pos);

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['projection_contract', 'offline_reconciliation'] LOOP
    EXECUTE format('ALTER TABLE access.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE access.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON access.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY rows ON access.%I AS PERMISSIVE USING (true)', t);
    EXECUTE format('CREATE POLICY domain_scope ON access.%I AS RESTRICTIVE '
                   'USING (domain_id = (SELECT access.domain_scope())) '
                   'WITH CHECK (domain_id = (SELECT access.domain_scope()))', t);
    EXECUTE format('CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.%I '
                   'FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation()', t);
    EXECUTE format('CREATE TRIGGER no_mutation BEFORE UPDATE OR DELETE ON access.%I '
                   'FOR EACH ROW EXECUTE FUNCTION access.reject_mutation()', t);
  END LOOP;
END
$$;

GRANT SELECT, INSERT ON access.projection_contract, access.offline_reconciliation TO access_sequencer;
GRANT SELECT ON access.projection_contract, access.offline_reconciliation TO access_app;

RESET ROLE;
