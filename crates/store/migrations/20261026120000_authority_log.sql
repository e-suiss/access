-- OP-130, OP-17, OP-12, OP-11a, OP-13a
SET LOCAL ROLE access_migrator;

CREATE FUNCTION access.domain_scope() RETURNS bytea
  LANGUAGE sql STABLE PARALLEL SAFE
  SET search_path = pg_catalog
  AS $$ SELECT decode(current_setting('app.domain_id', true), 'hex') $$;

CREATE FUNCTION access.reject_mutation() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  RAISE EXCEPTION 'append-only table %: % is not allowed', TG_TABLE_NAME, TG_OP
    USING ERRCODE = 'insufficient_privilege';
END
$$;

CREATE TABLE access.authority_domain (
  domain_id bytea NOT NULL CHECK (octet_length(domain_id) = 32),
  tenant_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (domain_id)
);

CREATE TABLE access.authority_log (
  domain_id bytea NOT NULL CHECK (octet_length(domain_id) = 32),
  pos bigint NOT NULL CHECK (pos >= 0),
  kind text NOT NULL CHECK (kind IN ('genesis', 'opening', 'decision', 'claim')),
  recorded_at bigint NOT NULL CHECK (recorded_at >= 0),
  leaf_hash bytea NOT NULL CHECK (octet_length(leaf_hash) = 32),
  envelope bytea NOT NULL,
  CHECK ((kind = 'genesis') = (pos = 0)),
  PRIMARY KEY (domain_id, pos),
  FOREIGN KEY (domain_id) REFERENCES access.authority_domain (domain_id)
) PARTITION BY RANGE (domain_id, pos);
CREATE TABLE access.authority_log_default PARTITION OF access.authority_log DEFAULT;
-- OP-11a: the commitment is unique per partition; a leaf hash binds its position, so it cannot recur across partitions
CREATE UNIQUE INDEX authority_log_default_leaf ON access.authority_log_default (domain_id, leaf_hash);

CREATE TABLE access.domain_head (
  domain_id bytea NOT NULL,
  pos bigint NOT NULL CHECK (pos >= 0),
  epoch bigint NOT NULL CHECK (epoch >= 0),
  leaf_hash bytea NOT NULL CHECK (octet_length(leaf_hash) = 32),
  recorded_at bigint NOT NULL CHECK (recorded_at >= 0),
  frontier bytea[] NOT NULL,
  PRIMARY KEY (domain_id),
  FOREIGN KEY (domain_id) REFERENCES access.authority_domain (domain_id)
) WITH (fillfactor = 70);

CREATE TABLE access.sequencer_lease (
  domain_id bytea NOT NULL,
  holder text NOT NULL,
  epoch bigint NOT NULL CHECK (epoch >= 0),
  acquired_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  released_at timestamptz,
  PRIMARY KEY (domain_id),
  FOREIGN KEY (domain_id) REFERENCES access.authority_domain (domain_id)
);

CREATE TABLE access.authority_nonce (
  domain_id bytea NOT NULL,
  tenant_id uuid NOT NULL,
  nonce bytea NOT NULL CHECK (octet_length(nonce) BETWEEN 1 AND 64),
  actor bytea NOT NULL,
  intent_digest bytea NOT NULL CHECK (octet_length(intent_digest) = 32),
  decision_pos bigint NOT NULL CHECK (decision_pos > 0),
  PRIMARY KEY (domain_id, nonce),
  FOREIGN KEY (domain_id, decision_pos) REFERENCES access.authority_log (domain_id, pos)
);

CREATE TABLE access.authority_outbox (
  domain_id bytea NOT NULL,
  tenant_id uuid NOT NULL,
  pos bigint NOT NULL,
  idx integer NOT NULL CHECK (idx >= 0),
  event_id bytea NOT NULL CHECK (octet_length(event_id) = 32),
  event bytea NOT NULL,
  PRIMARY KEY (domain_id, pos, idx),
  UNIQUE (domain_id, event_id),
  FOREIGN KEY (domain_id, pos) REFERENCES access.authority_log (domain_id, pos)
);

CREATE TABLE access.proof_store (
  domain_id bytea NOT NULL,
  digest bytea NOT NULL CHECK (octet_length(digest) = 32),
  bytes bytea NOT NULL,
  PRIMARY KEY (domain_id, digest),
  FOREIGN KEY (domain_id) REFERENCES access.authority_domain (domain_id)
);

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['authority_domain', 'authority_log', 'authority_log_default', 'domain_head',
                           'sequencer_lease', 'authority_nonce', 'authority_outbox', 'proof_store'] LOOP
    EXECUTE format('ALTER TABLE access.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE access.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON access.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY rows ON access.%I AS PERMISSIVE USING (true)', t);
    EXECUTE format('CREATE POLICY domain_scope ON access.%I AS RESTRICTIVE '
                   'USING (domain_id = (SELECT access.domain_scope())) '
                   'WITH CHECK (domain_id = (SELECT access.domain_scope()))', t);
  END LOOP;
  FOREACH t IN ARRAY ARRAY['authority_log', 'authority_nonce', 'authority_outbox', 'proof_store'] LOOP
    EXECUTE format('CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.%I '
                   'FOR EACH ROW EXECUTE FUNCTION access.reject_mutation()', t);
    EXECUTE format('CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.%I '
                   'FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation()', t);
  END LOOP;
END
$$;

REVOKE ALL ON FUNCTION access.domain_scope() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.reject_mutation() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION access.domain_scope() TO access_sequencer, access_app, access_archive;

GRANT SELECT ON access.authority_domain, access.authority_log, access.domain_head, access.sequencer_lease,
  access.authority_nonce, access.authority_outbox, access.proof_store TO access_app, access_sequencer;
GRANT INSERT ON access.authority_domain, access.authority_log, access.authority_nonce, access.authority_outbox, access.proof_store
  TO access_sequencer;
GRANT INSERT, UPDATE ON access.domain_head, access.sequencer_lease TO access_sequencer;

RESET ROLE;
