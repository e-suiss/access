-- OP-141 m.22 (g), (k), CMP-9, INV-33: the derived index of Grants. The deriver writes it from
-- the domain log from a cursor; it is never a commit input and can be rebuilt from the log.
SET LOCAL ROLE access_migrator;

CREATE TABLE access_derived.cursor (
  domain_id bytea NOT NULL,
  pos bigint NOT NULL CHECK (pos >= 0),
  PRIMARY KEY (domain_id)
);

CREATE TABLE access_derived.grant_index (
  domain_id bytea NOT NULL,
  grant_id bytea NOT NULL CHECK (octet_length(grant_id) = 16),
  holder_kind text NOT NULL CHECK (holder_kind IN ('party', 'pred', 'public', 'foreign')),
  holder bytea CHECK (holder IS NULL OR octet_length(holder) = 16),
  namespace text NOT NULL,
  ended boolean NOT NULL,
  pos bigint NOT NULL CHECK (pos >= 0),
  PRIMARY KEY (domain_id, grant_id)
);
CREATE INDEX grant_index_holder ON access_derived.grant_index (domain_id, holder) WHERE NOT ended;
CREATE INDEX grant_index_namespace ON access_derived.grant_index (domain_id, namespace) WHERE NOT ended;

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['cursor', 'grant_index'] LOOP
    EXECUTE format('ALTER TABLE access_derived.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE access_derived.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON access_derived.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY rows ON access_derived.%I AS PERMISSIVE USING (true)', t);
    EXECUTE format('CREATE POLICY domain_scope ON access_derived.%I AS RESTRICTIVE '
      'USING (domain_id = (SELECT access.domain_scope())) '
      'WITH CHECK (domain_id = (SELECT access.domain_scope()))', t);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE ON access_derived.%I TO access_deriver', t);
    EXECUTE format('GRANT SELECT ON access_derived.%I TO access_app', t);
  END LOOP;
END
$$;

GRANT EXECUTE ON FUNCTION access.domain_scope() TO access_deriver;
GRANT SELECT ON access.authority_log, access.domain_head TO access_deriver;

RESET ROLE;
