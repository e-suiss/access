-- OP-37, OP-158 m.3 (w): the identity audit tree as C2SP tlog-tiles. A tile of 256 hashes is
-- written once, when full; the yearly shard freezes the tree at the last checkpoint of a year and
-- writes its tiles to the cold tier as static objects.
SET LOCAL ROLE access_migrator;

CREATE TABLE access_ops.audit_tiles (
  level smallint NOT NULL CHECK (level BETWEEN 0 AND 7),
  n bigint NOT NULL CHECK (n >= 0),
  hashes bytea NOT NULL CHECK (octet_length(hashes) = 8192),
  end_xid xid8 NOT NULL,
  end_id bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (level, n)
);

CREATE TABLE access_ops.audit_shards (
  year integer NOT NULL CHECK (year BETWEEN 2000 AND 9999),
  size bigint NOT NULL CHECK (size >= 0),
  root bytea NOT NULL CHECK (octet_length(root) = 32),
  note text CHECK (octet_length(note) <= 4096),
  tiles integer NOT NULL CHECK (tiles >= 0),
  frozen_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((size = 0) = (note IS NULL)),
  PRIMARY KEY (year)
);

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['audit_tiles', 'audit_shards'] LOOP
    EXECUTE format('ALTER TABLE access_ops.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE access_ops.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON access_ops.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY rows ON access_ops.%I AS PERMISSIVE USING (true)', t);
    EXECUTE format('CREATE POLICY checkpointer_only ON access_ops.%I AS RESTRICTIVE '
                   'USING (pg_has_role(current_user, ''access_checkpointer'', ''MEMBER''))', t);
    EXECUTE format('CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access_ops.%I '
                   'FOR EACH ROW EXECUTE FUNCTION access.reject_mutation()', t);
    EXECUTE format('CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access_ops.%I '
                   'FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation()', t);
    EXECUTE format('GRANT SELECT, INSERT ON access_ops.%I TO access_checkpointer', t);
  END LOOP;
END
$$;

RESET ROLE;
