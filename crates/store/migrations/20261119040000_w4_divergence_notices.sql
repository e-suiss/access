-- OP-158 m.3 (h), (i), G32, G33, TI-RT1, RT9: what a replay found. A fold difference (the state
-- the recorded effects build is not the live state) stops the domain's commits until the state
-- is rebuilt from the log, which wins (TI-1); a re-evaluation difference is declared and stops
-- nothing. The provider writes no restriction: quarantine is the root's or the Security Party's
-- own policy.set. A notice is never removed (OP-73); only its resolution and relay times are set,
-- once.
SET LOCAL ROLE access_migrator;

CREATE TABLE access.divergence_notices (
  domain_id bytea NOT NULL CHECK (octet_length(domain_id) = 32),
  tenant_id uuid NOT NULL,
  id bigint GENERATED ALWAYS AS IDENTITY,
  kind text NOT NULL CHECK (kind IN ('fold', 're-evaluation')),
  source text NOT NULL CHECK (source IN ('rebuild-diff', 'replica', 'verifier')),
  declared_by text CHECK (char_length(declared_by) BETWEEN 1 AND 255),
  range_from bigint NOT NULL CHECK (range_from >= 0),
  range_to bigint NOT NULL CHECK (range_to >= range_from),
  items integer NOT NULL CHECK (items >= 1),
  first_position bigint NOT NULL CHECK (first_position >= 0),
  set_bytes bytea NOT NULL CHECK (octet_length(set_bytes) BETWEEN 1 AND 1048576),
  set_digest bytea NOT NULL CHECK (octet_length(set_digest) = 32),
  declared_at timestamptz NOT NULL DEFAULT now(),
  resolved_at timestamptz,
  relayed_at timestamptz,
  CHECK (kind = 'fold' OR resolved_at IS NULL),
  PRIMARY KEY (domain_id, id),
  UNIQUE (domain_id, set_digest),
  FOREIGN KEY (domain_id) REFERENCES access.domain_head (domain_id)
);
CREATE INDEX divergence_notices_open_fold ON access.divergence_notices (domain_id)
  WHERE kind = 'fold' AND resolved_at IS NULL;

CREATE FUNCTION access.divergence_notice_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE'
     OR (NEW.domain_id, NEW.tenant_id, NEW.id, NEW.kind, NEW.source, NEW.declared_by,
         NEW.range_from, NEW.range_to, NEW.items, NEW.first_position, NEW.set_bytes,
         NEW.set_digest, NEW.declared_at)
        IS DISTINCT FROM
        (OLD.domain_id, OLD.tenant_id, OLD.id, OLD.kind, OLD.source, OLD.declared_by,
         OLD.range_from, OLD.range_to, OLD.items, OLD.first_position, OLD.set_bytes,
         OLD.set_digest, OLD.declared_at)
     OR (OLD.resolved_at IS NOT NULL AND NEW.resolved_at IS DISTINCT FROM OLD.resolved_at)
     OR (OLD.relayed_at IS NOT NULL AND NEW.relayed_at IS DISTINCT FROM OLD.relayed_at) THEN
    RAISE EXCEPTION 'divergence notice: % changes a declared notice', TG_OP
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION access.divergence_notice_guard() FROM PUBLIC;

ALTER TABLE access.divergence_notices ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.divergence_notices FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.divergence_notices FROM PUBLIC;
CREATE POLICY rows ON access.divergence_notices AS PERMISSIVE USING (true);
CREATE POLICY domain_scope ON access.divergence_notices AS RESTRICTIVE
  USING (domain_id = (SELECT access.domain_scope()))
  WITH CHECK (domain_id = (SELECT access.domain_scope()));
CREATE TRIGGER guard BEFORE UPDATE OR DELETE ON access.divergence_notices
  FOR EACH ROW EXECUTE FUNCTION access.divergence_notice_guard();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.divergence_notices
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT, INSERT, UPDATE (resolved_at, relayed_at) ON access.divergence_notices
  TO access_app, access_sequencer;

RESET ROLE;
