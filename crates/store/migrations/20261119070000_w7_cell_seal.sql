-- OP-158 m.3 (n), §17.4.1, TI-2, EI-20, FA-2: a cell move seals the domain head at position q under
-- its epoch e; once sealed the head never moves again, so every later append on the source is
-- refused, and the target cell accepts the domain at (q, e + 1). A seal and an acceptance are each
-- one row of the cell move history, never changed or removed (OP-73).
SET LOCAL ROLE access_migrator;

CREATE FUNCTION access.domain_head_sealed() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF OLD.sealed_at IS NOT NULL AND (NEW.pos IS DISTINCT FROM OLD.pos
      OR NEW.leaf_hash IS DISTINCT FROM OLD.leaf_hash OR NEW.frontier IS DISTINCT FROM OLD.frontier
      OR NEW.sealed_at IS DISTINCT FROM OLD.sealed_at) THEN
    RAISE EXCEPTION 'the domain is sealed at %', OLD.sealed_at
      USING ERRCODE = 'object_not_in_prerequisite_state';
  END IF;
  IF NEW.sealed_at IS NOT NULL AND NEW.sealed_at <> NEW.pos THEN
    RAISE EXCEPTION 'a seal is at the head' USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.accepted_epoch IS NOT NULL AND NEW.accepted_epoch IS DISTINCT FROM OLD.accepted_epoch THEN
    RAISE EXCEPTION 'an acceptance is final' USING ERRCODE = 'object_not_in_prerequisite_state';
  END IF;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION access.domain_head_sealed() FROM PUBLIC;
CREATE TRIGGER sealed BEFORE UPDATE ON access.domain_head
  FOR EACH ROW EXECUTE FUNCTION access.domain_head_sealed();

CREATE TABLE access.cell_moves (
  domain_id bytea NOT NULL,
  kind text NOT NULL CHECK (kind IN ('seal', 'accept', 'accept_unplanned')),
  epoch bigint NOT NULL CHECK (epoch >= 0),
  pos bigint NOT NULL CHECK (pos >= 0),
  leaf_hash bytea NOT NULL CHECK (octet_length(leaf_hash) = 32),
  root bytea NOT NULL CHECK (octet_length(root) = 32),
  fence text NOT NULL DEFAULT '' CHECK (octet_length(fence) <= 256),
  at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (domain_id, kind, epoch),
  FOREIGN KEY (domain_id) REFERENCES access.authority_domain (domain_id)
);
ALTER TABLE access.cell_moves ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.cell_moves FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.cell_moves FROM PUBLIC;
CREATE POLICY rows ON access.cell_moves AS PERMISSIVE USING (true);
CREATE POLICY domain_scope ON access.cell_moves AS RESTRICTIVE
  USING (domain_id = (SELECT access.domain_scope()))
  WITH CHECK (domain_id = (SELECT access.domain_scope()));
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.cell_moves
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.cell_moves
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
GRANT SELECT, INSERT ON access.cell_moves TO access_sequencer;
GRANT SELECT ON access.cell_moves TO access_app;

RESET ROLE;
