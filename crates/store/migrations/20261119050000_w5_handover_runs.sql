-- OP-158 m.3 (l), m.4 (l), §16.6 HO-1…HO-9, §16.6.1 RB-1…RB-6, U11, PI-15: the steps of a cooperative
-- handover or a binding re-anchor, one row per step, never changed or removed (OP-73).
-- - `frozen`: HO-1/HO-2, the head stood at k − 1 and `domain_head.frozen_at` was set.
-- - `committed`: HO-6, the handover batch k..h moved the head; written by the head trigger itself.
-- - `thawed`: RB-6, a re-anchor's provider writes again from h + 1 under its new binding; or a run
--   abandoned before its batch (no `h`) gives the domain back to its provider.
-- - `adopted`: HO-8, the incoming provider took the domain over at h + 1 from the export.
-- While a domain is frozen its head moves only once, from k − 1 to the batch's last position, and
-- only for a run that froze it at k and has not committed yet; after an outgoing handover it never
-- moves again (the DB fence of U11).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.handover_runs (
  domain_id bytea NOT NULL,
  run uuid NOT NULL,
  step text NOT NULL CHECK (step IN ('frozen', 'committed', 'thawed', 'adopted')),
  role text NOT NULL CHECK (role IN ('outgoing', 'reanchor', 'incoming')),
  k bigint NOT NULL CHECK (k >= 1),
  h bigint CHECK (h >= k),
  cited_root bytea CHECK (octet_length(cited_root) = 32),
  at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (domain_id, run, step),
  FOREIGN KEY (domain_id) REFERENCES access.authority_domain (domain_id)
);
ALTER TABLE access.handover_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.handover_runs FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.handover_runs FROM PUBLIC;
CREATE POLICY rows ON access.handover_runs AS PERMISSIVE USING (true);
CREATE POLICY domain_scope ON access.handover_runs AS RESTRICTIVE
  USING (domain_id = (SELECT access.domain_scope()))
  WITH CHECK (domain_id = (SELECT access.domain_scope()));
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.handover_runs
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.handover_runs
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
GRANT SELECT, INSERT ON access.handover_runs TO access_sequencer;
GRANT SELECT ON access.handover_runs TO access_app;

-- HO-1, U11
CREATE FUNCTION access.domain_head_frozen() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
  open_run uuid;
  open_role text;
BEGIN
  IF OLD.frozen_at IS NOT NULL AND NEW.frozen_at IS NULL THEN
    IF NOT EXISTS (SELECT 1 FROM access.handover_runs r
                    WHERE r.domain_id = OLD.domain_id AND r.step = 'thawed'
                      AND ((r.role = 'reanchor' AND r.h = OLD.pos)
                        OR (r.h IS NULL AND r.k = OLD.pos + 1
                            AND NOT EXISTS (SELECT 1 FROM access.handover_runs c
                                             WHERE c.domain_id = r.domain_id AND c.run = r.run
                                               AND c.step = 'committed')))) THEN
      RAISE EXCEPTION 'only a committed re-anchor or a run that wrote no batch thaws a frozen domain'
        USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    RETURN NEW;
  END IF;
  IF OLD.frozen_at IS NOT NULL AND (NEW.pos IS DISTINCT FROM OLD.pos
      OR NEW.leaf_hash IS DISTINCT FROM OLD.leaf_hash OR NEW.frontier IS DISTINCT FROM OLD.frontier) THEN
    SELECT r.run, r.role INTO open_run, open_role FROM access.handover_runs r
     WHERE r.domain_id = OLD.domain_id AND r.step = 'frozen' AND r.k = OLD.pos + 1
       AND NOT EXISTS (SELECT 1 FROM access.handover_runs c
                        WHERE c.domain_id = r.domain_id AND c.run = r.run AND c.step = 'committed');
    IF open_run IS NULL OR NEW.pos < OLD.pos + 1 THEN
      RAISE EXCEPTION 'the domain is frozen for a handover since %', OLD.frozen_at
        USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    INSERT INTO access.handover_runs (domain_id, run, step, role, k, h)
      VALUES (OLD.domain_id, open_run, 'committed', open_role, OLD.pos + 1, NEW.pos);
  END IF;
  IF OLD.frozen_at IS NOT NULL AND NEW.frozen_at IS DISTINCT FROM OLD.frozen_at THEN
    RAISE EXCEPTION 'a freeze is kept' USING ERRCODE = 'object_not_in_prerequisite_state';
  END IF;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION access.domain_head_frozen() FROM PUBLIC;
CREATE TRIGGER frozen BEFORE UPDATE ON access.domain_head
  FOR EACH ROW EXECUTE FUNCTION access.domain_head_frozen();

RESET ROLE;
