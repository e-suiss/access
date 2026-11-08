-- EI-25, MD-14, TN-110, OP-151 m.3 (l): an inbound SSF transmitter is configuration like every
-- other idp_* row. It is declared under the `idp.upstream.register` ALLOW and ended under the
-- `idp.upstream.retire` ALLOW bound in the same transaction; the database refuses any other
-- insert, and any other change of its end or of its decision. Transmitters declared before
-- this migration carry no decision and keep none. Nothing is deleted (OP-73).
SET LOCAL ROLE access_migrator;

ALTER TABLE access.ssf_transmitter ADD COLUMN domain_id bytea;
ALTER TABLE access.ssf_transmitter ADD COLUMN decision_pos bigint;
ALTER TABLE access.ssf_transmitter ADD CONSTRAINT ssf_transmitter_decision
  CHECK ((domain_id IS NULL) = (decision_pos IS NULL)) NOT VALID;
ALTER TABLE access.ssf_transmitter ADD CONSTRAINT ssf_transmitter_decision_fk
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
  REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos) NOT VALID;

CREATE TRIGGER idp_bound BEFORE INSERT ON access.ssf_transmitter
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.upstream.register');
CREATE TRIGGER idp_bound_change BEFORE UPDATE ON access.ssf_transmitter
  FOR EACH ROW
  WHEN (OLD.disabled_at IS DISTINCT FROM NEW.disabled_at
        OR OLD.domain_id IS DISTINCT FROM NEW.domain_id
        OR OLD.decision_pos IS DISTINCT FROM NEW.decision_pos)
  EXECUTE FUNCTION access.idp_bound('idp.upstream.retire');

RESET ROLE;
