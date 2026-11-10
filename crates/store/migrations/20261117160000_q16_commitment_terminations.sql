-- OP-156 m.3 (t), EI-5, §7.9.5.4, §8.17.7.2: the commitments a coordinator ended, as Access saw
-- them. A row is written once, after the `claim` record of an admitted `commitment_active` Claim
-- whose disclosed body says `active: false`; every Grant held while that commitment is active has
-- ended with it. The authority log stays the source: this table only lets the inventory say
-- "Ended with Work commitment X" and when. Append-only; nothing is deleted (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.commitment_terminations (
  domain_id bytea NOT NULL,
  commitment bytea NOT NULL CHECK (octet_length(commitment) = 32),
  pos bigint NOT NULL CHECK (pos > 0),
  claim_id bytea NOT NULL CHECK (octet_length(claim_id) = 16),
  issuer_id bytea NOT NULL CHECK (octet_length(issuer_id) = 16),
  subject_id bytea NOT NULL CHECK (octet_length(subject_id) = 16),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (domain_id, commitment, issuer_id),
  FOREIGN KEY (domain_id, pos) REFERENCES access.authority_log (domain_id, pos)
);

ALTER TABLE access.commitment_terminations ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.commitment_terminations FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.commitment_terminations FROM PUBLIC;
CREATE POLICY rows ON access.commitment_terminations AS PERMISSIVE USING (true);
CREATE POLICY domain_scope ON access.commitment_terminations AS RESTRICTIVE
  USING (domain_id = (SELECT access.domain_scope()))
  WITH CHECK (domain_id = (SELECT access.domain_scope()));
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.commitment_terminations
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_mutation BEFORE UPDATE OR DELETE ON access.commitment_terminations
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT, INSERT ON access.commitment_terminations TO access_sequencer;
GRANT SELECT ON access.commitment_terminations TO access_app;

RESET ROLE;
