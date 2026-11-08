-- OP-152 m.7 (d) E6, EI-25: an upstream subject is linked to an account by an
-- `idp.upstream.link` decision; the link names it. Links made before this have none.
SET LOCAL ROLE access_migrator;

ALTER TABLE access.upstream_subject
  ADD COLUMN domain_id bytea CHECK (octet_length(domain_id) = 32),
  ADD COLUMN decision_pos bigint CHECK (decision_pos > 0);

ALTER TABLE access.upstream_subject
  ADD CONSTRAINT upstream_subject_decision CHECK ((domain_id IS NULL) = (decision_pos IS NULL))
  NOT VALID;

ALTER TABLE access.upstream_subject VALIDATE CONSTRAINT upstream_subject_decision;

RESET ROLE;
