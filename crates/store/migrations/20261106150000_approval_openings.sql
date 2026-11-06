-- OP-150 L6, §9.14.1, §13.7.3: what a decision point knows about a request it decided, for the
-- approval that follows it: the render digest it computed from the accepted Action Schema and
-- the intent (§9.13.3, XI-8) and the consequence tier. A contribution to the intent is checked
-- against the latest REQUIRE_ACTION that carries them. Rows are never changed (OP-73).
SET LOCAL ROLE access_migrator;

ALTER TABLE access.authority_nonce
  ADD COLUMN render_digest bytea CHECK (render_digest IS NULL OR octet_length(render_digest) = 32),
  ADD COLUMN tier smallint CHECK (tier IS NULL OR tier BETWEEN 0 AND 3);

CREATE INDEX authority_nonce_intent
  ON access.authority_nonce (domain_id, intent_digest, decision_pos DESC);

RESET ROLE;
