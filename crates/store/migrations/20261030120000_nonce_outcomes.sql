-- OP-141 m.9, L2-REC-5: a nonce's outcomes are an append-only sequence; allow and deny are
-- terminal, require_action stays open; one intent and one actor per nonce
SET LOCAL ROLE access_migrator;

ALTER TABLE access.authority_nonce
  ADD COLUMN outcome text NOT NULL DEFAULT 'allow'
  CHECK (outcome IN ('allow', 'deny', 'require_action'));
ALTER TABLE access.authority_nonce ALTER COLUMN outcome DROP DEFAULT;
ALTER TABLE access.authority_nonce DROP CONSTRAINT authority_nonce_pkey;
ALTER TABLE access.authority_nonce ADD PRIMARY KEY (domain_id, nonce, decision_pos);

CREATE FUNCTION access.nonce_sequence() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM access.authority_nonce n
             WHERE n.domain_id = NEW.domain_id AND n.nonce = NEW.nonce
               AND (n.outcome <> 'require_action' OR n.actor <> NEW.actor
                    OR n.intent_digest <> NEW.intent_digest)) THEN
    RAISE EXCEPTION 'nonce closed or bound to another intent' USING ERRCODE = 'unique_violation';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER nonce_sequence BEFORE INSERT ON access.authority_nonce
  FOR EACH ROW EXECUTE FUNCTION access.nonce_sequence();

REVOKE ALL ON FUNCTION access.nonce_sequence() FROM PUBLIC;

RESET ROLE;
