-- OP-155 m.3 (p), IDP-21: the verifier's own schema. A request is opened once and answered at
-- most once; its outcome keeps no disclosed value, only the reason, the Claims sent to Access
-- and the evidence digest. Trusted list snapshots are appended as they are loaded. No row is
-- ever updated or removed (OP-73): the records are the history.
CREATE SCHEMA vc_verifier;

-- Ek B 4833: one presentation request
CREATE TABLE vc_verifier.requests (
  request bytea PRIMARY KEY CHECK (octet_length(request) = 16),
  caller bytea NOT NULL CHECK (octet_length(caller) = 32),
  domain_id bytea NOT NULL CHECK (octet_length(domain_id) = 32),
  subject bytea NOT NULL CHECK (octet_length(subject) = 16),
  mode text NOT NULL CHECK (mode IN ('same-device', 'cross-device')),
  query text NOT NULL CHECK (char_length(query) BETWEEN 2 AND 65536),
  nonce text NOT NULL CHECK (char_length(nonce) BETWEEN 16 AND 64),
  state text NOT NULL CHECK (char_length(state) BETWEEN 16 AND 64),
  return_uri text CHECK (char_length(return_uri) BETWEEN 9 AND 2048),
  created_ms bigint NOT NULL CHECK (created_ms > 0),
  expires_ms bigint NOT NULL CHECK (expires_ms > created_ms),
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK ((mode = 'same-device') = (return_uri IS NOT NULL))
);

-- Ek B 4831, 4982: the request's one outcome
CREATE TABLE vc_verifier.outcomes (
  request bytea PRIMARY KEY REFERENCES vc_verifier.requests (request),
  outcome text NOT NULL CHECK (outcome IN ('verified', 'refused')),
  reason text CHECK (char_length(reason) BETWEEN 1 AND 128),
  detail text NOT NULL CHECK (char_length(detail) BETWEEN 2 AND 65536),
  response_code bytea CHECK (octet_length(response_code) = 32),
  recorded_ms bigint NOT NULL CHECK (recorded_ms > 0),
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK ((outcome = 'refused') = (reason IS NOT NULL))
);

-- Ek B 4834: each trusted list snapshot the verifier loaded
CREATE TABLE vc_verifier.trusted_lists (
  loaded_ms bigint PRIMARY KEY CHECK (loaded_ms > 0),
  snapshot text NOT NULL CHECK (char_length(snapshot) BETWEEN 2 AND 16777216),
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- OP-73
CREATE FUNCTION vc_verifier.append_only() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  RAISE EXCEPTION 'verifier records are append-only' USING ERRCODE = 'restrict_violation';
END
$$;
CREATE TRIGGER requests_append_only BEFORE UPDATE OR DELETE ON vc_verifier.requests
  FOR EACH ROW EXECUTE FUNCTION vc_verifier.append_only();
CREATE TRIGGER outcomes_append_only BEFORE UPDATE OR DELETE ON vc_verifier.outcomes
  FOR EACH ROW EXECUTE FUNCTION vc_verifier.append_only();
CREATE TRIGGER trusted_lists_append_only BEFORE UPDATE OR DELETE ON vc_verifier.trusted_lists
  FOR EACH ROW EXECUTE FUNCTION vc_verifier.append_only();
