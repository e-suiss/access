-- OP-155 m.3 (j), IDP-19, IDP-20, IDI-12, §10.7.1: OpenID Federation.
-- idp_federation_settings: one row per idp.federation.enable, disable, ta_enable,
--   registration_open or registration_close; the newest version rules. It holds the leaf's
--   authority hints, whether the intermediate or trust anchor role is served and the subordinates
--   it vouches for, and whether OIDF client registration is open. Off by default.
-- idp_federation_trust_anchors: one row per idp.federation.trust_anchor_add or
--   trust_anchor_remove; the newest version of an anchor rules. Its keys are pinned here and never
--   taken from a fetched configuration.
-- oauth_oidf_clients: a URL client_id resolved through a trust chain, with the chain's metadata as
--   resolved and the chain's expiry; refreshed in place, retired once (IDI-10, OP-73).
-- oauth_oidf_jti: the jti of each automatic registration request object, kept past its exp
--   (replay check); archived by retention, never deleted.
-- federation_issuer_state: the chain state of each issuer whose Acceptance is chain-constrained,
--   per domain. Claim Ingest refuses an issuer whose chain does not resolve, is older than the
--   freshness window or has a policy conflict; the Acceptance is never touched (IDI-12).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.idp_federation_settings (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  version bigint NOT NULL CHECK (version >= 1),
  enabled boolean NOT NULL,
  authority_hints text[] NOT NULL CHECK (cardinality(authority_hints) <= 8),
  ta_enabled boolean NOT NULL,
  subordinates bytea NOT NULL CHECK (octet_length(subordinates) BETWEEN 1 AND 262144),
  registration_open boolean NOT NULL,
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (enabled OR (NOT ta_enabled AND NOT registration_open)),
  PRIMARY KEY (tenant_id, realm_id, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.idp_federation_settings
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.federation.enable',
                                                 'idp.federation.disable',
                                                 'idp.federation.ta_enable',
                                                 'idp.federation.registration_open',
                                                 'idp.federation.registration_close');
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.idp_federation_settings
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

CREATE TABLE access.idp_federation_trust_anchors (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  entity_id text NOT NULL CHECK (length(entity_id) BETWEEN 10 AND 2048 AND entity_id ~ '^https://'),
  version bigint NOT NULL CHECK (version >= 1),
  state text NOT NULL CHECK (state IN ('live', 'removed')),
  jwks bytea NOT NULL CHECK (octet_length(jwks) BETWEEN 2 AND 65536),
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, entity_id, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.idp_federation_trust_anchors
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.federation.trust_anchor_add',
                                                 'idp.federation.trust_anchor_remove');
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.idp_federation_trust_anchors
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

CREATE TABLE access.oauth_oidf_clients (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  client_uuid uuid NOT NULL DEFAULT uuidv7(),
  client_id text NOT NULL CHECK (length(client_id) BETWEEN 10 AND 2048 AND client_id ~ '^https://'),
  metadata bytea NOT NULL CHECK (octet_length(metadata) BETWEEN 2 AND 65536),
  metadata_hash bytea NOT NULL CHECK (octet_length(metadata_hash) = 32),
  anchor text NOT NULL CHECK (anchor ~ '^https://'),
  trust_marks text[] NOT NULL CHECK (cardinality(trust_marks) <= 16),
  registration text NOT NULL CHECK (registration IN ('resolved', 'automatic', 'explicit')),
  first_seen_ms bigint NOT NULL CHECK (first_seen_ms > 0),
  fetched_ms bigint NOT NULL CHECK (fetched_ms >= first_seen_ms),
  chain_exp_ms bigint NOT NULL CHECK (chain_exp_ms > 0),
  retired_ms bigint CHECK (retired_ms >= first_seen_ms),
  retire_reason text CHECK (retire_reason IN ('chain_lost', 'disabled')),
  CHECK ((retired_ms IS NULL) = (retire_reason IS NULL)),
  PRIMARY KEY (tenant_id, realm_id, client_uuid),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id)
);
CREATE UNIQUE INDEX oauth_oidf_clients_live ON access.oauth_oidf_clients (tenant_id, realm_id, client_id)
  WHERE retired_ms IS NULL;

CREATE FUNCTION access.oauth_oidf_client_rules() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' OR OLD.retired_ms IS NOT NULL
     OR (NEW.tenant_id, NEW.realm_id, NEW.client_uuid, NEW.client_id, NEW.first_seen_ms)
        IS DISTINCT FROM (OLD.tenant_id, OLD.realm_id, OLD.client_uuid, OLD.client_id,
                          OLD.first_seen_ms) THEN
    RAISE EXCEPTION 'oauth_oidf_clients: a client keeps its identity and a retired client stays retired'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER oauth_oidf_client_rules BEFORE UPDATE OR DELETE ON access.oauth_oidf_clients
  FOR EACH ROW EXECUTE FUNCTION access.oauth_oidf_client_rules();

CREATE TABLE access.oauth_oidf_jti (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  replay_key bytea NOT NULL CHECK (octet_length(replay_key) = 32),
  exp_ms bigint NOT NULL CHECK (exp_ms > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, replay_key),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id)
);
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.oauth_oidf_jti
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

-- IDP-1: a grant is the code exchange of a registered, a CIMD, a DCR or an OIDF client of the realm
CREATE OR REPLACE FUNCTION access.oauth_grant_client() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM access.idp_clients c
                  WHERE c.tenant_id = NEW.tenant_id AND c.realm_id = NEW.realm_id
                    AND c.client_uuid = NEW.client_uuid)
     AND NOT EXISTS (SELECT 1 FROM access.oauth_cimd_clients c
                      WHERE c.tenant_id = NEW.tenant_id AND c.realm_id = NEW.realm_id
                        AND c.client_uuid = NEW.client_uuid)
     AND NOT EXISTS (SELECT 1 FROM access.oauth_dcr_clients c
                      WHERE c.tenant_id = NEW.tenant_id AND c.realm_id = NEW.realm_id
                        AND c.client_uuid = NEW.client_uuid)
     AND NOT EXISTS (SELECT 1 FROM access.oauth_oidf_clients c
                      WHERE c.tenant_id = NEW.tenant_id AND c.realm_id = NEW.realm_id
                        AND c.client_uuid = NEW.client_uuid) THEN
    RAISE EXCEPTION 'oauth_grants: client % is not a client of the realm', NEW.client_uuid
      USING ERRCODE = 'foreign_key_violation';
  END IF;
  RETURN NEW;
END
$$;

-- P58: an OIDF client's consent record says so
ALTER TABLE access.oauth_consent_records DROP CONSTRAINT oauth_consent_records_source_check;
ALTER TABLE access.oauth_consent_records ADD CONSTRAINT oauth_consent_records_source_check
  CHECK (source IN ('cimd', 'registered', 'dcr', 'oidf')) NOT VALID;
ALTER TABLE access.oauth_consent_records VALIDATE CONSTRAINT oauth_consent_records_source_check;

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['idp_federation_settings', 'idp_federation_trust_anchors',
                           'oauth_oidf_clients', 'oauth_oidf_jti'] LOOP
    EXECUTE format('ALTER TABLE access.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE access.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON access.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY rows ON access.%I AS PERMISSIVE USING (true)', t);
    EXECUTE format('CREATE POLICY tenant_scope ON access.%I AS RESTRICTIVE TO access_app '
                   'USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope())) '
                   'WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))', t);
    EXECUTE format('CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.%I '
                   'FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation()', t);
  END LOOP;
END
$$;

-- IDI-12: one row per (domain, issuer entity); the gate reads it on every Claim of that issuer
CREATE TABLE access.federation_issuer_state (
  domain_id bytea NOT NULL,
  entity_id text NOT NULL CHECK (length(entity_id) BETWEEN 10 AND 2048 AND entity_id ~ '^https://'),
  issuer_id bytea CHECK (issuer_id IS NULL OR octet_length(issuer_id) = 16),
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  state text NOT NULL CHECK (state IN ('pending', 'resolved', 'unresolved', 'conflict')),
  anchor text CHECK (anchor IS NULL OR anchor ~ '^https://'),
  checked_ms bigint NOT NULL CHECK (checked_ms >= 0),
  chain_exp_ms bigint NOT NULL CHECK (chain_exp_ms >= 0),
  tracked_ms bigint NOT NULL CHECK (tracked_ms > 0),
  untracked_ms bigint CHECK (untracked_ms >= tracked_ms),
  PRIMARY KEY (domain_id, entity_id),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id) REFERENCES access.authority_domain (tenant_id, domain_id)
);
CREATE INDEX federation_issuer_state_issuer ON access.federation_issuer_state (domain_id, issuer_id)
  WHERE issuer_id IS NOT NULL;
CREATE INDEX federation_issuer_state_realm ON access.federation_issuer_state (tenant_id, realm_id);

CREATE FUNCTION access.federation_issuer_state_rules() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE'
     OR (NEW.domain_id, NEW.entity_id, NEW.issuer_id, NEW.tenant_id, NEW.realm_id, NEW.tracked_ms)
        IS DISTINCT FROM (OLD.domain_id, OLD.entity_id, OLD.issuer_id, OLD.tenant_id,
                          OLD.realm_id, OLD.tracked_ms)
     OR (OLD.untracked_ms IS NOT NULL AND NEW.untracked_ms IS DISTINCT FROM OLD.untracked_ms) THEN
    RAISE EXCEPTION 'federation_issuer_state: an issuer keeps its identity and stays untracked'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER federation_issuer_state_rules BEFORE UPDATE OR DELETE ON access.federation_issuer_state
  FOR EACH ROW EXECUTE FUNCTION access.federation_issuer_state_rules();

ALTER TABLE access.federation_issuer_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.federation_issuer_state FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.federation_issuer_state FROM PUBLIC;
CREATE POLICY rows ON access.federation_issuer_state AS PERMISSIVE USING (true);
CREATE POLICY domain_scope ON access.federation_issuer_state AS RESTRICTIVE
  USING (domain_id = (SELECT access.domain_scope()))
  WITH CHECK (domain_id = (SELECT access.domain_scope()));
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.federation_issuer_state
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

REVOKE ALL ON FUNCTION access.oauth_oidf_client_rules() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.oauth_grant_client() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.federation_issuer_state_rules() FROM PUBLIC;
GRANT SELECT, INSERT ON access.idp_federation_settings, access.idp_federation_trust_anchors,
  access.oauth_oidf_clients, access.oauth_oidf_jti, access.federation_issuer_state TO access_app;
GRANT UPDATE (metadata, metadata_hash, anchor, trust_marks, fetched_ms, chain_exp_ms, retired_ms,
              retire_reason) ON access.oauth_oidf_clients TO access_app;
GRANT UPDATE (state, anchor, checked_ms, chain_exp_ms, untracked_ms)
  ON access.federation_issuer_state TO access_app;

RESET ROLE;
