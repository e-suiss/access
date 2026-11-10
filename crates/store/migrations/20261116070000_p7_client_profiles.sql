-- OP-155 m.3 (k), IDP-12, IDP-24, MD-3, MD-6, CR-2, CR-4, CR-38: each client's high-assurance and
-- legacy settings beside its registration. Each row is one decision: the FAPI 2.0 profile
-- (idp.client.profile / profile_loosen), a legacy token endpoint method (auth_method_legacy),
-- RS256 identity assertions (alg_rs256), JWE (encryption), the SAML 2.0 bearer grant
-- (saml_bearer), the legacy bearer exception (legacy_bearer), or the registration metadata
-- idp.client.update carries (mutual TLS client authentication, front-channel logout). The newest
-- version is the client's profile. A client_secret_jwt secret is sealed under the realm KEK.
-- The realm's front-channel logout opt-in is its own row. Nothing is deleted (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.oauth_client_profiles (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  client_uuid uuid NOT NULL,
  version bigint NOT NULL CHECK (version >= 1),
  fapi2 boolean NOT NULL,
  legacy_auth text CHECK (legacy_auth IN ('client_secret_post', 'client_secret_jwt')),
  jwt_kek_id text CHECK (length(jwt_kek_id) BETWEEN 1 AND 128),
  jwt_wrapped bytea CHECK (octet_length(jwt_wrapped) BETWEEN 16 AND 512),
  jwt_nonce bytea CHECK (octet_length(jwt_nonce) = 12),
  jwt_sealed bytea CHECK (octet_length(jwt_sealed) BETWEEN 32 AND 256),
  tls_auth text CHECK (tls_auth IN ('tls_client_auth', 'self_signed_tls_client_auth')),
  tls_name_kind text CHECK (tls_name_kind IN ('subject_dn', 'san_dns', 'san_uri', 'san_ip', 'san_email')),
  tls_name text CHECK (length(tls_name) BETWEEN 1 AND 1024),
  tls_jwks text CHECK (length(tls_jwks) BETWEEN 2 AND 65536),
  rs256 boolean NOT NULL,
  id_token_alg text CHECK (id_token_alg IN ('ES256', 'Ed25519', 'RS256')),
  enc_alg text CHECK (enc_alg IN ('ECDH-ES+A256KW', 'RSA-OAEP-256')),
  enc_jwks text CHECK (length(enc_jwks) BETWEEN 2 AND 65536),
  enc_id_token boolean NOT NULL,
  enc_userinfo boolean NOT NULL,
  enc_jarm boolean NOT NULL,
  userinfo_signed boolean NOT NULL,
  saml_bearer_upstream text CHECK (saml_bearer_upstream ~ '^[a-z][a-z0-9-]{0,62}$'),
  legacy_bearer boolean NOT NULL,
  frontchannel_logout_uri text CHECK (length(frontchannel_logout_uri) BETWEEN 9 AND 2048
    AND frontchannel_logout_uri ~ '^https://'),
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  -- OP-148 m.16 (l): the sealed secret exists exactly for client_secret_jwt
  CHECK ((legacy_auth IS NOT DISTINCT FROM 'client_secret_jwt')
    = (jwt_kek_id IS NOT NULL AND jwt_wrapped IS NOT NULL AND jwt_nonce IS NOT NULL
       AND jwt_sealed IS NOT NULL)),
  CHECK (num_nulls(jwt_kek_id, jwt_wrapped, jwt_nonce, jwt_sealed) IN (0, 4)),
  -- RFC 8705 §2.1.2, §2.2.2: the PKI method names one subject; the self-signed one registers keys
  CHECK ((tls_auth IS NOT DISTINCT FROM 'tls_client_auth')
    = (tls_name_kind IS NOT NULL AND tls_name IS NOT NULL)),
  CHECK ((tls_name_kind IS NULL) = (tls_name IS NULL)),
  CHECK ((tls_auth IS NOT DISTINCT FROM 'self_signed_tls_client_auth') = (tls_jwks IS NOT NULL)),
  CHECK (legacy_auth IS NULL OR tls_auth IS NULL),
  -- MD-6, CR-2: RS256 only after the opt-in
  CHECK (id_token_alg IS DISTINCT FROM 'RS256' OR rs256),
  -- CR-4: encryption names its algorithm and the client's key
  CHECK ((enc_alg IS NULL) = (enc_jwks IS NULL)),
  CHECK (enc_alg IS NOT NULL OR NOT (enc_id_token OR enc_userinfo OR enc_jarm)),
  -- IDP-12, OP-155 m.3 (k): no client_secret_*, RS256 or bearer exception under FAPI 2.0
  CHECK (NOT fapi2 OR (legacy_auth IS NULL AND NOT rs256 AND NOT legacy_bearer)),
  PRIMARY KEY (tenant_id, realm_id, client_uuid, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.oauth_client_profiles
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.client.profile', 'idp.client.profile_loosen',
    'idp.client.auth_method_legacy', 'idp.client.alg_rs256', 'idp.client.encryption',
    'idp.client.saml_bearer', 'idp.client.legacy_bearer', 'idp.client.update');
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.oauth_client_profiles
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

ALTER TABLE access.oauth_client_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.oauth_client_profiles FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.oauth_client_profiles FROM PUBLIC;
CREATE POLICY rows ON access.oauth_client_profiles AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.oauth_client_profiles AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()));
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.oauth_client_profiles
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
GRANT SELECT, INSERT ON access.oauth_client_profiles TO access_app;

-- IDP-24, §10.4.6: the realm lets its clients opt in to front-channel logout; one-way (OP-155 m.7 (c))
CREATE TABLE access.oauth_realm_frontchannel (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.oauth_realm_frontchannel
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.realm.frontchannel_logout');
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.oauth_realm_frontchannel
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

ALTER TABLE access.oauth_realm_frontchannel ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.oauth_realm_frontchannel FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.oauth_realm_frontchannel FROM PUBLIC;
CREATE POLICY rows ON access.oauth_realm_frontchannel AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.oauth_realm_frontchannel AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()));
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.oauth_realm_frontchannel
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
GRANT SELECT, INSERT ON access.oauth_realm_frontchannel TO access_app;

RESET ROLE;
