-- OP-149 m.4: a platform product's client. It authenticates with private_key_jwt (RFC 7523)
-- against a JWKS URI or one public key kept inline as a one-key JWKS, and carries the public key
-- of the service Instance its product holds in each tenant. Access never sees the private key.
SET LOCAL ROLE access_migrator;

ALTER TABLE access.idp_clients
  ADD COLUMN jwks text CHECK (length(jwks) <= 4096),
  ADD COLUMN platform_product text CHECK (platform_product IN ('work', 'relay', 'one')),
  ADD COLUMN service_key bytea CHECK (octet_length(service_key) <= 256),
  ADD CONSTRAINT idp_clients_private_key_jwt
    CHECK ((auth_method = 'private_key_jwt') = ((jwks_uri IS NOT NULL) <> (jwks IS NOT NULL))),
  ADD CONSTRAINT idp_clients_platform
    CHECK ((platform_product IS NULL) = (service_key IS NULL)
           AND (platform_product IS NULL OR auth_method = 'private_key_jwt'));

-- the single-key form joins the JWKS URI form; the rule above replaces the old one
ALTER TABLE access.idp_clients DROP CONSTRAINT idp_clients_check1;

RESET ROLE;
