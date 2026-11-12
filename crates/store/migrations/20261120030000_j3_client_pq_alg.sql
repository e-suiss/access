-- CR-41, OP-159 m.3 (o)
SET LOCAL ROLE access_migrator;

ALTER TABLE access.oauth_client_profiles DROP CONSTRAINT oauth_client_profiles_id_token_alg_check;
ALTER TABLE access.oauth_client_profiles ADD CONSTRAINT oauth_client_profiles_id_token_alg_check
  CHECK (id_token_alg IN ('ES256', 'Ed25519', 'RS256', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87')) NOT VALID;
ALTER TABLE access.oauth_client_profiles VALIDATE CONSTRAINT oauth_client_profiles_id_token_alg_check;

RESET ROLE;
