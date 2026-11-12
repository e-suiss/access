-- CR-41, OP-159 m.3 (o): a client may register an ML-DSA id_token_signed_response_alg; the
-- admin plane takes it only while the realm's signing profile holds that parameter set, and the
-- token is refused, never signed classically, once it does not. The JWE algorithms stay
-- classical (CR-4, RR-36, OP-159 m.3 (rr)).
SET LOCAL ROLE access_migrator;

ALTER TABLE access.oauth_client_profiles DROP CONSTRAINT oauth_client_profiles_id_token_alg_check;
ALTER TABLE access.oauth_client_profiles ADD CONSTRAINT oauth_client_profiles_id_token_alg_check
  CHECK (id_token_alg IN ('ES256', 'Ed25519', 'RS256', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'));

RESET ROLE;
