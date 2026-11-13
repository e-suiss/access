-- CR-41, OP-159 m.21 (b), (g): the algorithm a protected resource's access tokens are signed
-- with, chosen at registration; absent is the realm's algorithm.
SET LOCAL ROLE access_migrator;

ALTER TABLE access.idp_protected_resources ADD COLUMN access_token_alg text
  CHECK (access_token_alg IN ('ES256', 'Ed25519', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'));

RESET ROLE;
