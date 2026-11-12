-- OP-159 m.3 (ll): a passkey verified under a realm's direct policy records the statement
-- format it was verified in (`verified:tpm`, `verified:android-key`, ...); `verified` alone is
-- the `packed` verification of earlier rows.
SET LOCAL ROLE access_migrator;

ALTER TABLE access.webauthn_credentials DROP CONSTRAINT webauthn_credentials_attestation_check;
ALTER TABLE access.webauthn_credentials ADD CONSTRAINT webauthn_credentials_attestation_check
  CHECK (attestation IN ('none', 'verified')
         OR attestation ~ '^unverified:[A-Za-z0-9_.-]{1,32}$'
         OR attestation IN ('verified:packed', 'verified:tpm', 'verified:android-key',
                            'verified:apple', 'verified:fido-u2f')) NOT VALID;
ALTER TABLE access.webauthn_credentials VALIDATE CONSTRAINT webauthn_credentials_attestation_check;

RESET ROLE;
