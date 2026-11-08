-- TN-85, CR-37, OP-153 m.11 (h), Ek B 3569, 3894: the daily analytics count the active accounts whose
-- password is still an imported hash waiting for its lazy migration; the console shows it and the
-- `access_legacy_hash_accounts` gauge is their sum (no realm label, OP-47).
SET LOCAL ROLE access_migrator;

ALTER TABLE access.analytics_daily
  ADD COLUMN legacy_password_accounts bigint NOT NULL DEFAULT 0 CHECK (legacy_password_accounts >= 0);

RESET ROLE;
