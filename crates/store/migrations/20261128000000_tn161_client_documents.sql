-- TN-161: the privacy policy and terms of service a client's operator gave, shown on the share
-- page; never what a client registered for itself (DCR, CIMD).
SET LOCAL ROLE access_migrator;

ALTER TABLE access.idp_clients
  ADD COLUMN policy_uri text CHECK (policy_uri IS NULL OR (policy_uri ~ '^https://[^[:space:]]+$' AND length(policy_uri) <= 2048)),
  ADD COLUMN tos_uri text CHECK (tos_uri IS NULL OR (tos_uri ~ '^https://[^[:space:]]+$' AND length(tos_uri) <= 2048));

RESET ROLE;
