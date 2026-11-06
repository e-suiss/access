-- OP-150 m.3 (m), OP-149 m.4: `platform_product` is a role the operator gives any registered
-- product, third parties included, not a closed list of Suiss products (MUST-NEVER-13, XI-18).
-- The value is the product name within the name grammar; nothing else about the row changes.
SET LOCAL ROLE access_migrator;

ALTER TABLE access.idp_clients
  DROP CONSTRAINT idp_clients_platform_product_check,
  ADD CONSTRAINT idp_clients_platform_product_name
    CHECK (platform_product IS NULL OR platform_product ~ '^[a-z][a-z0-9-]{1,31}$');

ALTER TABLE access.event_subscription
  DROP CONSTRAINT event_subscription_platform_product_check,
  ADD CONSTRAINT event_subscription_platform_product_name
    CHECK (platform_product IS NULL OR platform_product ~ '^[a-z][a-z0-9-]{1,31}$');

RESET ROLE;
