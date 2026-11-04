-- OP-149 m.17 (e): a platform product's subscription. A subscription owned by a platform client
-- (`idp_clients.platform_product`) lives in the platform tenant and receives the events of every
-- tenant. The outbox reader finds these across tenants by their ids and requested events only;
-- the rest of the row stays behind the tenant scope of access_app.
SET LOCAL ROLE access_migrator;

ALTER TABLE access.event_subscription
  ADD COLUMN owner_client_id text CHECK (owner_client_id IS NULL OR octet_length(owner_client_id) BETWEEN 1 AND 128),
  ADD COLUMN platform_product text CHECK (platform_product IN ('work', 'relay', 'one')),
  ADD CONSTRAINT event_subscription_platform_owner
    CHECK (platform_product IS NULL OR owner_client_id IS NOT NULL);

CREATE INDEX event_subscription_platform ON access.event_subscription (tenant_id, realm_id, subscription_id)
  WHERE platform_product IS NOT NULL AND disabled_at IS NULL;

CREATE POLICY platform_reads ON access.event_subscription AS RESTRICTIVE TO access_outbox_reader
  USING (platform_product IS NOT NULL AND disabled_at IS NULL) WITH CHECK (false);
GRANT SELECT (tenant_id, realm_id, subscription_id, events, platform_product, disabled_at)
  ON access.event_subscription TO access_outbox_reader;

RESET ROLE;
