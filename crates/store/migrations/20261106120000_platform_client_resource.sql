-- OP-149 m.26 (a): a registered platform product client is the RFC 8707 resource a realm's
-- protocol-scope access token may name. The authorization server of any realm finds such a
-- client across tenants by its client_id, product and status only; the rest of the row stays
-- behind the tenant scope of access_app.
SET LOCAL ROLE access_migrator;

CREATE POLICY platform_reads ON access.idp_clients AS RESTRICTIVE TO access_outbox_reader
  USING (platform_product IS NOT NULL) WITH CHECK (false);
GRANT SELECT (client_id, platform_product, status) ON access.idp_clients TO access_outbox_reader;

RESET ROLE;
