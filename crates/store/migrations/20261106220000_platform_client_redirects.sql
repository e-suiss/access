-- OP-149 m.33 (d): a product is registered in the platform realm only, and the Approval Surface
-- of any realm accepts the product's registered return address exactly (RFC 6749 §3.1.2). The
-- surface finds a platform product client across tenants by its redirect URIs too; the policy
-- platform_reads keeps every other client's row behind the tenant scope of access_app.
SET LOCAL ROLE access_migrator;

GRANT SELECT (redirect_uris) ON access.idp_clients TO access_outbox_reader;

RESET ROLE;
