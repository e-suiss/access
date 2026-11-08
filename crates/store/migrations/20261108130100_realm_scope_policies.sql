-- OP-132 m.5, OP-18: realm-level rows need the realm scope as well as the tenant scope. The
-- identity outbox and the realm-keyed event, webhook, SSF and upstream tables get a restrictive
-- realm policy for access_app, so a transaction of one realm never reads or writes another
-- realm's rows of the same tenant, and a realm-less transaction sees none of them.
--
-- Two reads are tenant-wide on purpose: the fan-outs list the live stream subscriptions and the
-- live webhooks of every realm of the event's tenant. They read in a transaction that declares
-- it (`app.realm_wide = 'on'`, no realm set; `TenantTx::begin_tenant_wide`), which opens
-- SELECT on those two tables only; every write stays in its realm.
SET LOCAL ROLE access_migrator;

CREATE FUNCTION access.realm_wide() RETURNS boolean
  LANGUAGE sql STABLE PARALLEL SAFE
  SET search_path = pg_catalog
  AS $$ SELECT coalesce(current_setting('app.realm_wide', true), '') = 'on'
               AND nullif(current_setting('app.realm_id', true), '') IS NULL $$;
REVOKE ALL ON FUNCTION access.realm_wide() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION access.realm_wide() TO access_app;

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['identity_outbox', 'event_ack', 'event_delivery', 'event_subscription_ssf',
                           'idp_hooks', 'idp_webhook_attempts', 'idp_webhook_deliveries',
                           'idp_webhook_keys', 'ssf_inbound_set', 'ssf_transmitter',
                           'upstream_subject'] LOOP
    EXECUTE format('CREATE POLICY realm_scope ON access.%I AS RESTRICTIVE TO access_app '
                   'USING (realm_id = (SELECT access.realm_scope())) '
                   'WITH CHECK (realm_id = (SELECT access.realm_scope()))', t);
  END LOOP;
  FOREACH t IN ARRAY ARRAY['event_subscription', 'idp_webhooks'] LOOP
    EXECUTE format('CREATE POLICY realm_scope_reads ON access.%I AS RESTRICTIVE FOR SELECT TO access_app '
                   'USING (realm_id = (SELECT access.realm_scope()) OR (SELECT access.realm_wide()))', t);
    EXECUTE format('CREATE POLICY realm_scope_inserts ON access.%I AS RESTRICTIVE FOR INSERT TO access_app '
                   'WITH CHECK (realm_id = (SELECT access.realm_scope()))', t);
    EXECUTE format('CREATE POLICY realm_scope_updates ON access.%I AS RESTRICTIVE FOR UPDATE TO access_app '
                   'USING (realm_id = (SELECT access.realm_scope())) '
                   'WITH CHECK (realm_id = (SELECT access.realm_scope()))', t);
    EXECUTE format('CREATE POLICY realm_scope_deletes ON access.%I AS RESTRICTIVE FOR DELETE TO access_app '
                   'USING (realm_id = (SELECT access.realm_scope()))', t);
  END LOOP;
END
$$;

RESET ROLE;
