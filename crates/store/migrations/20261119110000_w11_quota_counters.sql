-- OP-158 m.3 (v), T27, TN-24, OP-35 (layer B), MD-8: exact quota counters per tenant, realm and
-- domain. One GCRA arrival time per counter, held under a row lock for the read-modify-write;
-- the table holds one row per counter and nothing is removed (OP-73). Only access.quota_take
-- reads or writes it, so a refusal never touches another tenant's or domain's row.
SET LOCAL ROLE access_migrator;

CREATE TABLE access.quota_counters (
  tenant_id uuid NOT NULL,
  dimension text NOT NULL CHECK (dimension IN ('tenant', 'realm', 'domain')),
  class text NOT NULL CHECK (class IN ('commit', 'request')),
  subject bytea NOT NULL CHECK (octet_length(subject) IN (16, 32)),
  tat_us bigint NOT NULL DEFAULT 0 CHECK (tat_us >= 0),
  PRIMARY KEY (tenant_id, dimension, class, subject)
);

ALTER TABLE access.quota_counters ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.quota_counters FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.quota_counters FROM PUBLIC;
CREATE POLICY rows ON access.quota_counters AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.quota_counters AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()));
CREATE TRIGGER append_only_row BEFORE DELETE ON access.quota_counters
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.quota_counters
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

-- Takes one unit of p_class from each counter, all or none. Counter i is (p_dims[i],
-- p_subjects[i]) with p_interval[i] microseconds between units and p_burst[i] units at once;
-- p_now is in microseconds. Returns 0 when every counter admitted, else the 1-based index of the
-- first that refused, and nothing is drawn then. A clock that stepped back finds a counter more
-- than one burst ahead and pulls it back to one burst, so the refusal lasts one burst window. Callers pass the tenant counter
-- first, so two calls lock rows in the same order.
CREATE FUNCTION access.quota_take(
  p_tenant uuid, p_class text, p_dims text[], p_subjects bytea[], p_now bigint, p_interval bigint[],
  p_burst bigint[]
) RETURNS integer
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog
  AS $$
DECLARE
  n integer := coalesce(array_length(p_dims, 1), 0);
  tat bigint;
  cap bigint;
  next bigint[] := '{}';
BEGIN
  IF n = 0 OR array_length(p_subjects, 1) <> n OR array_length(p_interval, 1) <> n
     OR array_length(p_burst, 1) <> n OR p_now < 0 THEN
    RAISE EXCEPTION 'quota_take: malformed arguments' USING ERRCODE = 'invalid_parameter_value';
  END IF;
  FOR i IN 1..n LOOP
    IF p_interval[i] < 1 OR p_burst[i] < 1 THEN
      RAISE EXCEPTION 'quota_take: malformed limit' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    INSERT INTO access.quota_counters (tenant_id, dimension, class, subject)
      VALUES (p_tenant, p_dims[i], p_class, p_subjects[i])
      ON CONFLICT (tenant_id, dimension, class, subject) DO NOTHING;
    SELECT c.tat_us INTO tat FROM access.quota_counters c
     WHERE c.tenant_id = p_tenant AND c.dimension = p_dims[i] AND c.class = p_class
       AND c.subject = p_subjects[i]
       FOR UPDATE;
    cap := p_now + p_interval[i] * p_burst[i];
    IF tat > cap THEN
      UPDATE access.quota_counters c SET tat_us = cap
       WHERE c.tenant_id = p_tenant AND c.dimension = p_dims[i] AND c.class = p_class
         AND c.subject = p_subjects[i];
      tat := cap;
    END IF;
    next := next || (greatest(tat, p_now) + p_interval[i]);
  END LOOP;
  FOR i IN 1..n LOOP
    IF next[i] - p_now > p_interval[i] * p_burst[i] THEN
      RETURN i;
    END IF;
  END LOOP;
  FOR i IN 1..n LOOP
    UPDATE access.quota_counters c SET tat_us = next[i]
     WHERE c.tenant_id = p_tenant AND c.dimension = p_dims[i] AND c.class = p_class
       AND c.subject = p_subjects[i];
  END LOOP;
  RETURN 0;
END
$$;

-- T27, TN-1, B10, OP-158 m.3 (v): one widening commit of a domain, drawn from its tenant's and
-- its own commit quota. Returns null when admitted, else 'suspended' (the tenant's billing hold:
-- a protocol rejection, never a decision), 'tenant' or 'domain'. Runs under the domain's scope.
CREATE FUNCTION access.commit_quota(
  p_domain bytea, p_now bigint, p_tenant_limit bigint[], p_domain_limit bigint[]
) RETURNS text
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog
  AS $$
DECLARE
  tenant uuid;
  held boolean;
  refused integer;
BEGIN
  SELECT d.tenant_id INTO tenant FROM access.authority_domain d WHERE d.domain_id = p_domain;
  IF tenant IS NULL THEN
    RAISE EXCEPTION 'commit_quota: unknown domain' USING ERRCODE = 'no_data_found';
  END IF;
  SELECT t.status = 'suspended' INTO held FROM access.tenants t WHERE t.tenant_id = tenant;
  IF coalesce(held, false) THEN
    RETURN 'suspended';
  END IF;
  refused := access.quota_take(tenant, 'commit', ARRAY['tenant', 'domain'],
                               ARRAY[uuid_send(tenant), p_domain], p_now,
                               ARRAY[p_tenant_limit[1], p_domain_limit[1]],
                               ARRAY[p_tenant_limit[2], p_domain_limit[2]]);
  RETURN CASE refused WHEN 0 THEN NULL WHEN 1 THEN 'tenant' ELSE 'domain' END;
END
$$;

REVOKE ALL ON FUNCTION access.quota_take(uuid, text, text[], bytea[], bigint, bigint[], bigint[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION access.commit_quota(bytea, bigint, bigint[], bigint[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION access.commit_quota(bytea, bigint, bigint[], bigint[]) TO access_app;

RESET ROLE;
