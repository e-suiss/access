-- TN-10, TN-16, §17.9.6, OP-146 m.4 (a): the realm issuer, stored on the realm row and fixed once set; the slug never changes
SET LOCAL ROLE access_migrator;

ALTER TABLE access.realms ADD COLUMN issuer text
  CHECK (length(issuer) <= 255 AND issuer ~ '^https://[a-z0-9.-]+(:[1-9][0-9]{0,4})?(/[A-Za-z0-9._~-]+)*$');

CREATE FUNCTION access.realm_names_fixed() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF NEW.slug IS DISTINCT FROM OLD.slug
     OR (OLD.issuer IS NOT NULL AND NEW.issuer IS DISTINCT FROM OLD.issuer) THEN
    RAISE EXCEPTION 'realm %: slug and issuer are immutable', OLD.realm_id
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION access.realm_names_fixed() FROM PUBLIC;

CREATE TRIGGER realm_names_fixed BEFORE UPDATE ON access.realms
  FOR EACH ROW EXECUTE FUNCTION access.realm_names_fixed();

-- OP-132 m.3: Host resolution reads the issuer it serves
GRANT SELECT (issuer) ON access.realms TO access_router;

RESET ROLE;
