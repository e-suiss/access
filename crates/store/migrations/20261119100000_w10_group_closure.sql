-- §9.7A.1, §9.7A.5, CMP-9, INV-33, OP-158 m.3 (u): the group closure index. Each Party a domain's
-- membership index names gets a dense ordinal; each claim class keeps the ordinals of its members
-- as a portable roaring bitmap. The deriver writes both from the domain log next to the Grant
-- index; they name advisory candidates only and are never a commit input. A domain indexes at most
-- 200 classes; a class past that keeps no bitmap and its queries are refused (index-quota-exceeded).
SET LOCAL ROLE access_migrator;

CREATE TABLE access_derived.party_ordinal (
  domain_id bytea NOT NULL,
  party_id bytea NOT NULL CHECK (octet_length(party_id) = 16),
  ordinal integer NOT NULL CHECK (ordinal >= 0),
  PRIMARY KEY (domain_id, party_id),
  UNIQUE (domain_id, ordinal)
);

CREATE TABLE access_derived.group_closure (
  domain_id bytea NOT NULL,
  class text NOT NULL CHECK (char_length(class) BETWEEN 1 AND 255),
  members bytea,
  over_quota boolean NOT NULL DEFAULT false,
  pos bigint NOT NULL CHECK (pos >= 0),
  CHECK ((members IS NULL) = over_quota),
  PRIMARY KEY (domain_id, class)
);

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['party_ordinal', 'group_closure'] LOOP
    EXECUTE format('ALTER TABLE access_derived.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE access_derived.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON access_derived.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY rows ON access_derived.%I AS PERMISSIVE USING (true)', t);
    EXECUTE format('CREATE POLICY domain_scope ON access_derived.%I AS RESTRICTIVE '
      'USING (domain_id = (SELECT access.domain_scope())) '
      'WITH CHECK (domain_id = (SELECT access.domain_scope()))', t);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE ON access_derived.%I TO access_deriver', t);
    EXECUTE format('GRANT SELECT ON access_derived.%I TO access_app', t);
  END LOOP;
END
$$;

RESET ROLE;
