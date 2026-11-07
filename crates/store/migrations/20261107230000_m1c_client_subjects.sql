-- MD-10, IDP-24, OP-151 m.2 M1: a client reads pairwise subs unless it opted in to the realm's
-- public sub; a sector identifier URI is kept as the client registered it, after its document
-- was checked to list every redirect URI (OIDC Core §8.1)
SET LOCAL ROLE access_migrator;

ALTER TABLE access.idp_clients
  ADD COLUMN subject_type text NOT NULL DEFAULT 'pairwise'
    CHECK (subject_type IN ('pairwise', 'public')),
  ADD COLUMN sector_identifier_uri text
    CHECK (length(sector_identifier_uri) <= 2048 AND sector_identifier_uri ~ '^https://');

CREATE INDEX idp_clients_public_sub ON access.idp_clients (tenant_id, realm_id)
  WHERE subject_type = 'public' AND status = 'active';

RESET ROLE;
