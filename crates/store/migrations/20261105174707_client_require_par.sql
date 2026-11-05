-- RFC 9126 §6, §10.4.3: a client may be registered to require pushed authorization requests;
-- its authorization requests are then accepted only by `request_uri` from `/par`.
SET LOCAL ROLE access_migrator;

ALTER TABLE access.idp_clients
  ADD COLUMN require_pushed_authorization_requests boolean NOT NULL DEFAULT false;

RESET ROLE;
