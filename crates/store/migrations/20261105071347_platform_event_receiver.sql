-- OP-149 m.4 (A2 addendum): a platform product client may name the https endpoint where its
-- product receives Access events. On pairing, Access opens one SSF push stream (RFC 8935) for
-- the client to that endpoint; only platform clients carry it.
SET LOCAL ROLE access_migrator;

ALTER TABLE access.idp_clients
  ADD COLUMN suiss_event_receiver text
    CHECK (length(suiss_event_receiver) <= 2048 AND suiss_event_receiver LIKE 'https://%'),
  ADD CONSTRAINT idp_clients_event_receiver
    CHECK (suiss_event_receiver IS NULL OR platform_product IS NOT NULL);

RESET ROLE;
