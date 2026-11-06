-- OP-149 m.28 (a): a one-shot process asks the live leader of a domain to hand its lease over.
-- The leader sees the request when it renews, releases, and the named holder has the first
-- claim on the released lease for one lease length.
ALTER TABLE access.sequencer_lease
  ADD COLUMN handoff_to text,
  ADD COLUMN handoff_requested_at timestamptz,
  ADD CONSTRAINT sequencer_lease_handoff_pair
    CHECK ((handoff_to IS NULL) = (handoff_requested_at IS NULL));
