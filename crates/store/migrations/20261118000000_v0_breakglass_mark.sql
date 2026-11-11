-- OP-157 m.3 (h), m.4 (a), INV-28, SI-22: whether an organization member's account is a
-- break-glass account. The mark carries no authority and exempts nothing from recording, audit
-- or requirements; it is set by idp.org.member_breakglass and cleared by
-- member_breakglass_clear, each bound to the committed decision's position (EI-25). A cleared
-- mark keeps its history in the audit trail; nothing is deleted (OP-73).
SET LOCAL ROLE access_migrator;

ALTER TABLE access.org_memberships
  ADD COLUMN is_breakglass boolean NOT NULL DEFAULT false,
  ADD COLUMN breakglass_position bigint CHECK (breakglass_position IS NULL OR breakglass_position > 0),
  ADD COLUMN breakglass_marked_at timestamptz,
  ADD CONSTRAINT org_membership_breakglass CHECK (
    NOT is_breakglass OR (breakglass_position IS NOT NULL AND breakglass_marked_at IS NOT NULL)) NOT VALID;

GRANT UPDATE (is_breakglass, breakglass_position, breakglass_marked_at)
  ON access.org_memberships TO access_app;

RESET ROLE;
