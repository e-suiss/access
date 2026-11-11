-- OP-158 m.4 (l), m.3 (l), (n): the domain head columns of Stage 13, declared here and written only
-- by their owners. `frozen_at` (Unix ms) is the HO-1 freeze of a handover, written by the handover
-- (lane W5); while it is set nothing commits. `sealed_at` is the record position q a cell move
-- seals at, under the head's epoch e, and `accepted_epoch` the epoch e + 1 the target cell
-- accepted the domain at; both are written by the cell seal and accept (lane W7). Every column is
-- NULL until its owner writes it; nothing is deleted (OP-73).
SET LOCAL ROLE access_migrator;

ALTER TABLE access.domain_head
  ADD COLUMN frozen_at bigint CHECK (frozen_at >= 0),
  ADD COLUMN sealed_at bigint CHECK (sealed_at >= 0),
  ADD COLUMN accepted_epoch bigint CHECK (accepted_epoch >= 1);

RESET ROLE;
