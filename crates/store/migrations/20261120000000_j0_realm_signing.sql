-- OP-159 m.3 (a), (o), (t), m.4 (a), (l): the realm's post-quantum signing profile and its hybrid
-- key exchange share policy. A realm without a signing profile signs with its classical
-- algorithms only; both share policies offer the post-quantum group. idp.realm.signing_profile,
-- signing_profile_close and kex_share write them (lane J3); nothing is deleted (OP-73).
SET LOCAL ROLE access_migrator;

ALTER TABLE access.realms ADD COLUMN signing_profile text
  CHECK (signing_profile IN ('ml-dsa-65', 'ml-dsa-44', 'ml-dsa-87'));
ALTER TABLE access.realms ADD COLUMN kex_share text NOT NULL DEFAULT 'optimistic'
  CHECK (kex_share IN ('optimistic', 'advertise-only'));

RESET ROLE;
