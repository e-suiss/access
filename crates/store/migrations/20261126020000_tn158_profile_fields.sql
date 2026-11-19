-- TN-158: the national identity number and its scheme are profile fields, sealed under the
-- account's profile key like the others.
SET LOCAL ROLE access_migrator;

ALTER TABLE access.identity_profile_fields
  DROP CONSTRAINT identity_profile_fields_field_check,
  ADD CONSTRAINT identity_profile_fields_field_check
    CHECK (field IN ('name', 'given_name', 'family_name', 'birthdate', 'locale', 'zoneinfo',
                     'national_id', 'national_id_scheme')) NOT VALID;

RESET ROLE;
