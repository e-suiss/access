-- OP-149 m.8: when a login session last stepped up; the auth_context artifact carries it
SET LOCAL ROLE access_migrator;

ALTER TABLE access.login_sessions ADD COLUMN step_up_ms bigint CHECK (step_up_ms > 0);
GRANT UPDATE (step_up_ms) ON access.login_sessions TO access_app;

RESET ROLE;
