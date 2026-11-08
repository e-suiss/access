-- TN-91, TN-125: a job item the identity plane recorded without an Exercise yet, such as an
-- ownership handover's proposal that waits for its recipient and its delay, is 'accepted'.
SET LOCAL ROLE access_migrator;

ALTER TABLE access.admin_job_items DROP CONSTRAINT admin_job_items_status_check;
ALTER TABLE access.admin_job_items ADD CONSTRAINT admin_job_items_status_check
  CHECK (status IN ('pending', 'committed', 'accepted', 'not_allowed', 'rejected', 'throttled',
                    'failed_dependency', 'unavailable'));

RESET ROLE;
