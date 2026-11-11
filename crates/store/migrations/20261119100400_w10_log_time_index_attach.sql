-- OP-55, OP-158 m.3 (z): the partition's index completes the parent's
ALTER INDEX access.authority_log_recorded ATTACH PARTITION access.authority_log_default_recorded;
