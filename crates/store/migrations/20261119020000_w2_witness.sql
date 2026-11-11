-- CMP-6, T17, SEC23, U9, HL-7, OP-158 m.3 (c), (d): each witness cosignature of a domain
-- checkpoint, with whether its witness is independent of the provider operator (SI-12, B13),
-- and the equivocation evidence the checkpointer's monitor kept: two cosigned notes of one
-- size with different roots. Rows are never changed or removed (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.witness_cosign (
  domain_id bytea NOT NULL CHECK (octet_length(domain_id) = 32),
  issued_at bigint NOT NULL CHECK (issued_at >= 0),
  size bigint NOT NULL CHECK (size > 0),
  witness text NOT NULL CHECK (octet_length(witness) <= 1024),
  independent boolean NOT NULL,
  cosigned_at bigint NOT NULL CHECK (cosigned_at >= 0),
  line text NOT NULL CHECK (octet_length(line) <= 4096),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (domain_id, issued_at, witness),
  FOREIGN KEY (domain_id, issued_at) REFERENCES access.authority_checkpoint (domain_id, issued_at)
);
CREATE INDEX witness_cosign_size ON access.witness_cosign (domain_id, size) WHERE independent;

CREATE TABLE access.equivocation_evidence (
  domain_id bytea NOT NULL CHECK (octet_length(domain_id) = 32),
  size bigint NOT NULL CHECK (size > 0),
  root_a bytea NOT NULL CHECK (octet_length(root_a) = 32),
  root_b bytea NOT NULL CHECK (octet_length(root_b) = 32),
  note_a text NOT NULL CHECK (octet_length(note_a) <= 262144),
  note_b text NOT NULL CHECK (octet_length(note_b) <= 262144),
  source text NOT NULL CHECK (octet_length(source) <= 1024),
  detected_at bigint NOT NULL CHECK (detected_at >= 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (root_a <> root_b),
  PRIMARY KEY (domain_id, size, root_a, root_b),
  FOREIGN KEY (domain_id) REFERENCES access.domain_head (domain_id)
);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['witness_cosign', 'equivocation_evidence'] LOOP
    EXECUTE format('ALTER TABLE access.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE access.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON access.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY rows ON access.%I AS PERMISSIVE USING (true)', t);
    EXECUTE format('CREATE POLICY domain_scope ON access.%I AS RESTRICTIVE
      USING (domain_id = (SELECT access.domain_scope()))
      WITH CHECK (domain_id = (SELECT access.domain_scope()))', t);
    EXECUTE format('CREATE TRIGGER no_mutation BEFORE UPDATE OR DELETE ON access.%I
      FOR EACH ROW EXECUTE FUNCTION access.reject_mutation()', t);
    EXECUTE format('CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.%I
      FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation()', t);
    EXECUTE format('GRANT SELECT, INSERT ON access.%I TO access_sequencer', t);
    EXECUTE format('GRANT SELECT ON access.%I TO access_app', t);
  END LOOP;
END $$;

RESET ROLE;
