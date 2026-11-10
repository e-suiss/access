-- OP-156 m.3 (n), AG-42: the tool list an administrator pinned for a proxy in MCP mode. Each
-- row is one idp.proxy.mcp_pin decision and holds the whole list: every tool's name and the
-- SHA-256 of its canonical definition (name, description, inputSchema, annotations). The newest
-- version is the list; a tool not in it, or with another digest, is blocked until pinned again.
-- Nothing is deleted (OP-73): a new version replaces the list, the old ones stay.
SET LOCAL ROLE access_migrator;

CREATE TABLE access.mcp_tool_pins (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  proxy text NOT NULL CHECK (proxy ~ '^[a-z][a-z0-9-]{0,62}$'),
  version bigint NOT NULL CHECK (version >= 1),
  tools text NOT NULL CHECK (length(tools) BETWEEN 2 AND 65536),
  domain_id bytea NOT NULL,
  decision_pos bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, proxy, version),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id),
  FOREIGN KEY (tenant_id, domain_id, decision_pos)
    REFERENCES access.idp_config_log (tenant_id, domain_id, decision_pos)
);
CREATE TRIGGER idp_bound BEFORE INSERT ON access.mcp_tool_pins
  FOR EACH ROW EXECUTE FUNCTION access.idp_bound('idp.proxy.mcp_pin');
CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.mcp_tool_pins
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.mcp_tool_pins
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();

ALTER TABLE access.mcp_tool_pins ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.mcp_tool_pins FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.mcp_tool_pins FROM PUBLIC;
CREATE POLICY rows ON access.mcp_tool_pins AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.mcp_tool_pins AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()));
GRANT SELECT, INSERT ON access.mcp_tool_pins TO access_app;

RESET ROLE;
