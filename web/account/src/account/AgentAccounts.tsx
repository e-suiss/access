// S2, S11 (§8.5, §12.4.1, TN-133, OP-154 m.3 (e), (t)): the accounts this person connected for
// agents and which agent used each, by the agent's name, from the realm's own agent-connections
// route on the session cookie; never a token. Disconnect is one click and keeps the record (OP-73).
import { agents } from "@suiss/access-react";
import { useCallback, useEffect, useState, type ReactElement } from "react";

import { frontend, json } from "../lib/api.js";
import { at, catalogue, t } from "../lib/i18n.js";
import { useAnnouncer } from "./common.js";

/** The names of the agents `GET /v1/account/agent-connections` lists, by agent Party. */
function agentNames(answer: unknown): ReadonlyMap<string, string> {
  const out = new Map<string, string>();
  const list = (answer as { agents?: unknown } | null)?.agents;
  if (!Array.isArray(list)) return out;
  for (const a of list as unknown[]) {
    const o = (a ?? {}) as { agent?: unknown; name?: unknown };
    if (typeof o.agent === "string" && typeof o.name === "string" && o.name !== "") {
      out.set(o.agent, o.name);
    }
  }
  return out;
}

/** "Connected accounts for agents". */
export function AgentAccounts(): ReactElement {
  const [list, setList] = useState<readonly agents.Connection[] | null | "unknown">(null);
  const [names, setNames] = useState<ReadonlyMap<string, string>>(new Map());
  const { say, fail, region } = useAnnouncer();
  const reload = useCallback(() => {
    json<unknown>(frontend("/v1/account/agent-connections"))
      .then((a) => {
        setNames(agentNames(a));
        setList(agents.connectionsOf(a));
      })
      .catch((e: unknown) => {
        setList("unknown");
        fail(e);
      });
  }, [fail]);
  useEffect(reload, [reload]);
  return (
    <div data-testid="agent-accounts">
      {region}
      {list === null ? (
        <p>{t("shell.loading")}</p>
      ) : list === "unknown" ? (
        <p>{t("agent_connections.unavailable")}</p>
      ) : (
        <agents.AgentConnections
          connections={list}
          name={(p) => names.get(p) ?? p}
          time={at}
          catalogue={catalogue}
          onDisconnect={(c) => {
            void json(
              frontend(`/v1/account/vault/connections/${encodeURIComponent(c)}`, {
                method: "DELETE",
              }),
            )
              .then(() => {
                say(t("agent_connections.disconnected"));
                reload();
              })
              .catch((e: unknown) => {
                fail(e);
              });
          }}
        />
      )}
    </div>
  );
}
