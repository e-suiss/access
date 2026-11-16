// S2, S11 (§8.5, §12.4.1, TN-133, OP-154 m.3 (e), (t)): the accounts this person connected for
// agents and which agent used each, by the agent's name, from the environment's own agent-connections
// route on the session cookie; never a token. Disconnect is one click and keeps the record (OP-73).
import { agents } from "@access/ui";
import { Card, CardContent } from "@access/ui/components/card";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { ReactElement } from "react";
import * as v from "valibot";

import { frontend, json } from "../lib/api.js";
import { at, catalogue, t } from "../lib/i18n.js";
import { Loading, Nothing } from "../lib/ui.js";
import { useAnnouncer } from "./common.js";

const Named = v.object({ agent: v.string(), name: v.pipe(v.string(), v.nonEmpty()) });
const Agents = v.object({ agents: v.optional(v.array(v.unknown()), []) });

/** The names of the agents `GET /v1/account/agent-connections` lists, by agent Party. */
function agentNames(answer: unknown): ReadonlyMap<string, string> {
  const out = new Map<string, string>();
  const list = v.safeParse(Agents, answer);
  for (const a of list.success ? list.output.agents : []) {
    const o = v.safeParse(Named, a);
    if (o.success) out.set(o.output.agent, o.output.name);
  }
  return out;
}

const KEY = ["agent-connections"] as const;

/** "Connected accounts for agents". */
export function AgentAccounts(): ReactElement {
  const queries = useQueryClient();
  const { data, error } = useQuery({
    queryKey: KEY,
    queryFn: async () => {
      const a = await json(frontend("/v1/account/agent-connections"), v.unknown());
      return { names: agentNames(a), list: agents.connectionsOf(a) };
    },
  });
  const { say, fail, region } = useAnnouncer(error);
  const disconnect = useMutation({
    mutationFn: (c: string) =>
      json(
        frontend(`/v1/account/vault/connections/${encodeURIComponent(c)}`, { method: "DELETE" }),
      ),
    onSuccess: () => {
      say(t("agent_connections.disconnected"));
      void queries.invalidateQueries({ queryKey: KEY });
    },
    onError: (e) => {
      fail(e);
    },
  });
  return (
    <Card data-testid="agent-accounts">
      <CardContent className="flex flex-col gap-4">
        {region}
        {error !== null ? (
          <Nothing>{t("agent_connections.unavailable")}</Nothing>
        ) : data === undefined ? (
          <Loading />
        ) : (
          <agents.AgentConnections
            connections={data.list}
            name={(p) => data.names.get(p) ?? p}
            time={at}
            catalogue={catalogue}
            onDisconnect={(c) => {
              disconnect.mutate(c);
            }}
          />
        )}
      </CardContent>
    </Card>
  );
}
