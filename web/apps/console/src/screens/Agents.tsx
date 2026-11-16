// §8.5 S7, §11.16, XI-17, AG-19, AG-21, AG-41, OP-154 m.3 (c), (e), (f): the environment's agent
// registry. Each agent is shown as an agent with its kind, operator, sponsors and status; one
// without an active sponsor reads suspended; its running copies end one signed change each, as
// containment ends them, and nothing here changes authority without a signature.

import { Badge as SuissBadge } from "@access/ui/components/badge";
import { Button } from "@access/ui/components/button";
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@access/ui/components/table";
import { type ReactElement, useState } from "react";
import * as v from "valibot";

import { t } from "../i18n/index.js";
import { adminGet, items } from "../lib/admin.js";
import { type MetaResult, metaWrite } from "../lib/meta.js";
import { BULLETS, FACTS, H4, HINT, MONO, Notice, REPORT } from "../ui.js";
import { at, type Ctx, Panel, readKey, Show, useLoad, useRun } from "./parts.js";

// OP-159 m.46 (f)
const summary = {
  agent: v.string(),
  display_name: v.string(),
  agent_kind: v.string(),
  operator: v.string(),
  status: v.string(),
  sponsors: v.exactOptional(v.array(v.string())),
};

const AgentSummary = v.looseObject(summary);

type AgentSummary = v.InferOutput<typeof AgentSummary>;

const AgentSummaries = items(AgentSummary);

const Sponsorship = v.looseObject({
  account_id: v.string(),
  assigned_at: v.string(),
  ended_at: v.exactOptional(v.nullable(v.string())),
  ended_by: v.exactOptional(v.nullable(v.string())),
});

const Agent = v.looseObject({
  ...summary,
  description: v.exactOptional(v.nullable(v.string())),
  status_at: v.string(),
  connections: v.array(v.string()),
  last_run_at: v.exactOptional(v.nullable(v.string())),
  created_at: v.string(),
  sponsorships: v.array(Sponsorship),
  instances: v.exactOptional(v.array(v.string())),
});

type Agent = v.InferOutput<typeof Agent>;

function statusText(s: string): string {
  if (s === "active") return t("agentActive");
  if (s === "suspended") return t("agentSuspended");
  if (s === "retired") return t("agentRetired");
  return t("agentStatusOther");
}

/** XI-17 */
function Badge({ a }: { readonly a: AgentSummary }): ReactElement {
  return (
    <SuissBadge variant="outline" data-party-kind="agent" data-testid="agent-badge">
      {t("agentBadge", { operator: a.operator })}
    </SuissBadge>
  );
}

function AgentView({ a, ctx }: { readonly a: Agent; readonly ctx: Ctx }): ReactElement {
  const [done, setDone] = useState<Readonly<Record<string, MetaResult>>>({});
  const [w, write] = useRun<MetaResult>();
  const end = (instance: string) => {
    write(() =>
      metaWrite(ctx.instance, ctx.confirm, ctx.instance.party ?? "", {
        instance_terminate: { instance },
      }).then((r) => {
        setDone((d) => ({ ...d, [instance]: r }));
        return r;
      }),
    );
  };
  const open = a.sponsorships.filter((s) => s.ended_at === undefined || s.ended_at === null);
  return (
    <article className={REPORT} data-testid="agent">
      <h4 className="flex flex-wrap items-center gap-2 text-base font-semibold">
        {a.display_name} <Badge a={a} />
      </h4>
      <dl className={FACTS}>
        <dt>{t("agentId")}</dt>
        <dd className={MONO}>{a.agent}</dd>
        <dt>{t("agentKind")}</dt>
        <dd>{a.agent_kind}</dd>
        <dt>{t("agentOperator")}</dt>
        <dd className={MONO}>{a.operator}</dd>
        <dt>{t("agentStatus")}</dt>
        <dd data-testid="agent-status">
          {statusText(a.status)} · {at(a.status_at)}
        </dd>
        <dt>{t("agentLastRun")}</dt>
        <dd>
          {a.last_run_at === undefined || a.last_run_at === null
            ? t("agentNotReported")
            : at(a.last_run_at)}
        </dd>
      </dl>
      {a.status === "suspended" && (
        <Notice role="note" tone="warning" data-testid="agent-no-sponsor">
          {t("agentNoSponsor")}
        </Notice>
      )}
      <h5 className={H4}>{t("agentSponsors")}</h5>
      {open.length === 0 ? (
        <p className={HINT}>{t("agentNoSponsors")}</p>
      ) : (
        <ul data-testid="agent-sponsors" className={BULLETS}>
          {open.map((s) => (
            <li key={`${s.account_id}:${s.assigned_at}`} className={MONO}>
              {s.account_id} · {t("agentSponsorSince", { at: at(s.assigned_at) })}
            </li>
          ))}
        </ul>
      )}
      <h5 className={H4}>{t("agentSponsorChanges")}</h5>
      <ul data-testid="agent-sponsorships" className={BULLETS}>
        {a.sponsorships.map((s) => (
          <li key={`${s.account_id}:${s.assigned_at}`}>
            <span className={MONO}>{s.account_id}</span> ·{" "}
            {s.ended_at === undefined || s.ended_at === null
              ? t("agentSponsorSince", { at: at(s.assigned_at) })
              : t("agentSponsorEnded", { at: at(s.ended_at), by: s.ended_by ?? "" })}
          </li>
        ))}
      </ul>
      <h5 className={H4}>{t("agentConnections")}</h5>
      {a.connections.length === 0 ? (
        <p className={HINT}>{t("agentNoConnections")}</p>
      ) : (
        <ul data-testid="agent-connections" className={BULLETS}>
          {a.connections.map((c) => (
            <li key={c} className={MONO}>
              {c}
            </li>
          ))}
        </ul>
      )}
      <h5 className={H4}>{t("agentCopies")}</h5>
      <p className={HINT}>{t("agentCopiesHow")}</p>
      {(a.instances ?? []).length === 0 ? (
        <p className={HINT}>{t("agentNoCopies")}</p>
      ) : (
        <ul data-testid="agent-instances" className="flex flex-col gap-2">
          {(a.instances ?? []).map((i) => (
            <li key={i} className="flex flex-wrap items-center gap-3">
              <span className={MONO}>{i}</span>
              {done[i]?.decision === true ? (
                <span role="status" className="text-sm">
                  {t("changeRecorded", { exercise: done[i].exercise ?? "" })}
                </span>
              ) : (
                <Button
                  variant="destructive"
                  size="sm"
                  onClick={() => {
                    end(i);
                  }}
                >
                  {t("agentEndCopy")}
                </Button>
              )}
            </li>
          ))}
        </ul>
      )}
      <Show l={w}>{() => <></>}</Show>
    </article>
  );
}

/** §8.5 S7, OP-154 m.3 (e): the environment's agents, one opened at a time. */
export function Agents({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const environment = encodeURIComponent(ctx.session.environment);
  const list = useLoad(readKey(ctx, `envs/${environment}/agents`), () =>
    adminGet(ctx.instance, `envs/${environment}/agents`, AgentSummaries),
  );
  const [open, setOpen] = useState<string | undefined>(undefined);
  const [one, run] = useRun<Agent>();
  return (
    <>
      <p>{t("agentsIntro")}</p>
      <Show l={list}>
        {(l) =>
          l.items.length === 0 ? (
            <p className={HINT}>{t("agentsNone")}</p>
          ) : (
            <Table data-testid="agent-list" className="caption-top">
              <TableCaption className="sr-only">{t("screenAgents")}</TableCaption>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead scope="col">{t("agentName")}</TableHead>
                  <TableHead scope="col">{t("agentKind")}</TableHead>
                  <TableHead scope="col">{t("agentStatus")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {l.items.map((a) => (
                  <TableRow key={a.agent} data-agent={a.agent}>
                    <TableCell>
                      <span className="flex flex-wrap items-center gap-2">
                        <Button
                          variant={open === a.agent ? "tinted" : "outline"}
                          size="sm"
                          aria-pressed={open === a.agent}
                          onClick={() => {
                            setOpen(a.agent);
                            run(() =>
                              adminGet(
                                ctx.instance,
                                `envs/${environment}/agents/${encodeURIComponent(a.agent)}`,
                                Agent,
                              ),
                            );
                          }}
                        >
                          {a.display_name}
                        </Button>
                        <Badge a={a} />
                      </span>
                    </TableCell>
                    <TableCell>{a.agent_kind}</TableCell>
                    <TableCell>{statusText(a.status)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )
        }
      </Show>
      {open !== undefined && (
        <Panel id="agent-open" title={t("agentOpen")}>
          <Show l={one}>{(a) => <AgentView a={a} ctx={ctx} />}</Show>
        </Panel>
      )}
    </>
  );
}
