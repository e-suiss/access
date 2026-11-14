// §8.5 S7, §11.16, XI-17, AG-19, AG-21, AG-41, OP-154 m.3 (c), (e), (f): the realm's agent
// registry. Each agent is shown as an agent with its kind, operator, sponsors and status; one
// without an active sponsor reads suspended; its running copies end one signed change each, as
// containment ends them, and nothing here changes authority without a signature.
import { useState, type ReactElement } from "react";

import { Badge as SuissBadge } from "@suiss/access-ui/components/ui/badge";
import { Button } from "@suiss/access-ui/components/ui/button";
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@suiss/access-ui/components/ui/table";

import { t } from "../i18n/index.js";
import { adminGet } from "../lib/admin.js";
import { metaWrite, type MetaResult } from "../lib/meta.js";
import { BULLETS, FACTS, H4, HINT, MONO, Notice, REPORT } from "../ui.js";
import { at, type Ctx, Panel, Show, useLoad, useRun } from "./parts.js";

interface AgentSummary {
  readonly agent: string;
  readonly display_name: string;
  readonly agent_kind: string;
  readonly operator: string;
  readonly status: string;
  readonly sponsors?: readonly string[];
}

interface Sponsorship {
  readonly account_id: string;
  readonly assigned_at: string;
  readonly ended_at?: string | null;
  readonly ended_by?: string | null;
}

interface Agent extends AgentSummary {
  readonly description?: string | null;
  readonly status_at: string;
  readonly connections: readonly string[];
  readonly last_run_at?: string | null;
  readonly created_at: string;
  readonly sponsorships: readonly Sponsorship[];
  readonly instances?: readonly string[];
}

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
                  onPress={() => {
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

/** §8.5 S7, OP-154 m.3 (e): the realm's agents, one opened at a time. */
export function Agents({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const realm = encodeURIComponent(ctx.session.realm);
  const list = useLoad(() =>
    adminGet<{ readonly items: readonly AgentSummary[] }>(ctx.instance, `realms/${realm}/agents`),
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
                          onPress={() => {
                            setOpen(a.agent);
                            run(() =>
                              adminGet<Agent>(
                                ctx.instance,
                                `realms/${realm}/agents/${encodeURIComponent(a.agent)}`,
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
