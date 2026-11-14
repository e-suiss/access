// S2, S4, S5, S6, Changes (§8.5, §8.17.7, OP-153 m.3 (w), m.8 (e)): the Authority hub, read with
// this browser's device key. Every row says whose record it is and when it was read; Revoke is
// at most two steps away and is shown done only once Access recorded it (XI-3, XI-5); a lost
// answer is "Not confirmed — checking", retried with the same signed request (G39, HL-5). An
// agent is shown as an agent (XI-17); what it did is what its runtime reported (E64, X30); Stop
// is two rows (X13) and the aftermath is honest about the horizon (§8.13, §8.17.7.4).
import { agents, honesty, payment, WhyPanel, type Explanation } from "@suiss/access-react";
import { Alert } from "@suiss/access-ui/components/ui/alert";
import { Badge as UiBadge } from "@suiss/access-ui/components/ui/badge";
import { Button } from "@suiss/access-ui/components/ui/button";
import { cn } from "@suiss/access-ui/lib/utils";
import { useCallback, useEffect, useState, type ReactElement } from "react";

import { revoke, search, type Revoking } from "../lib/adp.js";
import { at, catalogue, locale, t } from "../lib/i18n.js";
import type { Confirm, Instance, SignatureView } from "../lib/instance.js";
import {
  Actions,
  Loading,
  Meta,
  MONO,
  Nothing,
  PageTitle,
  Panel,
  Rows as List,
} from "../lib/ui.js";
import { assemble, type ActivityRow, type Hub as HubData, type Read, type Row } from "./model.js";
import { relayStatus } from "./relay.js";
import { supportAccess, supportLine, type SupportRow } from "../support/model.js";

export type Section = "authority" | "activity" | "changes";

const ROW = "flex flex-col gap-2 rounded-xl border p-4";
const PANEL = "flex flex-col gap-3 rounded-xl border bg-muted/50 p-4";

/** IA-2: a change kind is shown only when the catalog has its text. */
function known(kind: string): boolean {
  return /^[a-z_]+$/.test(kind) && `change.${kind}` in catalogue;
}

async function read(
  p: Promise<{ readonly results: readonly Readonly<Record<string, unknown>>[] }>,
): Promise<Read> {
  try {
    return { kind: "answered", results: (await p).results };
  } catch {
    return { kind: "unknown" };
  }
}

/** How a Party is named to the viewer: the viewer is "you"; any other is its identifier. */
function namer(viewer: string): (party: string) => string {
  return (party) => (party === viewer ? t("party.you") : party);
}

function line(l: agents.Line): string {
  return t(l.text, l.args);
}

/** The runtime state of the uses made on `grant` (§8.17.7.4): what the runtime confirmed. */
function runtimeOn(uses: readonly ActivityRow[], grant: string): agents.RuntimeState {
  const control = uses.filter((u) => u.grant === grant).flatMap((u) => u.reports.control);
  return agents.runtimeOf({ attested: [], control });
}

function reportsOf(uses: readonly ActivityRow[], exercise: string): agents.Reports {
  const of = uses.filter((u) => u.exercise === exercise);
  return {
    attested: of.flatMap((u) => u.reports.attested),
    control: of.flatMap((u) => u.reports.control),
  };
}

/** XI-17 */
function Badge({ face, viewer }: { readonly face: agents.AgentFace; readonly viewer: string }) {
  return (
    <p className="text-sm text-muted-foreground" data-testid="agent-badge">
      <agents.AgentBadge face={face} name={namer(viewer)} catalogue={catalogue} />
    </p>
  );
}

/** §8.17.5.8, E31: the next authority check of the agent's open tasks on this Grant. */
function NextCheck({
  instance,
  grant,
}: {
  readonly instance: Instance;
  readonly grant: string;
}): ReactElement | null {
  const [next, setNext] = useState<number | undefined>(undefined);
  useEffect(() => {
    search(instance, "revocation-impact", { grant })
      .then((a) => {
        setNext(agents.nextCheck(agents.exposedOf(a.results[0]), Date.now()));
      })
      .catch(() => {
        setNext(undefined);
      });
  }, [instance, grant]);
  if (next === undefined) return null;
  return (
    <p className="text-sm text-muted-foreground" data-testid="agent-next-check">
      {t("agent.next_check", { time: at(next) })}
    </p>
  );
}

/** §8.17.7.1, X31: what the holder passed on from this Grant. */
function Passed({
  row,
  rows,
  viewer,
}: {
  readonly row: Row;
  readonly rows: readonly Row[];
  readonly viewer: string;
}): ReactElement | null {
  const passed = agents.passedOn(row.grant, rows);
  if (passed.length === 0 || row.who.party === undefined) return null;
  const name = namer(viewer);
  return (
    <ul className="text-sm text-muted-foreground" data-testid="passed-on">
      {passed.map((p) => (
        <li key={p.grant}>
          {t("subdelegation.passed", {
            agent: name(row.who.party ?? ""),
            holder: name(p.holder),
            limits: p.limits.map(line).join(", "),
          })}
        </li>
      ))}
    </ul>
  );
}

function Owner({ asOf }: { readonly asOf: number }): ReactElement {
  return (
    <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm text-muted-foreground">
      <UiBadge variant="outline">{t("hub.owner", { owner: t("owner.access") })}</UiBadge>{" "}
      {t("domain.current", { time: at(asOf) })}
    </p>
  );
}

function Capacities({ row }: { readonly row: Row }): ReactElement {
  return <span>{row.capacity.map((c) => t(c.text, { party: c.party ?? "" })).join(" · ")}</span>;
}

function Why({ row }: { readonly row: Row }): ReactElement {
  const [depth, setDepth] = useState<"default" | "expert" | "audit">("default");
  const fromRoot = typeof row.source["anchor"] === "string";
  const summary = t(fromRoot ? "why.from_root" : "why.from_delegation");
  const source = Object.entries(row.source).map(([k, v]) => `${k} ${String(v)}`);
  const explanation: Explanation = {
    source: "decision_record",
    when: "past",
    summary,
    owners: [
      {
        owner: t("owner.access"),
        line: `${summary} · ${row.capacity.map((c) => t(c.text, { party: c.party ?? "" })).join(" · ")}`,
      },
    ],
    couldChange: row.offers.filter((o) => o.available).map((o) => t(`action.${o.action}`)),
    expert: [
      `grant ${row.grant}`,
      ...source,
      ...(row.since === undefined ? [] : [`since ${String(row.since)}`]),
    ],
  };
  return (
    <div className="flex flex-col gap-2 rounded-xl bg-muted p-4" data-testid="why">
      <h4 className="font-semibold">{t("why.title")}</h4>
      <WhyPanel explanation={explanation} depth={depth} onDepth={setDepth} catalogue={catalogue} />
    </div>
  );
}

/** S4: Revoke → the impact and the decoded intent on one screen → Revoke. Then the Aftermath. */
function RevokePanel({
  instance,
  row,
  uses,
  stop,
  onDone,
  onClose,
}: {
  readonly instance: Instance;
  readonly row: Row;
  readonly uses: readonly ActivityRow[];
  /** "Stop" for an agent (§8.17.7.5): the same revoke, shown as two rows. */
  readonly stop: boolean;
  readonly onDone: () => void;
  readonly onClose: () => void;
}): ReactElement {
  const [impact, setImpact] = useState<number | null>(null);
  const [exposed, setExposed] = useState<readonly agents.Exposed[]>([]);
  const [view, setView] = useState<{ v: SignatureView; resolve: (b: boolean) => void } | null>(
    null,
  );
  const [state, setState] = useState<{ r: Revoking; next: honesty.Next; when: number } | null>(
    null,
  );
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    search(instance, "revocation-impact", { grant: row.grant })
      .then((a) => {
        const first = a.results[0] ?? {};
        const subtree = Array.isArray(first["subtree"]) ? first["subtree"].length : 0;
        setImpact(Math.max(0, subtree - 1));
        setExposed(agents.exposedOf(first).filter((e) => e.holder === row.who.party));
      })
      .catch(() => {
        setImpact(-1);
      });
    const confirm: Confirm = (v) =>
      new Promise<boolean>((resolve) => {
        setView({ v, resolve });
      });
    revoke(instance, confirm, row.grant)
      .then((s) => {
        const next = honesty.next(s.attempt, Date.now());
        setState({ r: s, next, when: Date.now() });
        if (next === "done") onDone();
      })
      .catch(() => {
        setFailed(true);
      });
  }, [instance, row, onDone]);
  const runtime = runtimeOn(uses, row.grant);
  const recorded = state?.r.shown === "outcome.confirmed";
  const stopRows =
    stop && row.agent !== undefined ? (
      <div data-testid="stop-rows">
        <agents.StopRows
          rows={agents.stopRows(
            runtime,
            recorded
              ? { text: "stop.authority_revoked", args: { time: at(state.when) } }
              : { text: "stop.authority_not_recorded" },
          )}
          catalogue={catalogue}
        />
        <Meta>{t("stop.runtime_note")}</Meta>
      </div>
    ) : null;
  if (state !== null) {
    const { r: done, next, when: now } = state;
    return (
      <section aria-label={t("aftermath.title")} data-testid="aftermath" className={PANEL}>
        <h4 className="font-semibold">{t("aftermath.title")}</h4>
        <p role="status" data-testid="outcome" className="font-semibold">
          {t(done.shown)}
        </p>
        {stopRows}
        {recorded && row.agent !== undefined && (
          <ul className="flex flex-col gap-2" data-testid="agent-aftermath">
            {(exposed.length === 0 ? [undefined] : exposed).map((e) => {
              const after =
                e === undefined
                  ? undefined
                  : agents.aftermath(e, reportsOf(uses, e.exercise), now, at);
              const state = after?.runtime ?? runtime;
              return (
                <li key={e?.exercise ?? "none"}>
                  <p data-testid="agent-status">
                    {t("agent.status.label", { status: t(agents.runtimeText(state)) })}
                  </p>
                  {after !== undefined && <p data-testid="agent-next">{line(after.next)}</p>}
                  {after?.containment === true && (
                    <p className="text-sm text-muted-foreground" data-testid="containment">
                      {t("aftermath.containment")}
                    </p>
                  )}
                </li>
              );
            })}
          </ul>
        )}
        {done.position !== undefined && (
          <p>{t("aftermath.recorded_at", { position: String(done.position) })}</p>
        )}
        {done.shown === "outcome.confirmed" && <p>{t("aftermath.past_uses")}</p>}
        <Actions>
          {next === "retry_same_nonce" && (
            <Button
              size="sm"
              onPress={() => {
                void done.retry().then((s) => {
                  const after = honesty.next(s.attempt, Date.now());
                  setState({ r: s, next: after, when: Date.now() });
                  if (after === "done") onDone();
                });
              }}
            >
              {t("action.read_again")}
            </Button>
          )}
          <Button variant="outline" size="sm" onPress={onClose}>
            {t("action.cancel")}
          </Button>
        </Actions>
      </section>
    );
  }
  return (
    <section aria-label={t("revoke.title")} data-testid="revoke" className={PANEL}>
      <h4 className="font-semibold">{t("revoke.title")}</h4>
      {stopRows}
      <h5 className="text-sm font-semibold">{t("revoke.impact")}</h5>
      <p data-testid="impact">
        {impact === null
          ? t("shell.loading")
          : impact <= 0
            ? t("revoke.impact_none")
            : t("revoke.impact_count", { count: String(impact) })}
      </p>
      {view !== null && (
        <dl className="flex flex-col gap-2">
          {view.v.intents.map((i) => (
            <div key={i.digest}>
              <dt className="text-sm font-semibold">
                {t("sign.action", { action: `${i.action.namespace}.${i.action.name}` })}
              </dt>
              <dd className={MONO}>
                {i.resources.map((r) => `${r.namespace}:${r.path.join("/")}`).join(", ")}
              </dd>
            </div>
          ))}
        </dl>
      )}
      {failed && <Alert variant="destructive">{t("shell.unavailable")}</Alert>}
      <Actions>
        <Button
          size="sm"
          isDisabled={view === null}
          onPress={() => {
            view?.resolve(true);
            setView(null);
          }}
        >
          {t("action.revoke")}
        </Button>
        <Button
          variant="outline"
          size="sm"
          onPress={() => {
            view?.resolve(false);
            onClose();
          }}
        >
          {t("action.keep")}
        </Button>
      </Actions>
    </section>
  );
}

function Rows({
  title,
  rows,
  all,
  uses,
  instance,
  onChanged,
  testid,
}: {
  readonly title: string;
  readonly rows: readonly Row[];
  readonly all: readonly Row[];
  readonly uses: readonly ActivityRow[];
  readonly instance: Instance;
  readonly onChanged: () => void;
  readonly testid: string;
}): ReactElement {
  const [open, setOpen] = useState<{ grant: string; what: "why" | "revoke" | "stop" } | null>(null);
  return (
    <Panel aria-label={title} data-testid={testid} title={title}>
      {rows.length === 0 && <Nothing>{t("hub.empty")}</Nothing>}
      <List>
        {rows.map((r) => {
          const revokeOffer = r.offers.find((o) => o.action === "revoke");
          return (
            <li key={`${testid}:${r.grant}`} className={cn("row", ROW)} data-grant={r.grant}>
              {r.agent !== undefined && <Badge face={r.agent} viewer={instance.party} />}
              <p>
                <span className={MONO}>{r.what.join(", ")}</span> · <Capacities row={r} />
              </p>
              {r.agent !== undefined && <NextCheck instance={instance} grant={r.grant} />}
              <Passed row={r} rows={all} viewer={instance.party} />
              {/* XI-14: Access's own limits; a financial limit is Pay's row, shown only from Pay */}
              <payment.LimitRows
                rows={payment.limitRows(r.limits, [], locale, (p) => t(`period.${p}`))}
                catalogue={catalogue}
              />
              {/* §8.17.9.8 */}
              {r.hrSource !== undefined && (
                <p className="text-sm text-muted-foreground" data-testid="hr-source">
                  {t("source.sync_from_hr", { issuer: r.hrSource })}
                </p>
              )}
              <p className="text-sm text-muted-foreground">
                {r.selection?.at === undefined
                  ? t(r.status)
                  : t(r.status, { time: at(r.selection.at) })}
                {/* XI-15, §8.17.5.7 */}
                {r.selection?.by !== undefined && (
                  <span data-testid="selection-said">
                    {" · "}
                    {r.selection.state === "ended"
                      ? t("selection.no_longer", { issuer: r.selection.by })
                      : t("selection.because", {
                          issuer: r.selection.by,
                          time: r.selection.statedAt === undefined ? "" : at(r.selection.statedAt),
                        })}
                  </span>
                )}
                {r.validUntil !== undefined && (
                  <> · {t("validity.valid_until", { time: at(r.validUntil) })}</>
                )}
              </p>
              <Owner asOf={r.asOf} />
              <Actions>
                <Button
                  variant="outline"
                  size="sm"
                  onPress={() => {
                    setOpen({ grant: r.grant, what: "why" });
                  }}
                >
                  {t("action.why")}
                </Button>
                {revokeOffer?.available === true ? (
                  <>
                    <Button
                      size="sm"
                      onPress={() => {
                        setOpen({ grant: r.grant, what: "revoke" });
                      }}
                    >
                      {t("action.revoke")}
                    </Button>
                    {r.agent !== undefined && (
                      <Button
                        variant="outline"
                        size="sm"
                        onPress={() => {
                          setOpen({ grant: r.grant, what: "stop" });
                        }}
                      >
                        {t("action.stop_agent")}
                      </Button>
                    )}
                  </>
                ) : (
                  revokeOffer?.whoCan !== undefined && (
                    <span className="text-sm text-muted-foreground">{t(revokeOffer.whoCan)}</span>
                  )
                )}
              </Actions>
              {open?.grant === r.grant && open.what === "why" && <Why row={r} />}
              {open?.grant === r.grant && open.what !== "why" && (
                <RevokePanel
                  instance={instance}
                  row={r}
                  uses={uses}
                  stop={open.what === "stop"}
                  onDone={onChanged}
                  onClose={() => {
                    setOpen(null);
                  }}
                />
              )}
            </li>
          );
        })}
      </List>
    </Panel>
  );
}

/** The hub sections over this browser's device Instance. */
export function Hub({
  instance,
  section,
}: {
  readonly instance: Instance;
  readonly section: Section;
}): ReactElement {
  const [hub, setHub] = useState<HubData | null>(null);
  const [delayed, setDelayed] = useState(false);
  const [given, setGiven] = useState<readonly SupportRow[]>([]);
  const load = useCallback(() => {
    // §8.16, XI-17
    void supportAccess().then(setGiven);
    // §8.13, INV-24: a delay is a notice; no row changes with it
    void relayStatus().then((s) => {
      setDelayed(s?.delayed === true);
    });
    const query = { party: instance.party };
    void Promise.all([
      read(search(instance, "inventory", query)),
      read(search(instance, "activity", query)),
      read(search(instance, "changes", {})),
    ]).then(([inventory, uses, changes]) => {
      setHub(assemble(instance.party, Date.now(), inventory, uses, changes, known));
    });
  }, [instance]);
  useEffect(load, [load]);
  if (hub === null) return <Loading status rows={3} />;
  const all = [...hub.yourAuthority, ...hub.actingForYou, ...hub.sharedFromYou];
  return (
    <div className="flex flex-col gap-6" data-testid="hub">
      <div className="flex flex-wrap items-center justify-between gap-3">
        {section === "authority" ? <PageTitle>{t("nav.authority")}</PageTitle> : <span />}
        <Button variant="outline" size="sm" onPress={load}>
          {t("action.read_again")}
        </Button>
      </div>
      <p className="text-sm text-muted-foreground" data-testid="domain-status">
        {hub.status === "domain.current"
          ? t("domain.current", { time: at(hub.asOf) })
          : t("domain.unreachable")}
      </p>
      {hub.notices.map((n) => (
        <Alert key={n} role="note">
          {t(n)}
        </Alert>
      ))}
      {/* §8.13, OP-156 m.6 (d) */}
      {hub.status === "domain.unreachable" && (
        <Alert variant="destructive" data-testid="access-unavailable">
          {t("status.access_unavailable")}
        </Alert>
      )}
      {delayed && (
        <Alert role="note" data-testid="notifications-delayed">
          {t("status.notifications_delayed")}
        </Alert>
      )}
      {section === "authority" && (
        <>
          <Rows
            title={t("hub.your_authority")}
            rows={hub.yourAuthority}
            all={all}
            uses={hub.activity}
            instance={instance}
            onChanged={load}
            testid="your-authority"
          />
          <Rows
            title={t("hub.acting_for_you")}
            rows={hub.actingForYou}
            all={all}
            uses={hub.activity}
            instance={instance}
            onChanged={load}
            testid="acting-for-you"
          />
          <Rows
            title={t("hub.shared_from_you")}
            rows={hub.sharedFromYou}
            all={all}
            uses={hub.activity}
            instance={instance}
            onChanged={load}
            testid="shared-from-you"
          />
          {hub.roots.length > 0 && (
            <Panel aria-label={t("hub.roots")} title={t("hub.roots")}>
              <ul className="divide-y text-sm">
                {hub.roots.map((r) => (
                  <li key={r.anchor} className="py-2">
                    <span className={MONO}>{r.anchor}</span> · {t(r.confirm)}
                  </li>
                ))}
              </ul>
            </Panel>
          )}
        </>
      )}
      {section === "activity" && (
        <Panel
          aria-label={t("hub.activity")}
          data-testid="activity"
          title={t("hub.activity")}
          description={t("hub.activity_note")}
        >
          {hub.activity.length === 0 && <Nothing>{t("hub.empty")}</Nothing>}
          <List>
            {hub.activity.map((a) => (
              <li key={a.pos} className={cn("row", ROW)} data-testid="use">
                {a.agent !== undefined && <Badge face={a.agent} viewer={instance.party} />}
                {supportLine(a.grant, given, a.at === undefined ? "" : at(a.at)) ?? (
                  <>
                    {t(a.text)} · {t(a.capacity.text, { party: a.capacity.party ?? "" })}
                    {a.at !== undefined && <> · {at(a.at)}</>}
                  </>
                )}
                {/* E64, X30 */}
                {(a.agent !== undefined || a.reports.attested.length > 0) && (
                  <agents.OutcomeLabels
                    lines={agents.outcomeLines(a.reports)}
                    name={namer(instance.party)}
                    catalogue={catalogue}
                  />
                )}
                <Owner asOf={hub.asOf} />
              </li>
            ))}
          </List>
        </Panel>
      )}
      {section === "changes" && (
        <Panel
          aria-label={t("hub.changes")}
          data-testid="changes"
          title={t("hub.changes")}
          description={t("hub.changes_note")}
        >
          {hub.hygiene.length > 0 && (
            <section
              data-testid="hygiene"
              aria-label={t("hygiene.suggestion")}
              className="flex flex-col gap-3 rounded-xl bg-muted p-4"
            >
              <p className="text-sm font-semibold">{t("hygiene.suggestion")}</p>
              <List>
                {hub.hygiene.map((h) => (
                  <li key={h.kind} className={cn("row", ROW, "bg-background")}>
                    {t(h.text, { count: String(h.count) })}
                    <Owner asOf={hub.asOf} />
                  </li>
                ))}
              </List>
            </section>
          )}
          {hub.changes.length === 0 && <Nothing>{t("hub.empty")}</Nothing>}
          <List>
            {hub.changes.map((c) => (
              <li key={`${String(c.pos)}:${c.about}`} className={cn("row", ROW)}>
                <p>
                  {t(c.text)} <span className={MONO}>{c.about}</span>
                  {c.at !== undefined && <> · {at(c.at)}</>}
                </p>
                <Owner asOf={hub.asOf} />
              </li>
            ))}
          </List>
        </Panel>
      )}
    </div>
  );
}
