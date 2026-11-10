// S2, S4, S5, S6, Changes (§8.5, §8.17.7, OP-153 m.3 (w), m.8 (e)): the Authority hub, read with
// this browser's device key. Every row says whose record it is and when it was read; Revoke is
// at most two steps away and is shown done only once Access recorded it (XI-3, XI-5); a lost
// answer is "Not confirmed — checking", retried with the same signed request (G39, HL-5). An
// agent is shown as an agent (XI-17); what it did is what its runtime reported (E64, X30); Stop
// is two rows (X13) and the aftermath is honest about the horizon (§8.13, §8.17.7.4).
import { agents, honesty, payment, WhyPanel, type Explanation } from "@suiss/access-react";
import { useCallback, useEffect, useState, type ReactElement } from "react";

import { revoke, search, type Revoking } from "../lib/adp.js";
import { at, catalogue, locale, t } from "../lib/i18n.js";
import type { Confirm, Instance, SignatureView } from "../lib/instance.js";
import { assemble, type ActivityRow, type Hub as HubData, type Read, type Row } from "./model.js";
import { relayStatus } from "./relay.js";

export type Section = "authority" | "activity" | "changes";

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
    <p className="meta" data-testid="agent-badge">
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
    <p className="meta" data-testid="agent-next-check">
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
    <ul className="meta" data-testid="passed-on">
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
    <p className="owner">
      <span className="badge">{t("hub.owner", { owner: t("owner.access") })}</span>{" "}
      {t("domain.current", { time: at(asOf) })}
    </p>
  );
}

function Capacities({ row }: { readonly row: Row }): ReactElement {
  return (
    <span className="capacity">
      {row.capacity.map((c) => t(c.text, { party: c.party ?? "" })).join(" · ")}
    </span>
  );
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
    <div className="why" data-testid="why">
      <h4>{t("why.title")}</h4>
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
        <p className="notice">{t("stop.runtime_note")}</p>
      </div>
    ) : null;
  if (state !== null) {
    const { r: done, next, when: now } = state;
    return (
      <section className="panel" aria-label={t("aftermath.title")} data-testid="aftermath">
        <h4>{t("aftermath.title")}</h4>
        <p role="status" data-testid="outcome">
          {t(done.shown)}
        </p>
        {stopRows}
        {recorded && row.agent !== undefined && (
          <ul className="rows" data-testid="agent-aftermath">
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
                    <p className="notice" data-testid="containment">
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
        {next === "retry_same_nonce" && (
          <button
            type="button"
            onClick={() => {
              void done.retry().then((s) => {
                const after = honesty.next(s.attempt, Date.now());
                setState({ r: s, next: after, when: Date.now() });
                if (after === "done") onDone();
              });
            }}
          >
            {t("action.read_again")}
          </button>
        )}
        <button type="button" className="secondary" onClick={onClose}>
          {t("action.cancel")}
        </button>
      </section>
    );
  }
  return (
    <section className="panel" aria-label={t("revoke.title")} data-testid="revoke">
      <h4>{t("revoke.title")}</h4>
      {stopRows}
      <h5>{t("revoke.impact")}</h5>
      <p data-testid="impact">
        {impact === null
          ? t("shell.loading")
          : impact <= 0
            ? t("revoke.impact_none")
            : t("revoke.impact_count", { count: String(impact) })}
      </p>
      {view !== null && (
        <dl className="facts">
          {view.v.intents.map((i) => (
            <div key={i.digest}>
              <dt>{t("sign.action", { action: `${i.action.namespace}.${i.action.name}` })}</dt>
              <dd className="mono">
                {i.resources.map((r) => `${r.namespace}:${r.path.join("/")}`).join(", ")}
              </dd>
            </div>
          ))}
        </dl>
      )}
      {failed && <p role="alert">{t("shell.unavailable")}</p>}
      <div className="actions">
        <button
          type="button"
          disabled={view === null}
          onClick={() => {
            view?.resolve(true);
            setView(null);
          }}
        >
          {t("action.revoke")}
        </button>
        <button
          type="button"
          className="secondary"
          onClick={() => {
            view?.resolve(false);
            onClose();
          }}
        >
          {t("action.keep")}
        </button>
      </div>
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
    <section aria-label={title} data-testid={testid}>
      <h3>{title}</h3>
      {rows.length === 0 && <p>{t("hub.empty")}</p>}
      <ul className="rows">
        {rows.map((r) => {
          const revokeOffer = r.offers.find((o) => o.action === "revoke");
          return (
            <li key={`${testid}:${r.grant}`} className="row" data-grant={r.grant}>
              {r.agent !== undefined && <Badge face={r.agent} viewer={instance.party} />}
              <p>
                <span className="mono">{r.what.join(", ")}</span> · <Capacities row={r} />
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
                <p className="meta" data-testid="hr-source">
                  {t("source.sync_from_hr", { issuer: r.hrSource })}
                </p>
              )}
              <p className="meta">
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
              <div className="actions">
                <button
                  type="button"
                  className="secondary"
                  onClick={() => {
                    setOpen({ grant: r.grant, what: "why" });
                  }}
                >
                  {t("action.why")}
                </button>
                {revokeOffer?.available === true ? (
                  <>
                    <button
                      type="button"
                      onClick={() => {
                        setOpen({ grant: r.grant, what: "revoke" });
                      }}
                    >
                      {t("action.revoke")}
                    </button>
                    {r.agent !== undefined && (
                      <button
                        type="button"
                        className="secondary"
                        onClick={() => {
                          setOpen({ grant: r.grant, what: "stop" });
                        }}
                      >
                        {t("action.stop_agent")}
                      </button>
                    )}
                  </>
                ) : (
                  revokeOffer?.whoCan !== undefined && (
                    <span className="meta">{t(revokeOffer.whoCan)}</span>
                  )
                )}
              </div>
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
      </ul>
    </section>
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
  const load = useCallback(() => {
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
  if (hub === null) return <p role="status">{t("shell.loading")}</p>;
  const all = [...hub.yourAuthority, ...hub.actingForYou, ...hub.sharedFromYou];
  return (
    <div className="hub" data-testid="hub">
      <p className="meta" data-testid="domain-status">
        {hub.status === "domain.current"
          ? t("domain.current", { time: at(hub.asOf) })
          : t("domain.unreachable")}
      </p>
      {hub.notices.map((n) => (
        <p key={n} className="notice">
          {t(n)}
        </p>
      ))}
      {/* §8.13, OP-156 m.6 (d) */}
      {hub.status === "domain.unreachable" && (
        <p className="notice" role="alert" data-testid="access-unavailable">
          {t("status.access_unavailable")}
        </p>
      )}
      {delayed && (
        <p className="notice" data-testid="notifications-delayed">
          {t("status.notifications_delayed")}
        </p>
      )}
      <button type="button" className="secondary" onClick={load}>
        {t("action.read_again")}
      </button>
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
            <section aria-label={t("hub.roots")}>
              <h3>{t("hub.roots")}</h3>
              <ul>
                {hub.roots.map((r) => (
                  <li key={r.anchor}>
                    <span className="mono">{r.anchor}</span> · {t(r.confirm)}
                  </li>
                ))}
              </ul>
            </section>
          )}
        </>
      )}
      {section === "activity" && (
        <section aria-label={t("hub.activity")} data-testid="activity">
          <h3>{t("hub.activity")}</h3>
          <p className="notice">{t("hub.activity_note")}</p>
          {hub.activity.length === 0 && <p>{t("hub.empty")}</p>}
          <ul className="rows">
            {hub.activity.map((a) => (
              <li key={a.pos} className="row" data-testid="use">
                {a.agent !== undefined && <Badge face={a.agent} viewer={instance.party} />}
                {t(a.text)} · {t(a.capacity.text, { party: a.capacity.party ?? "" })}
                {a.at !== undefined && <> · {at(a.at)}</>}
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
          </ul>
        </section>
      )}
      {section === "changes" && (
        <section aria-label={t("hub.changes")} data-testid="changes">
          <h3>{t("hub.changes")}</h3>
          <p className="notice">{t("hub.changes_note")}</p>
          {hub.changes.length === 0 && <p>{t("hub.empty")}</p>}
          <ul className="rows">
            {hub.changes.map((c) => (
              <li key={`${String(c.pos)}:${c.about}`} className="row">
                {t(c.text)} <span className="mono">{c.about}</span>
                {c.at !== undefined && <> · {at(c.at)}</>}
                <Owner asOf={hub.asOf} />
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}
