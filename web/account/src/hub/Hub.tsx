// S2, S4, S5, S6, Changes (§8.5, §8.17.7, OP-153 m.3 (w), m.8 (e)): the Authority hub, read with
// this browser's device key. Every row says whose record it is and when it was read; Revoke is
// at most two steps away and is shown done only once Access recorded it (XI-3, XI-5); a lost
// answer is "Not confirmed — checking", retried with the same signed request (G39, HL-5).
import { honesty, WhyPanel, type Explanation } from "@suiss/access-react";
import { useCallback, useEffect, useState, type ReactElement } from "react";

import { revoke, search, type Revoking } from "../lib/adp.js";
import { at, catalogue, t } from "../lib/i18n.js";
import type { Confirm, Instance, SignatureView } from "../lib/instance.js";
import { assemble, type Hub as HubData, type Read, type Row } from "./model.js";

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
  onDone,
  onClose,
}: {
  readonly instance: Instance;
  readonly row: Row;
  readonly onDone: () => void;
  readonly onClose: () => void;
}): ReactElement {
  const [impact, setImpact] = useState<number | null>(null);
  const [view, setView] = useState<{ v: SignatureView; resolve: (b: boolean) => void } | null>(
    null,
  );
  const [state, setState] = useState<{ r: Revoking; next: honesty.Next } | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    search(instance, "revocation-impact", { grant: row.grant })
      .then((a) => {
        const first = a.results[0] ?? {};
        const subtree = Array.isArray(first["subtree"]) ? first["subtree"].length : 0;
        setImpact(Math.max(0, subtree - 1));
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
        setState({ r: s, next });
        if (next === "done") onDone();
      })
      .catch(() => {
        setFailed(true);
      });
  }, [instance, row, onDone]);
  if (state !== null) {
    const { r: done, next } = state;
    return (
      <section className="panel" aria-label={t("aftermath.title")} data-testid="aftermath">
        <h4>{t("aftermath.title")}</h4>
        <p role="status" data-testid="outcome">
          {t(done.shown)}
        </p>
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
                setState({ r: s, next: after });
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
  instance,
  onChanged,
  testid,
}: {
  readonly title: string;
  readonly rows: readonly Row[];
  readonly instance: Instance;
  readonly onChanged: () => void;
  readonly testid: string;
}): ReactElement {
  const [open, setOpen] = useState<{ grant: string; what: "why" | "revoke" } | null>(null);
  return (
    <section aria-label={title} data-testid={testid}>
      <h3>{title}</h3>
      {rows.length === 0 && <p>{t("hub.empty")}</p>}
      <ul className="rows">
        {rows.map((r) => {
          const revokeOffer = r.offers.find((o) => o.action === "revoke");
          return (
            <li key={`${testid}:${r.grant}`} className="row" data-grant={r.grant}>
              <p>
                <span className="mono">{r.what.join(", ")}</span> · <Capacities row={r} />
              </p>
              <p className="meta">
                {t(r.status)}
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
                  <button
                    type="button"
                    onClick={() => {
                      setOpen({ grant: r.grant, what: "revoke" });
                    }}
                  >
                    {t("action.revoke")}
                  </button>
                ) : (
                  revokeOffer?.whoCan !== undefined && (
                    <span className="meta">{t(revokeOffer.whoCan)}</span>
                  )
                )}
              </div>
              {open?.grant === r.grant && open.what === "why" && <Why row={r} />}
              {open?.grant === r.grant && open.what === "revoke" && (
                <RevokePanel
                  instance={instance}
                  row={r}
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
  const load = useCallback(() => {
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
      <button type="button" className="secondary" onClick={load}>
        {t("action.read_again")}
      </button>
      {section === "authority" && (
        <>
          <Rows
            title={t("hub.your_authority")}
            rows={hub.yourAuthority}
            instance={instance}
            onChanged={load}
            testid="your-authority"
          />
          <Rows
            title={t("hub.acting_for_you")}
            rows={hub.actingForYou}
            instance={instance}
            onChanged={load}
            testid="acting-for-you"
          />
          <Rows
            title={t("hub.shared_from_you")}
            rows={hub.sharedFromYou}
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
              <li key={a.pos} className="row">
                {t(a.text)} · {t(a.capacity.text, { party: a.capacity.party ?? "" })}
                {a.at !== undefined && <> · {at(a.at)}</>}
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
