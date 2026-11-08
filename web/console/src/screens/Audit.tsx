// §8.17.4.1 S9, OP-151 m.8, §5.4, RR-13: the Audit section. Records are read at audit scope with
// `reason_admin`, the StateBasis and the expanded `basis_ref`; deeper identities stay
// pseudonymous; totals are given only within the reader's disclosure (m.8 (g)); an export is a
// signed Exercise of its own.
import { useState, type ReactElement } from "react";

import { t } from "../i18n/index.js";
import {
  explain,
  type Explained,
  exportAudit,
  type Exported,
  search,
  type SearchAnswer,
} from "../lib/adp.js";
import { type MetaPayload, type MetaResult, metaWrite } from "../lib/meta.js";
import { Explanation } from "./Explanation.js";
import { type Ctx, Field, PageCount, Panel, Show, useRun } from "./parts.js";
import {
  type CompromiseImpact,
  CompromiseView,
  type RevocationImpact,
  RevocationView,
} from "./Reports.js";

function split(action: string): { namespace: string; name: string } {
  const i = action.lastIndexOf(".");
  return i < 0
    ? { namespace: "", name: action }
    : { namespace: action.slice(0, i), name: action.slice(i + 1) };
}

function resourceOf(text: string): { namespace: string; path: string[] } {
  const [namespace = "", path = ""] = text.split(":", 2);
  return { namespace, path: path.split("/").filter((p) => p !== "") };
}

export function Records({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const [position, setPosition] = useState("");
  const [action, setAction] = useState("");
  const [resource, setResource] = useState("");
  const [subject, setSubject] = useState(ctx.session.account);
  const [record, runRecord] = useRun<Explained>();
  const [found, runSearch] = useRun<SearchAnswer<unknown>>();
  const [token, setToken] = useState<string | undefined>(undefined);
  const searchPage = (next?: string) => {
    const a = split(action);
    runSearch(() =>
      search(
        ctx.instance,
        "subject",
        { action: { ...a, major: 1 }, resource: resourceOf(resource) },
        next,
      ).then((r) => {
        setToken(r.page.next_token);
        return r;
      }),
    );
  };
  return (
    <>
      <p>{t("recordsIntro")}</p>
      <Panel id="record" title={t("recordsPosition")}>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const a = split(action);
            runRecord(() =>
              explain(
                ctx.instance,
                subject,
                { action: { ...a, major: 1 }, resources: [resourceOf(resource)] },
                { position: Number(position), scope: "audit" },
              ),
            );
          }}
        >
          <Field
            id="rec-pos"
            label={t("recordsPosition")}
            value={position}
            onChange={setPosition}
            type="number"
          />
          <Field
            id="rec-subject"
            label={t("recordsSubject")}
            value={subject}
            onChange={setSubject}
          />
          <Field id="rec-action" label={t("recordsAction")} value={action} onChange={setAction} />
          <Field
            id="rec-resource"
            label={t("recordsResource")}
            value={resource}
            onChange={setResource}
          />
          <button type="submit">{t("run")}</button>
          <button
            type="button"
            onClick={() => {
              searchPage();
            }}
          >
            {t("recordsSearchTitle")}
          </button>
        </form>
        <Show l={record}>{(a) => <Explanation answer={a} record={Number(position)} />}</Show>
        <Show l={found}>
          {(a) => (
            <>
              <PageCount page={a.page} shown={a.results.length} />
              <ul data-testid="search-results">
                {a.results.map((r, i) => (
                  <li key={String(i)} className="mono">
                    {JSON.stringify(r)}
                  </li>
                ))}
              </ul>
              {token !== undefined && token !== "" && (
                <button
                  type="button"
                  onClick={() => {
                    searchPage(token);
                  }}
                >
                  {t("nextPage")}
                </button>
              )}
            </>
          )}
        </Show>
      </Panel>
    </>
  );
}

/** §5.4, §16.5.1, XI-3: what a revocation affects and how long issued allowances may last. */
export function Revocation({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const [grant, setGrant] = useState("");
  const [instance, setInstance] = useState("");
  const [l, run] = useRun<SearchAnswer<RevocationImpact>>();
  return (
    <>
      <p>{t("revocationIntro")}</p>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          run(() =>
            search<RevocationImpact>(
              ctx.instance,
              "revocation-impact",
              grant !== "" ? { grant } : { instance },
            ),
          );
        }}
      >
        <Field id="rev-grant" label={t("revocationGrant")} value={grant} onChange={setGrant} />
        <Field
          id="rev-instance"
          label={t("revocationInstance")}
          value={instance}
          onChange={setInstance}
        />
        <button type="submit">{t("run")}</button>
      </form>
      <Show l={l}>
        {(a) => (
          <>
            {a.results.map((r, i) => (
              <RevocationView key={String(i)} r={r} />
            ))}
          </>
        )}
      </Show>
    </>
  );
}

type Compromised = "instance" | "issuer" | "key";

/** RR-13, SEC15, EI-22: uses in a window whose results are unknown are said to be unknown. */
export function Unknown({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const [kind, setKind] = useState<Compromised>("instance");
  const [value, setValue] = useState("");
  const [from, setFrom] = useState("");
  const [until, setUntil] = useState("");
  const [l, run] = useRun<SearchAnswer<CompromiseImpact>>();
  return (
    <>
      <p>{t("unknownIntro")}</p>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          run(() =>
            search<CompromiseImpact>(ctx.instance, "compromise-impact", {
              [kind]: value,
              window: { from: Number(from), until: Number(until) },
            }),
          );
        }}
      >
        <p className="field">
          <label htmlFor="unk-kind">{t("unknownKind")}</label>
          <select
            id="unk-kind"
            value={kind}
            onChange={(e) => {
              setKind(e.target.value as Compromised);
            }}
          >
            <option value="instance">{t("unknownKindInstance")}</option>
            <option value="issuer">{t("unknownKindIssuer")}</option>
            <option value="key">{t("unknownKindKey")}</option>
          </select>
        </p>
        <Field id="unk-value" label={t("unknownValue")} value={value} onChange={setValue} />
        <Field
          id="unk-from"
          label={t("unknownFrom")}
          value={from}
          onChange={setFrom}
          type="number"
        />
        <Field
          id="unk-until"
          label={t("unknownUntil")}
          value={until}
          onChange={setUntil}
          type="number"
        />
        <button type="submit">{t("run")}</button>
      </form>
      <Show l={l}>
        {(a) => (
          <>
            {a.results.map((c, i) => (
              <CompromiseView key={String(i)} c={c} />
            ))}
          </>
        )}
      </Show>
    </>
  );
}

/** OP-151 m.8 (b), (c): the export is an `access.audit_export` Exercise, signed here. */
export function Export({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [disclosure, setDisclosure] = useState<"redacted" | "full">("redacted");
  const [l, run] = useRun<Exported>();
  return (
    <>
      <p>{t("exportIntro")}</p>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          run(() =>
            exportAudit(ctx.instance, ctx.confirm, ctx.session.account, ctx.session.realm, {
              from: Number(from),
              to: Number(to),
              disclosure,
            }),
          );
        }}
      >
        <Field
          id="exp-from"
          label={t("exportFrom")}
          value={from}
          onChange={setFrom}
          type="number"
        />
        <Field id="exp-to" label={t("exportTo")} value={to} onChange={setTo} type="number" />
        <fieldset>
          <legend>{t("exportDisclosure")}</legend>
          <label>
            <input
              type="radio"
              name="disclosure"
              checked={disclosure === "redacted"}
              onChange={() => {
                setDisclosure("redacted");
              }}
            />
            {t("exportRedacted")}
          </label>
          <label>
            <input
              type="radio"
              name="disclosure"
              checked={disclosure === "full"}
              onChange={() => {
                setDisclosure("full");
              }}
            />
            {t("exportFull")}
          </label>
        </fieldset>
        <button type="submit" className="primary">
          {t("exportStart")}
        </button>
      </form>
      <Show l={l}>
        {(r) => (
          <>
            <p role="status">{t("exportDone", { exercise: r.exercise })}</p>
            <p>
              <a href={URL.createObjectURL(r.package)} download="audit-export.cbor">
                {t("exportDownload")}
              </a>
            </p>
          </>
        )}
      </Show>
    </>
  );
}

interface Proposal {
  readonly key: string;
  readonly label: string;
  readonly payload: MetaPayload;
}

function proposals(c: CompromiseImpact): readonly Proposal[] {
  const out: Proposal[] = [];
  if (c.instance !== undefined && c.instance !== null) {
    out.push({
      key: `i:${c.instance}`,
      label: t("containEndCopy", { id: c.instance }),
      payload: { instance_terminate: { instance: c.instance } },
    });
  }
  for (const g of c.grants) {
    out.push({
      key: `g:${g}`,
      label: t("containRevoke", { id: g }),
      payload: { grant_revoke: { grant: g } },
    });
  }
  return out;
}

function ContainResult({ r }: { readonly r: MetaResult }): ReactElement {
  if (r.decision) {
    return <p role="status">{t("containRecorded", { exercise: r.exercise ?? "" })}</p>;
  }
  return (
    <p role="status">{r.outcome === "require_action" ? t("changeHeld") : t("changeRefused")}</p>
  );
}

/**
 * §8.6, §8.13, §8.17.9.7, Ek B 3921: containment from S9. A compromise report lists the uses in
 * the window; each containment step is its own signed change (an Instance end or a revocation),
 * proposed one by one and never all at once. An executor that ignores a recorded step gets no
 * stop-all button either: the remaining steps stay listed as proposals.
 */
export function Containment({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const [instance, setInstance] = useState("");
  const [from, setFrom] = useState("");
  const [until, setUntil] = useState("");
  const [l, run] = useRun<SearchAnswer<CompromiseImpact>>();
  const [done, setDone] = useState<Readonly<Record<string, MetaResult>>>({});
  const [w, write] = useRun<MetaResult>();
  const sign = (p: Proposal) => {
    write(() =>
      metaWrite(ctx.instance, ctx.confirm, ctx.instance.party ?? "", p.payload).then((r) => {
        setDone((d) => ({ ...d, [p.key]: r }));
        return r;
      }),
    );
  };
  return (
    <>
      <p>{t("containIntro")}</p>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          setDone({});
          run(() =>
            search<CompromiseImpact>(ctx.instance, "compromise-impact", {
              instance,
              window: { from: Number(from), until: Number(until) },
            }),
          );
        }}
      >
        <Field
          id="con-instance"
          label={t("unknownKindInstance")}
          value={instance}
          onChange={setInstance}
        />
        <Field
          id="con-from"
          label={t("unknownFrom")}
          value={from}
          onChange={setFrom}
          type="number"
        />
        <Field
          id="con-until"
          label={t("unknownUntil")}
          value={until}
          onChange={setUntil}
          type="number"
        />
        <button type="submit">{t("run")}</button>
      </form>
      <Show l={l}>
        {(a) => (
          <>
            {a.results.map((c, i) => {
              const steps = proposals(c);
              return (
                <Panel key={String(i)} id={`contain-${String(i)}`} title={t("containSteps")}>
                  <CompromiseView c={c} />
                  {steps.length === 0 ? (
                    <p>{t("containNothing")}</p>
                  ) : (
                    <ul data-testid="containment">
                      {steps.map((p) => {
                        const r = done[p.key];
                        return (
                          <li key={p.key}>
                            <span>{p.label}</span>{" "}
                            {r === undefined ? (
                              <button
                                type="button"
                                onClick={() => {
                                  sign(p);
                                }}
                              >
                                {t("containPropose")}
                              </button>
                            ) : (
                              <ContainResult r={r} />
                            )}
                          </li>
                        );
                      })}
                    </ul>
                  )}
                  <p className="hint">{t("containRestriction")}</p>
                  <p className="hint">{t("containIgnored")}</p>
                </Panel>
              );
            })}
          </>
        )}
      </Show>
      {w.status === "failed" && <p role="alert">{t(w.key)}</p>}
    </>
  );
}
