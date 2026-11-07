// §8.17.9, S7, IA-5: the Admin section's authority screens. Reads go to ADP as the viewer's own
// check; every action shown is one the viewer can exercise (IA-5); nothing here is a single
// "stop everything" control (§8.17.7.5), and revoke is never offered as reversible (§8.10).
import { useEffect, useState, type ReactElement } from "react";

import { t } from "../i18n/index.js";
import { adminGet, change, type WriteResult } from "../lib/admin.js";
import { search, type SearchAnswer } from "../lib/adp.js";
import { META } from "../lib/text.js";
import { type Ctx, Field, PageCount, Panel, Show, useLoad, useRun } from "./parts.js";
import {
  type ChangeImpact,
  ChangeImpactView,
  type Publication,
  PublicationView,
  type RevocationImpact,
  Aftermath,
} from "./Reports.js";

function lines(text: string): string[] {
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l !== "");
}

/** §8.17.9.2, E11, C28: a typed role editor with its "Not included" block. */
function RoleEditor(): ReactElement {
  const [namespace, setNamespace] = useState("commerce");
  const [version, setVersion] = useState("1");
  const [named, setNamed] = useState("");
  const explicit = lines(named);
  return (
    <Panel id="role-editor" title={t("roleEditorTitle")}>
      <p className="hint">{t("roleEditorIntro")}</p>
      <Field id="role-ns" label={t("roleNamespace")} value={namespace} onChange={setNamespace} />
      <Field
        id="role-catalog"
        label={t("roleCatalog")}
        value={version}
        onChange={setVersion}
        type="number"
      />
      <p className="field">
        <label htmlFor="role-named">{t("roleNamed")}</label>
        <textarea
          id="role-named"
          value={named}
          onChange={(e) => {
            setNamed(e.target.value);
          }}
        />
      </p>
      <h4>{t("roleCovers")}</h4>
      <ul data-testid="role-covers">
        <li>{t("roleCoversLine", { namespace, version })}</li>
        {explicit.map((a) => (
          <li key={a}>{t("roleNamedLine", { action: a })}</li>
        ))}
      </ul>
      <h4>{t("notIncludedTitle")}</h4>
      <ul data-testid="not-included">
        <li>{t("notIncludedProtected", { namespace })}</li>
        <li>{t("notIncludedFuture", { namespace, version })}</li>
      </ul>
    </Panel>
  );
}

/** §8.17.9.2, X20: the preview before role delegations move to a new version. */
function ImpactPreview({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const [role, setRole] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [l, run] = useRun<SearchAnswer<ChangeImpact>>();
  return (
    <Panel id="impact" title={t("impactTitle")}>
      <p className="hint">{t("impactIntro")}</p>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          run(() =>
            search<ChangeImpact>(ctx.instance, "change-impact", {
              role,
              from: Number(from),
              to: Number(to),
            }),
          );
        }}
      >
        <Field id="impact-role" label={t("impactRole")} value={role} onChange={setRole} />
        <Field
          id="impact-from"
          label={t("impactFrom")}
          value={from}
          onChange={setFrom}
          type="number"
        />
        <Field id="impact-to" label={t("impactTo")} value={to} onChange={setTo} type="number" />
        <button type="submit">{t("run")}</button>
      </form>
      <Show l={l}>
        {(a) =>
          a.results.length === 0 ? (
            <p>{t("resultsNone")}</p>
          ) : (
            a.results.map((c, i) => <ChangeImpactView key={String(i)} c={c} />)
          )
        }
      </Show>
    </Panel>
  );
}

/** §8.17.9.2, Ek B 3100: an admin delegation's meta-actions one by one; protected apart. */
function AdminMeta(): ReactElement {
  const ordinary = META.filter((m) => !m.reserved);
  const reserved = META.filter((m) => m.reserved);
  return (
    <Panel id="admin-meta" title={t("adminMetaTitle")}>
      <p className="hint">{t("adminMetaIntro")}</p>
      <h4>{t("adminMetaOrdinary")}</h4>
      <ul data-testid="meta-ordinary">
        {ordinary.map((m) => (
          <li key={m.label}>
            {t(m.label)} · {t("adminMetaTier", { tier: m.tier.toUpperCase() })}
          </li>
        ))}
      </ul>
      <h4>{t("adminMetaReserved")}</h4>
      <ul data-testid="meta-reserved">
        {reserved.map((m) => (
          <li key={m.label}>
            {t(m.label)} · <strong>{t("protectedBadge")}</strong> — {t("protectedText")}
          </li>
        ))}
      </ul>
    </Panel>
  );
}

export function Roles({ ctx }: { readonly ctx: Ctx }): ReactElement {
  return (
    <>
      <p>{t("rolesIntro")}</p>
      <RoleEditor />
      <ImpactPreview ctx={ctx} />
      <AdminMeta />
    </>
  );
}

interface Account {
  readonly account_id: string;
  readonly status: string;
  readonly status_at?: string;
}

function Accounts({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const slug = ctx.session.realm;
  const [version, setVersion] = useState(0);
  const [l, load] = useRun<{ items: Account[] }>();
  useEffect(() => {
    load(() =>
      adminGet<{ items: Account[] }>(ctx.instance, `realms/${encodeURIComponent(slug)}/accounts`),
    );
  }, [load, ctx.instance, slug, version]);
  const [w, write] = useRun<WriteResult>();
  const act = (a: Account, op: "suspend" | "reactivate") => {
    write(() =>
      change(ctx.instance, ctx.confirm, slug, {
        operation: op === "suspend" ? "suspendAccount" : "reactivateAccount",
        key: a.account_id,
        method: "POST",
        path: `accounts/${encodeURIComponent(a.account_id)}/${op}`,
        body: {},
      }).then((r) => {
        setVersion((v) => v + 1);
        return r;
      }),
    );
  };
  return (
    <Panel id="accounts" title={t("peopleAccounts")}>
      <Show l={l}>
        {(v) => (
          <table>
            <thead>
              <tr>
                <th scope="col">{t("peopleAccount")}</th>
                <th scope="col">{t("peopleStatus")}</th>
                <th scope="col">{t("peopleActions")}</th>
              </tr>
            </thead>
            <tbody>
              {v.items.map((a) => (
                <tr key={a.account_id}>
                  <td className="mono">{a.account_id}</td>
                  <td>{a.status}</td>
                  <td>
                    {a.status === "active" && (
                      <button
                        type="button"
                        onClick={() => {
                          act(a, "suspend");
                        }}
                      >
                        {t("peopleSuspend")}
                      </button>
                    )}
                    {a.status === "suspended" && (
                      <button
                        type="button"
                        onClick={() => {
                          act(a, "reactivate");
                        }}
                      >
                        {t("peopleReactivate")}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Show>
      <Show l={w}>
        {(r) => <p role="status">{t("changeRecorded", { exercise: r.exercise_id })}</p>}
      </Show>
    </Panel>
  );
}

/**
 * X31, §8.17.7.1, TN-119: by default the viewer sees only their own holdings, what they gave
 * and its subtree; looking up another party is offered only with explicit audit authority.
 */
function Holdings({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const others = ctx.screens.has("records");
  const [party, setParty] = useState(ctx.session.account);
  const [l, run] = useRun<SearchAnswer<unknown>>();
  const who = others ? party : ctx.session.account;
  return (
    <Panel id="holdings" title={t("peopleHoldingsTitle")}>
      <p className="hint">{t("peopleHoldingsOwn")}</p>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          run(() =>
            search(ctx.instance, "action", {
              party: who,
              resource: { namespace: "access.domain", path: [ctx.session.realm] },
            }),
          );
        }}
      >
        {others && (
          <Field
            id="holdings-party"
            label={t("peopleOtherLabel")}
            value={party}
            onChange={setParty}
            hint={t("peopleOtherHint")}
          />
        )}
        <button type="submit">{t("run")}</button>
      </form>
      <Show l={l}>
        {(a) => (
          <>
            <PageCount page={a.page} shown={a.results.length} />
            <ul data-testid="holdings">
              {a.results.map((r, i) => (
                <li key={String(i)} className="mono">
                  {JSON.stringify(r)}
                </li>
              ))}
            </ul>
          </>
        )}
      </Show>
    </Panel>
  );
}

/** OP-142, §8.17.7.5, XI-3: ending an agent's running copies, its impact before anything else. */
function EndCopies({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const [instance, setInstance] = useState("");
  const [l, run] = useRun<SearchAnswer<RevocationImpact>>();
  return (
    <Panel id="end-copies" title={t("endCopiesTitle")}>
      <p className="hint">{t("endCopiesIntro")}</p>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          run(() => search<RevocationImpact>(ctx.instance, "revocation-impact", { instance }));
        }}
      >
        <Field
          id="end-instance"
          label={t("endCopiesInstance")}
          value={instance}
          onChange={setInstance}
        />
        <button type="submit">{t("run")}</button>
      </form>
      <Show l={l}>
        {(a) => (
          <>
            {a.results.map((r, i) => (
              <Aftermath key={String(i)} r={r} />
            ))}
            <p className="hint">{t("endCopiesNotHere")}</p>
          </>
        )}
      </Show>
    </Panel>
  );
}

export function People({ ctx }: { readonly ctx: Ctx }): ReactElement {
  return (
    <>
      <p>{t("peopleIntro")}</p>
      <Accounts ctx={ctx} />
      <Holdings ctx={ctx} />
      <EndCopies ctx={ctx} />
    </>
  );
}

const USES = [
  ["useSignIn", "useSignInText"],
  ["useFact", "useFactText"],
  ["useMembership", "useMembershipText"],
  ["usePartner", "usePartnerText"],
  ["useSchema", "useSchemaText"],
] as const;

/** §8.17.9.3, §8.17.10.2, X21: sources by use, and the definitions waiting for this domain. */
export function Sources({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const [namespace, setNamespace] = useState("");
  const [l, run] = useRun<SearchAnswer<Publication>>();
  return (
    <>
      <p>{t("sourcesIntro")}</p>
      <dl className="facts">
        {USES.map(([label, text]) => (
          <div key={label}>
            <dt>{t(label)}</dt>
            <dd>{t(text)}</dd>
          </div>
        ))}
      </dl>
      <p>{t("useOnlyThis")}</p>
      <Panel id="pending" title={t("pendingTitle")}>
        <p className="hint">{t("pendingIntro")}</p>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            run(() => search<Publication>(ctx.instance, "schema-publications", { namespace }));
          }}
        >
          <Field
            id="pending-ns"
            label={t("pendingNamespace")}
            value={namespace}
            onChange={setNamespace}
          />
          <button type="submit">{t("run")}</button>
        </form>
        <Show l={l}>
          {(a) => (
            <>
              <PageCount page={a.page} shown={a.results.length} />
              {a.results.map((p) => (
                <PublicationView key={p.fingerprint} p={p} />
              ))}
            </>
          )}
        </Show>
      </Panel>
    </>
  );
}

export function Restrictions(): ReactElement {
  return (
    <>
      <p>{t("restrictionsIntro")}</p>
      <p>{t("restrictionsSuspend")}</p>
      <p data-testid="no-stop">{t("restrictionsNoStop")}</p>
      <p>{t("restrictionsClass")}</p>
    </>
  );
}

export function Protected(): ReactElement {
  return (
    <>
      <p>{t("protectedIntro")}</p>
      <p>
        <strong>{t("protectedBadge")}</strong> — {t("protectedText")}
      </p>
      <p>{t("protectedNoKill")}</p>
    </>
  );
}

export function Offboarding(): ReactElement {
  return (
    <>
      <p>{t("offboardingIntro")}</p>
      <p>{t("offboardingChannels")}</p>
      <p>{t("offboardingSurvive")}</p>
      <p>{t("offboardingLabel")}</p>
    </>
  );
}

interface Surface {
  readonly domain?: string;
  readonly sandbox?: boolean;
  readonly partners?: readonly { readonly name: string; readonly ceiling: string }[];
}

/** §8.17.9.7, INV-29, §5.13: the domain page; the host holds no authority. */
export function Domain({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const l = useLoad(() =>
    adminGet<Surface>(ctx.instance, `realms/${encodeURIComponent(ctx.session.realm)}`),
  );
  return (
    <>
      <p>{t("domainIntro")}</p>
      <dl className="facts">
        <dt>{t("domainRealm")}</dt>
        <dd className="mono">{ctx.session.realm}</dd>
        <dt>{t("domainId")}</dt>
        <dd className="mono">{ctx.session.domain}</dd>
        <dt>{t("domainProvider")}</dt>
        <dd data-testid="provider">{t("domainProviderText")}</dd>
      </dl>
      <Show l={l}>
        {(s) => (
          <>
            {s.sandbox === true && (
              <p>
                <strong>{t("domainSandbox")}</strong> — {t("domainSandboxText")}
              </p>
            )}
            {(s.partners ?? []).length > 0 && (
              <Panel id="partners" title={t("partnerTitle")}>
                <p className="hint">{t("partnerIntro")}</p>
                <ul>
                  {(s.partners ?? []).map((p) => (
                    <li key={p.name}>
                      {p.name}: {t("partnerText", { ceiling: p.ceiling })}
                    </li>
                  ))}
                </ul>
              </Panel>
            )}
          </>
        )}
      </Show>
    </>
  );
}

/** IA-2: Changes is information only; no row claims "action required". */
export function Changes(): ReactElement {
  return (
    <>
      <p>{t("changesIntro")}</p>
      <p>{t("changesNone")}</p>
    </>
  );
}
