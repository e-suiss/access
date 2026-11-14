// §8.17.9, S7, IA-5: the Admin section's authority screens. Reads go to ADP as the viewer's own
// check; every action shown is one the viewer can exercise (IA-5); nothing here is a single
// "stop everything" control (§8.17.7.5), and revoke is never offered as reversible (§8.10).
import { useEffect, useState, type ReactElement } from "react";

import { Badge } from "@suiss/access-ui/components/ui/badge";
import { Button } from "@suiss/access-ui/components/ui/button";
import { FieldLegend, FieldSet } from "@suiss/access-ui/components/ui/field";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@suiss/access-ui/components/ui/table";

import { type Key, t } from "../i18n/index.js";
import { adminGet, change, type WriteResult } from "../lib/admin.js";
import { search, type SearchAnswer } from "../lib/adp.js";
import { type MetaPayload, type MetaResult, metaWrite, metaWrites } from "../lib/meta.js";
import { META_BY_ACTION } from "../lib/text.js";
import { at, type Ctx, Field, PageCount, Panel, Show, useLoad, useRun } from "./parts.js";
import {
  type ChangeImpact,
  ChangeImpactView,
  type Publication,
  PublicationView,
  type RevocationImpact,
  Aftermath,
} from "./Reports.js";
import {
  ACTIONS,
  BULLETS,
  CHOICE,
  CHOICE_LABEL,
  FACTS,
  FORM,
  H4,
  HINT,
  MONO,
  Notice,
  NUMBERED,
} from "../ui.js";

/** An action reference as a role version or a holding names it (L1-ADP-17). */
interface ActionRef {
  readonly namespace: string;
  readonly name: string;
  readonly major: number;
  readonly schema: string;
}

interface RoleVersion {
  readonly name: string;
  readonly version: number;
  readonly latest: number;
  readonly authority: {
    readonly actions: { readonly exact?: readonly ActionRef[] };
    readonly resource: unknown;
  };
  readonly not_included: {
    readonly reserved: readonly ActionRef[];
    readonly catalogs: readonly {
      readonly namespace: string;
      readonly catalog_version: number | null;
      readonly newer: readonly ActionRef[];
    }[];
  };
}

interface HoldingView {
  readonly grant: string;
  readonly actions: readonly ActionRef[];
}

const key = (a: ActionRef) => `${a.namespace}.${a.name}/${String(a.major)}`;

/**
 * §8.17.9.2, E11, C28, Ek B 3097: the typed role editor. A version starts from the role's
 * latest one; actions come from it and from what the viewer itself holds, so every action is a
 * typed reference. Saving is the signed `authority_set_define` of a new version.
 */
function RoleEditor({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const [name, setName] = useState("");
  const [current, load] = useRun<RoleVersion | undefined>();
  const [held, loadHeld] = useRun<readonly ActionRef[]>();
  const [chosen, setChosen] = useState<ReadonlySet<string>>(new Set());
  const [w, write] = useRun<MetaResult>();
  const open = () => {
    load(() =>
      search<RoleVersion>(ctx.instance, "role", { name }).then((a) => {
        const v = a.results[0];
        setChosen(new Set((v?.authority.actions.exact ?? []).map(key)));
        return v;
      }),
    );
    loadHeld(() =>
      search<HoldingView>(ctx.instance, "holdings", {}).then((a) =>
        a.results.flatMap((h) => h.actions),
      ),
    );
  };
  const options = (v: RoleVersion | undefined, own: readonly ActionRef[]) => {
    const all = new Map<string, ActionRef>();
    for (const a of [...(v?.authority.actions.exact ?? []), ...own]) all.set(key(a), a);
    return [...all.values()];
  };
  const save = (v: RoleVersion | undefined, own: readonly ActionRef[]) => {
    const exact = options(v, own).filter((a) => chosen.has(key(a)));
    const resource = v?.authority.resource ?? {
      namespace: "idp",
      prefix: [ctx.session.realm],
    };
    write(() =>
      metaWrite(ctx.instance, ctx.confirm, ctx.instance.party ?? "", {
        authority_set_define: { name, authority: { actions: { exact }, resource } },
      }),
    );
  };
  const own = held.status === "done" ? held.value : [];
  return (
    <Panel id="role-editor" title={t("roleEditorTitle")}>
      <p className={HINT}>{t("roleEditorIntro")}</p>
      <form
        className={FORM}
        onSubmit={(e) => {
          e.preventDefault();
          open();
        }}
      >
        <Field id="role-name" label={t("roleName")} value={name} onChange={setName} />
        <Button type="submit" variant="outline" className="self-start">
          {t("roleOpen")}
        </Button>
      </form>
      <Show l={current}>
        {(v) => (
          <>
            {v === undefined ? (
              <p>{t("roleNew")}</p>
            ) : (
              <p data-testid="role-version">
                {t("roleVersionLine", { version: String(v.version), latest: String(v.latest) })}
              </p>
            )}
            <FieldSet className="gap-2">
              <FieldLegend variant="label">{t("roleCovers")}</FieldLegend>
              {options(v, own).map((a) => (
                <p key={key(a)}>
                  <label className={CHOICE_LABEL}>
                    <input
                      type="checkbox"
                      className={CHOICE}
                      checked={chosen.has(key(a))}
                      onChange={(e) => {
                        const next = new Set(chosen);
                        if (e.target.checked) next.add(key(a));
                        else next.delete(key(a));
                        setChosen(next);
                      }}
                    />
                    <span className={MONO}>{`${a.namespace}.${a.name}`}</span>
                  </label>
                </p>
              ))}
              {(v?.not_included.catalogs ?? []).map((c) => (
                <p key={c.namespace} data-testid="role-covers" className={HINT}>
                  {t("roleCoversLine", {
                    namespace: c.namespace,
                    version: c.catalog_version === null ? "?" : String(c.catalog_version),
                  })}
                </p>
              ))}
            </FieldSet>
            <h4 className={H4}>{t("notIncludedTitle")}</h4>
            <ul data-testid="not-included" className={BULLETS}>
              {(v?.not_included.reserved ?? []).map((a) => (
                <li key={key(a)}>
                  <Badge variant="outline">{t("protectedBadge")}</Badge>{" "}
                  {`${a.namespace}.${a.name}`} — {t("reservedOnlyNamed")}
                </li>
              ))}
              {(v?.not_included.catalogs ?? []).map((c) => (
                <li key={c.namespace}>
                  {t("notIncludedFuture", {
                    namespace: c.namespace,
                    version: c.catalog_version === null ? "?" : String(c.catalog_version),
                  })}
                </li>
              ))}
              {(v?.not_included.reserved.length ?? 0) + (v?.not_included.catalogs.length ?? 0) ===
                0 && <li>{t("notIncludedNothing")}</li>}
            </ul>
            <Button
              className="self-start"
              isDisabled={name === "" || chosen.size === 0}
              onPress={() => {
                save(v, own);
              }}
            >
              {t("roleSave")}
            </Button>
          </>
        )}
      </Show>
      <Show l={w}>{(r) => <WriteOutcome r={r} />}</Show>
    </Panel>
  );
}

/** The outcome of a signed change, in words; a held change says it is held, never "done". */
export function WriteOutcome({ r }: { readonly r: MetaResult }): ReactElement {
  if (r.decision) {
    return <Notice role="status">{t("changeRecorded", { exercise: r.exercise ?? "" })}</Notice>;
  }
  return (
    <Notice role="status" tone="warning">
      {r.outcome === "require_action" ? t("changeHeld") : t("changeRefused")}
    </Notice>
  );
}

interface Moveable extends ChangeImpact {
  readonly amends?: readonly MetaPayload[];
}

/**
 * §8.17.9.2, X20, Ek B 3098: the preview before role delegations move to a new version, then
 * the explicit bulk `grant_amend`: one Exercise per delegation, all on one signature screen. A
 * widening move carries its expansion requirements and may be held.
 */
function ImpactPreview({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const [role, setRole] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [l, run] = useRun<SearchAnswer<Moveable>>();
  const [w, move] = useRun<readonly MetaResult[]>();
  return (
    <Panel id="impact" title={t("impactTitle")}>
      <p className={HINT}>{t("impactIntro")}</p>
      <form
        className={FORM}
        onSubmit={(e) => {
          e.preventDefault();
          run(() =>
            search<Moveable>(ctx.instance, "change-impact", {
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
        <Button type="submit" variant="outline" className="self-start">
          {t("run")}
        </Button>
      </form>
      <Show l={l}>
        {(a) =>
          a.results.length === 0 ? (
            <p className={HINT}>{t("resultsNone")}</p>
          ) : (
            a.results.map((c, i) => (
              <div key={String(i)} className="flex flex-col gap-3">
                <ChangeImpactView c={c} />
                {(c.amends ?? []).length > 0 && (
                  <Button
                    data-testid="move-delegations"
                    className="self-start"
                    onPress={() => {
                      move(() =>
                        metaWrites(
                          ctx.instance,
                          ctx.confirm,
                          ctx.instance.party ?? "",
                          c.amends ?? [],
                        ),
                      );
                    }}
                  >
                    {t("impactMove", { n: String(c.amends?.length ?? 0), to })}
                  </Button>
                )}
              </div>
            ))
          )
        }
      </Show>
      <Show l={w}>
        {(rs) => (
          <ul data-testid="moved" className={BULLETS}>
            {rs.map((r, i) => (
              <li key={String(i)}>
                <WriteOutcome r={r} />
              </li>
            ))}
          </ul>
        )}
      </Show>
    </Panel>
  );
}

interface MetaLine {
  readonly action: string;
  readonly tier_when_widening: string;
  readonly grant_quorum: number;
  readonly joint_root_quorum: number;
}

interface AdminGrantView {
  readonly grant: string;
  readonly role?: { readonly name: string; readonly version: number } | null;
  readonly actions: readonly MetaLine[];
  readonly reserved: readonly MetaLine[];
}

/** A meta-action's plain label (OP-151 m.19 (c)); never its canonical id. */
function metaLabel(action: string): string {
  const m = META_BY_ACTION[action];
  return m === undefined ? t("metaOther") : t(m);
}

/** §8.17.9.2, Ek B 3100: an admin delegation's meta-actions one by one; protected apart. */
function AdminMeta({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const [grant, setGrant] = useState("");
  const [l, run] = useRun<AdminGrantView | undefined>();
  return (
    <Panel id="admin-meta" title={t("adminMetaTitle")}>
      <p className={HINT}>{t("adminMetaIntro")}</p>
      <form
        className={FORM}
        onSubmit={(e) => {
          e.preventDefault();
          run(() =>
            search<AdminGrantView>(ctx.instance, "admin-grant", { grant }).then(
              (a) => a.results[0],
            ),
          );
        }}
      >
        <Field id="admin-grant" label={t("adminMetaGrant")} value={grant} onChange={setGrant} />
        <Button type="submit" variant="outline" className="self-start">
          {t("run")}
        </Button>
      </form>
      <Show l={l}>
        {(g) =>
          g === undefined ? (
            <p className={HINT}>{t("resultsNone")}</p>
          ) : (
            <>
              {g.role !== undefined && g.role !== null && (
                <p>{t("adminMetaRole", { role: g.role.name, version: String(g.role.version) })}</p>
              )}
              <h4 className={H4}>{t("adminMetaOrdinary")}</h4>
              <ul data-testid="meta-ordinary" className={BULLETS}>
                {g.actions.map((m) => (
                  <li key={m.action}>
                    {metaLabel(m.action)} ·{" "}
                    {t("adminMetaTier", { tier: m.tier_when_widening.toUpperCase() })}
                  </li>
                ))}
              </ul>
              <h4 className={H4}>{t("adminMetaReserved")}</h4>
              <ul data-testid="meta-reserved" className={BULLETS}>
                {g.reserved.map((m) => (
                  <li key={m.action}>
                    {metaLabel(m.action)} · <Badge variant="outline">{t("protectedBadge")}</Badge> —{" "}
                    {t("adminMetaQuorum", { quorum: String(m.grant_quorum + m.joint_root_quorum) })}
                  </li>
                ))}
              </ul>
            </>
          )
        }
      </Show>
    </Panel>
  );
}

/** TN-114, OP-157 m.3 (t): the realm's staged opening of meta-action role Grants. */
function DelegatedAdmin({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const [w, write] = useRun<WriteResult>();
  const set = (enabled: boolean) => {
    write(() =>
      change(ctx.instance, ctx.confirm, ctx.session.realm, {
        operation: "putDelegatedAdmin",
        method: "PUT",
        path: "settings/delegated-admin",
        body: { enabled },
      }),
    );
  };
  return (
    <Panel id="delegated-admin" title={t("delegatedAdminTitle")}>
      <p className={HINT}>{t("delegatedAdminIntro")}</p>
      <div className={ACTIONS}>
        <Button
          onPress={() => {
            set(true);
          }}
        >
          {t("delegatedAdminOn")}
        </Button>
        <Button
          variant="outline"
          onPress={() => {
            set(false);
          }}
        >
          {t("delegatedAdminOff")}
        </Button>
      </div>
      <Show l={w}>
        {(r) => <Notice role="status">{t("changeRecorded", { exercise: r.exercise_id })}</Notice>}
      </Show>
    </Panel>
  );
}

export function Roles({ ctx }: { readonly ctx: Ctx }): ReactElement {
  return (
    <>
      <p>{t("rolesIntro")}</p>
      <RoleEditor ctx={ctx} />
      <ImpactPreview ctx={ctx} />
      <AdminMeta ctx={ctx} />
      <DelegatedAdmin ctx={ctx} />
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
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead scope="col">{t("peopleAccount")}</TableHead>
                <TableHead scope="col">{t("peopleStatus")}</TableHead>
                <TableHead scope="col">{t("peopleActions")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {v.items.map((a) => (
                <TableRow key={a.account_id}>
                  <TableCell className={MONO}>{a.account_id}</TableCell>
                  <TableCell>
                    <Badge variant="outline">{a.status}</Badge>
                  </TableCell>
                  <TableCell>
                    {a.status === "active" && (
                      <Button
                        variant="destructive"
                        size="sm"
                        onPress={() => {
                          act(a, "suspend");
                        }}
                      >
                        {t("peopleSuspend")}
                      </Button>
                    )}
                    {a.status === "suspended" && (
                      <Button
                        variant="outline"
                        size="sm"
                        onPress={() => {
                          act(a, "reactivate");
                        }}
                      >
                        {t("peopleReactivate")}
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Show>
      <Show l={w}>
        {(r) => <Notice role="status">{t("changeRecorded", { exercise: r.exercise_id })}</Notice>}
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
      <p className={HINT}>{t("peopleHoldingsOwn")}</p>
      <form
        className={FORM}
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
        <Button type="submit" variant="outline" className="self-start">
          {t("run")}
        </Button>
      </form>
      <Show l={l}>
        {(a) => (
          <>
            <PageCount page={a.page} shown={a.results.length} />
            <ul data-testid="holdings" className={BULLETS}>
              {a.results.map((r, i) => (
                <li key={String(i)} className={MONO}>
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
      <p className={HINT}>{t("endCopiesIntro")}</p>
      <form
        className={FORM}
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
        <Button type="submit" variant="outline" className="self-start">
          {t("run")}
        </Button>
      </form>
      <Show l={l}>
        {(a) => (
          <>
            {a.results.map((r, i) => (
              <Aftermath key={String(i)} r={r} />
            ))}
            <p className={HINT}>{t("endCopiesNotHere")}</p>
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

/** §8.17.9.3: the UI label of each canonical use. */
const USE_LABEL: Readonly<Record<string, Key>> = {
  "actor-binding": "useSignIn",
  "predicate-input": "useFact",
  "subject-selection": "useMembership",
  "foreign-authority": "usePartner",
  "schema-definition": "useSchema",
};

/** One live Acceptance as the `sources` search answers it. */
interface AcceptedSource {
  readonly acceptance: string;
  readonly use: string;
  readonly issuer: { readonly party?: string; readonly foreign?: string };
  readonly classes: readonly string[];
  readonly namespace: string | null;
  readonly protected: boolean;
  readonly dependents: number;
}

/** One partner and the ceilings its bridging Grants set (§5.13). */
interface PartnerView {
  readonly domain: string;
  readonly ceilings: readonly { readonly grant: string; readonly actions: readonly ActionRef[] }[];
}

interface SourcesReport {
  readonly sources: readonly AcceptedSource[];
  readonly partners: readonly PartnerView[];
}

function sourcesReport(ctx: Ctx): Promise<SourcesReport | undefined> {
  return search<SourcesReport>(ctx.instance, "sources", {}).then((a) => a.results[0]);
}

/** §5.13, 3372: what a partner may do here at most, as "Partner authority (up to …)". */
function ceilingText(p: PartnerView): string {
  const names = p.ceilings.flatMap((c) => c.actions.map((a) => `${a.namespace}.${a.name}`));
  return [...new Set(names)].join(", ");
}

function SourceView({ s }: { readonly s: AcceptedSource }): ReactElement {
  const label = USE_LABEL[s.use];
  const use = label === undefined ? s.use : t(label);
  // INV-15: an acceptance for one use is not one for another
  const other = s.use === "actor-binding" ? t("useMembership") : t("useSignIn");
  return (
    <li
      data-testid="source"
      data-use={s.use}
      className="flex flex-col gap-2 border-t pt-3 first:border-t-0 first:pt-0"
    >
      <strong>{use}</strong>
      {s.protected && <> — {t("acceptedProtected")}</>}
      <dl className={FACTS}>
        <dt>{s.issuer.foreign === undefined ? t("acceptedIssuer") : t("acceptedPartner")}</dt>
        <dd className={MONO}>{s.issuer.party ?? s.issuer.foreign ?? ""}</dd>
      </dl>
      <p>{t("acceptedFor", { use })}</p>
      <p>{t("acceptedNotOther", { other })}</p>
      {s.namespace !== null && <p>{t("acceptedNamespace", { namespace: s.namespace })}</p>}
      <p data-testid="blast">{t("acceptedDependents", { n: String(s.dependents) })}</p>
    </li>
  );
}

/** §8.17.9.3, §8.17.10.2, X21, INV-15: sources by use with their blast radius, and the definitions waiting for this domain. */
export function Sources({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const [namespace, setNamespace] = useState("");
  const [l, run] = useRun<SearchAnswer<Publication>>();
  const accepted = useLoad(() => sourcesReport(ctx));
  return (
    <>
      <p>{t("sourcesIntro")}</p>
      <dl className="flex flex-col gap-2 text-sm">
        {USES.map(([label, text]) => (
          <div key={label}>
            <dt className="font-medium">{t(label)}</dt>
            <dd className="text-muted-foreground">{t(text)}</dd>
          </div>
        ))}
      </dl>
      <p>{t("useOnlyThis")}</p>
      <Panel id="accepted" title={t("acceptedTitle")}>
        <Show l={accepted}>
          {(r) =>
            r === undefined || r.sources.length === 0 ? (
              <p className={HINT}>{t("acceptedNone")}</p>
            ) : (
              <ul data-testid="sources" className="flex flex-col gap-3">
                {r.sources.map((s) => (
                  <SourceView key={s.acceptance} s={s} />
                ))}
              </ul>
            )
          }
        </Show>
      </Panel>
      <Panel id="pending" title={t("pendingTitle")}>
        <p className={HINT}>{t("pendingIntro")}</p>
        <form
          className={FORM}
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
          <Button type="submit" variant="outline" className="self-start">
            {t("run")}
          </Button>
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
        <Badge variant="outline">{t("protectedBadge")}</Badge> — {t("protectedText")}
      </p>
      <p>{t("protectedNoKill")}</p>
    </>
  );
}

interface Surface {
  readonly domain?: string;
  readonly sandbox?: boolean;
}

/** §8.17.9.7, INV-29, §5.13: the domain page; the host holds no authority. */
export function Domain({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const l = useLoad(() =>
    adminGet<Surface>(ctx.instance, `realms/${encodeURIComponent(ctx.session.realm)}`),
  );
  const partners = useLoad(() => sourcesReport(ctx).then((r) => r?.partners ?? []));
  return (
    <>
      <p>{t("domainIntro")}</p>
      <dl className={FACTS}>
        <dt>{t("domainRealm")}</dt>
        <dd className={MONO}>{ctx.session.realm}</dd>
        <dt>{t("domainId")}</dt>
        <dd className={MONO}>{ctx.session.domain}</dd>
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
          </>
        )}
      </Show>
      <Show l={partners}>
        {(list) =>
          list.length > 0 ? (
            <Panel id="partners" title={t("partnerTitle")}>
              <p className={HINT}>{t("partnerIntro")}</p>
              <ul data-testid="partners" className={BULLETS}>
                {list.map((p) => (
                  <li key={p.domain}>
                    <span className={MONO}>{p.domain}</span>:{" "}
                    {p.ceilings.length === 0
                      ? t("partnerNoCeiling")
                      : t("partnerText", { ceiling: ceilingText(p) })}
                  </li>
                ))}
              </ul>
            </Panel>
          ) : (
            <></>
          )
        }
      </Show>
    </>
  );
}

interface ChangeRow {
  readonly position: string;
  readonly at: number;
  readonly kind: string;
  readonly id: string;
  readonly version?: number | null;
  readonly ended: boolean;
  readonly own: boolean;
}

const CHANGE_KINDS: Readonly<Record<string, Key>> = {
  grant: "changeKindGrant",
  anchor: "changeKindAnchor",
  party: "changeKindParty",
  instance: "changeKindInstance",
  mandate: "changeKindMandate",
  acceptance: "changeKindAcceptance",
  policy: "changeKindPolicy",
  authority_set: "changeKindRole",
};

/** IA-2: Changes is information only; no row claims "action required". */
export function Changes({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const [rows, setRows] = useState<readonly ChangeRow[]>([]);
  const [token, setToken] = useState<string | undefined>(undefined);
  const [l, run] = useRun<SearchAnswer<ChangeRow>>();
  const more = (after?: string) => {
    run(() =>
      search<ChangeRow>(ctx.instance, "changes", {}, after).then((a) => {
        setRows((r) => (after === undefined ? a.results : [...r, ...a.results]));
        setToken(a.page.next_token === "" ? undefined : a.page.next_token);
        return a;
      }),
    );
  };
  useEffect(() => {
    more();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return (
    <>
      <p>{t("changesIntro")}</p>
      <Show l={l}>
        {() =>
          rows.length === 0 ? (
            <p className={HINT}>{t("changesNone")}</p>
          ) : (
            <ul data-testid="changes" className={BULLETS}>
              {rows.map((r) => (
                <li key={`${r.position}/${r.kind}/${r.id}`}>
                  {at(r.at)} · {t(CHANGE_KINDS[r.kind] ?? "changeKindOther")}{" "}
                  <span className={MONO}>
                    {r.version === undefined || r.version === null
                      ? r.id
                      : `${r.id} v${String(r.version)}`}
                  </span>
                  {r.ended && ` · ${t("changeEnded")}`}
                  {r.own && ` · ${t("changeByYou")}`}
                </li>
              ))}
            </ul>
          )
        }
      </Show>
      {token !== undefined && (
        <Button
          variant="outline"
          className="self-start"
          onPress={() => {
            more(token);
          }}
        >
          {t("changesOlder")}
        </Button>
      )}
    </>
  );
}

/**
 * §8.5 S7, §8.17.9.1, Ek B 3874: the meta-Exercise history. Every allowed meta-Exercise, newest
 * first, with each object it changed under its record position; an auditor reads every one. It
 * is information only, like Changes, and no row offers an action.
 */
export function History({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const [rows, setRows] = useState<readonly ChangeRow[]>([]);
  const [token, setToken] = useState<string | undefined>(undefined);
  const [l, run] = useRun<SearchAnswer<ChangeRow>>();
  const more = (after?: string) => {
    run(() =>
      search<ChangeRow>(ctx.instance, "changes", {}, after).then((a) => {
        setRows((r) => (after === undefined ? a.results : [...r, ...a.results]));
        setToken(a.page.next_token === "" ? undefined : a.page.next_token);
        return a;
      }),
    );
  };
  useEffect(() => {
    more();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const byRecord = new Map<string, ChangeRow[]>();
  for (const r of rows) {
    const list = byRecord.get(r.position) ?? [];
    list.push(r);
    byRecord.set(r.position, list);
  }
  return (
    <>
      <p>{t("historyIntro")}</p>
      <Show l={l}>
        {() =>
          byRecord.size === 0 ? (
            <p className={HINT}>{t("changesNone")}</p>
          ) : (
            <ol data-testid="history" className={NUMBERED}>
              {[...byRecord.entries()].map(([position, list]) => (
                <li key={position}>
                  <p>
                    {t("historyRecord", { position, at: at(list[0]?.at) })}
                    {list.some((r) => r.own) && ` · ${t("changeByYou")}`}
                  </p>
                  <ul className={BULLETS}>
                    {list.map((r) => (
                      <li key={`${r.kind}/${r.id}`}>
                        {t(CHANGE_KINDS[r.kind] ?? "changeKindOther")}{" "}
                        <span className={MONO}>
                          {r.version === undefined || r.version === null
                            ? r.id
                            : `${r.id} v${String(r.version)}`}
                        </span>
                        {r.ended && ` · ${t("changeEnded")}`}
                      </li>
                    ))}
                  </ul>
                </li>
              ))}
            </ol>
          )
        }
      </Show>
      {token !== undefined && (
        <Button
          variant="outline"
          className="self-start"
          onPress={() => {
            more(token);
          }}
        >
          {t("changesOlder")}
        </Button>
      )}
    </>
  );
}
