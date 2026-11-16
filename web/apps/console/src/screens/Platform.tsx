// OP-159 m.41 (b), (c), TN-119, OP-151 m.2 M2, INV-29, X31: the Platform section. Tenants, the
// realms and sandbox domains in them, a realm's metadata with the state of its signing keys, and
// the deployment's readiness. Nothing here shows or changes a realm's accounts, apps, authority,
// records or settings: managing a realm means signing in to it. Each creation is one signed
// `idp.platform.*` Exercise on the viewer's own Grant. OP-159 m.42 (d): each realm shows its
// console link.
import { useEffect, useState, type ReactElement } from "react";

import { Badge } from "@access/ui/components/badge";
import { Button } from "@access/ui/components/button";
import { Field as FieldRoot, FieldLabel } from "@access/ui/components/field";
import { NativeSelect, NativeSelectOption } from "@access/ui/components/native-select";
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@access/ui/components/table";

import { t } from "../i18n/index.js";
import { adminGet, type WriteResult } from "../lib/admin.js";
import { consoleHref, consoleLink } from "../lib/paths.js";
import { platformChange, type PlatformChange } from "../lib/platform.js";
import { ACTIONS, CHOICE, CHOICE_LABEL, FORM, HINT, MONO, Notice, ROWS } from "../ui.js";
import { at, type Ctx, Field, type Loaded, Panel, Show, useRun } from "./parts.js";

interface Tenant {
  readonly tenant_id: string;
  readonly status: string;
  readonly placement: string;
  readonly created_at?: string;
}

interface RealmMeta {
  readonly slug: string;
  readonly tenant_id?: string;
  readonly issuer?: string | null;
  readonly status?: string;
  readonly placement?: string;
  readonly domain?: string;
  readonly sandbox?: boolean;
  readonly budget?: {
    readonly exercises_per_day: string;
    readonly projections_per_day: string;
  } | null;
  readonly created_at?: string;
  readonly key_state?: "pending" | "published" | "signing" | "unavailable";
  readonly signing_available_at?: string | null;
  readonly kex_share?: string;
}

interface Health {
  readonly status: "ready" | "degraded";
  readonly checks: readonly { readonly name: string; readonly ok: boolean }[];
}

interface Items<T> {
  readonly items: readonly T[];
}

function keyState(s: RealmMeta["key_state"]): string {
  if (s === "pending") return t("platformKeyPending");
  if (s === "published") return t("platformKeyPublished");
  if (s === "signing") return t("platformKeySigning");
  return t("platformKeyUnavailable");
}

/** A change's outcome: the Exercise it was recorded as. */
function Recorded({ w }: { readonly w: Loaded<WriteResult> }): ReactElement {
  return (
    <Show l={w}>
      {(r) => <Notice role="status">{t("changeRecorded", { exercise: r.exercise_id })}</Notice>}
    </Show>
  );
}

/** OP-159 m.42 (d): the console link of realm `slug`. */
function ConsoleLink({ slug }: { readonly slug: string }): ReactElement {
  return (
    <a
      href={consoleHref(slug)}
      data-testid="realm-console-link"
      className={`${MONO} break-all text-primary underline underline-offset-2 hover:text-foreground`}
    >
      {consoleLink(slug)}
    </a>
  );
}

/** The tenants, read again whenever `version` changes. */
function useTenants(ctx: Ctx, version: number): Loaded<Items<Tenant>> {
  const [list, load] = useRun<Items<Tenant>>();
  useEffect(() => {
    load(() => adminGet<Items<Tenant>>(ctx.instance, "platform/tenants"));
  }, [load, ctx.instance, version]);
  return list;
}

/** The tenant a realm list and a creation are in. */
function TenantPicker({
  id,
  tenants,
  value,
  onChange,
}: {
  readonly id: string;
  readonly tenants: readonly Tenant[];
  readonly value: string;
  readonly onChange: (v: string) => void;
}): ReactElement {
  return (
    <FieldRoot className="max-w-xl gap-2">
      <FieldLabel htmlFor={id} className="text-sm">
        {t("platformTenant")}
      </FieldLabel>
      <NativeSelect
        id={id}
        size="sm"
        value={value}
        onChange={(e) => {
          onChange(e.target.value);
        }}
      >
        <NativeSelectOption value="">{t("platformTenantChoose")}</NativeSelectOption>
        {tenants.map((x) => (
          <NativeSelectOption key={x.tenant_id} value={x.tenant_id}>
            {x.tenant_id}
          </NativeSelectOption>
        ))}
      </NativeSelect>
    </FieldRoot>
  );
}

/** Platform ▸ Tenants: every tenant and a new one. */
export function Tenants({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const [version, setVersion] = useState(0);
  const list = useTenants(ctx, version);
  const [placement, setPlacement] = useState("");
  const [w, write] = useRun<WriteResult>();
  return (
    <div data-testid="platform-tenants" className="flex flex-col gap-4">
      <p className="text-muted-foreground">{t("platformTenantsIntro")}</p>
      <Show l={list}>
        {(p) =>
          p.items.length === 0 ? (
            <p className={HINT}>{t("none")}</p>
          ) : (
            <Table data-testid="tenant-list" className="caption-top">
              <TableCaption className="sr-only">{t("screenTenants")}</TableCaption>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead scope="col">{t("platformTenant")}</TableHead>
                  <TableHead scope="col">{t("platformStatus")}</TableHead>
                  <TableHead scope="col">{t("platformPlacement")}</TableHead>
                  <TableHead scope="col">{t("platformCreated")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {p.items.map((x) => (
                  <TableRow key={x.tenant_id}>
                    <TableCell className={MONO}>{x.tenant_id}</TableCell>
                    <TableCell>{x.status}</TableCell>
                    <TableCell className={MONO}>{x.placement}</TableCell>
                    <TableCell>{at(x.created_at)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )
        }
      </Show>
      <Panel id="tenant-create" title={t("platformTenantCreate")}>
        <p className={HINT}>{t("platformTenantCreateHint")}</p>
        <form
          className={FORM}
          onSubmit={(e) => {
            e.preventDefault();
            const body: Record<string, unknown> = placement === "" ? {} : { placement };
            write(async () => {
              const r = await platformChange(ctx.instance, ctx.confirm, ctx.session.realm, {
                operation: "createTenant",
                action: "tenant_create",
                path: "platform/tenants",
                body,
              });
              setVersion((v) => v + 1);
              return r;
            });
          }}
        >
          <Field
            id="tenant-placement"
            label={t("platformPlacementOptional")}
            value={placement}
            onChange={(v) => {
              setPlacement(v.trim());
            }}
          />
          <div className={ACTIONS}>
            <Button type="submit">{t("platformTenantCreateSend")}</Button>
          </div>
        </form>
        <Recorded w={w} />
      </Panel>
    </div>
  );
}

type RootKind = "sole" | "joint";

/** A new realm or sandbox domain in `tenant`, its founding root the viewer's choice (TN-111). */
function CreateRealm({
  ctx,
  tenant,
  sandbox,
  onCreated,
}: {
  readonly ctx: Ctx;
  readonly tenant: string;
  readonly sandbox: boolean;
  readonly onCreated: () => void;
}): ReactElement {
  const own = ctx.instance.party ?? "";
  const prefix = sandbox ? "sandbox" : "realm";
  const [slug, setSlug] = useState("");
  const [style, setStyle] = useState<"subdomain" | "path">("subdomain");
  const [kind, setKind] = useState<RootKind>("joint");
  const [parties, setParties] = useState(own);
  const [k, setK] = useState("2");
  const [acknowledged, setAcknowledged] = useState(false);
  const [w, write] = useRun<WriteResult>();
  const [made, setMade] = useState("");
  const listed = parties
    .split(/[\s,]+/)
    .map((p) => p.trim())
    .filter((p) => p !== "");
  const ready =
    tenant !== "" &&
    slug !== "" &&
    (kind === "sole"
      ? acknowledged && own !== ""
      : listed.length >= 2 && Number(k) >= 2 && Number(k) <= listed.length);
  const send = () => {
    const root = kind === "sole" ? { sole: own } : { joint: { k: Number(k), parties: listed } };
    const body: Record<string, unknown> = {
      slug,
      issuer_style: style,
      root,
      ...(kind === "sole" ? { acknowledge_no_recovery: true } : {}),
    };
    const c: PlatformChange = sandbox
      ? {
          operation: "createSandboxDomain",
          action: "sandbox_create",
          tenant,
          path: `platform/tenants/${encodeURIComponent(tenant)}/sandbox-domains`,
          body,
        }
      : {
          operation: "createRealm",
          action: "realm_create",
          tenant,
          path: `platform/tenants/${encodeURIComponent(tenant)}/realms`,
          body,
        };
    const wanted = slug;
    write(async () => {
      const r = await platformChange(ctx.instance, ctx.confirm, ctx.session.realm, c);
      setMade(wanted);
      onCreated();
      return r;
    });
  };
  return (
    <Panel
      id={`${prefix}-create`}
      title={sandbox ? t("platformSandboxCreate") : t("platformRealmCreate")}
    >
      <p className={HINT}>
        {sandbox ? t("platformSandboxCreateHint") : t("platformRealmCreateHint")}
      </p>
      <form
        className={FORM}
        onSubmit={(e) => {
          e.preventDefault();
          if (ready) send();
        }}
      >
        <Field
          id={`${prefix}-slug`}
          label={t("platformSlug")}
          hint={t("platformSlugHint")}
          value={slug}
          onChange={(v) => {
            setSlug(v.trim().toLowerCase());
          }}
        />
        <fieldset className="flex flex-col gap-2">
          <legend className="mb-1 text-sm font-semibold">{t("platformIssuerStyle")}</legend>
          {(["subdomain", "path"] as const).map((s) => (
            <label key={s} className={CHOICE_LABEL}>
              <input
                className={CHOICE}
                type="radio"
                name={`${prefix}-style`}
                value={s}
                checked={style === s}
                onChange={() => {
                  setStyle(s);
                }}
              />
              {s === "subdomain" ? t("platformIssuerSubdomain") : t("platformIssuerPath")}
            </label>
          ))}
        </fieldset>
        <fieldset className="flex flex-col gap-2">
          <legend className="mb-1 text-sm font-semibold">{t("platformRoot")}</legend>
          <label className={CHOICE_LABEL}>
            <input
              className={CHOICE}
              type="radio"
              name={`${prefix}-root`}
              value="joint"
              checked={kind === "joint"}
              onChange={() => {
                setKind("joint");
              }}
            />
            {t("platformRootJoint")}
          </label>
          <label className={CHOICE_LABEL}>
            <input
              className={CHOICE}
              type="radio"
              name={`${prefix}-root`}
              value="sole"
              checked={kind === "sole"}
              onChange={() => {
                setKind("sole");
              }}
            />
            {t("platformRootSole")}
          </label>
        </fieldset>
        {kind === "joint" ? (
          <>
            <Field
              id={`${prefix}-parties`}
              label={t("platformRootParties")}
              hint={t("platformRootPartiesHint")}
              value={parties}
              onChange={setParties}
            />
            <Field
              id={`${prefix}-k`}
              type="number"
              label={t("platformRootK")}
              value={k}
              onChange={setK}
            />
          </>
        ) : (
          <label className={CHOICE_LABEL}>
            <input
              className={CHOICE}
              type="checkbox"
              checked={acknowledged}
              onChange={(e) => {
                setAcknowledged(e.target.checked);
              }}
            />
            {t("platformRootSoleAcknowledge")}
          </label>
        )}
        <div className={ACTIONS}>
          <Button type="submit" disabled={!ready}>
            {sandbox ? t("platformSandboxCreateSend") : t("platformRealmCreateSend")}
          </Button>
        </div>
      </form>
      <Recorded w={w} />
      {!sandbox && w.status === "done" && made !== "" && (
        <p data-testid="realm-console-created">
          {t("platformConsoleLinkCreated")} <ConsoleLink slug={made} />
        </p>
      )}
    </Panel>
  );
}

/** One realm's metadata and the state of its signing keys. */
function RealmDetails({ ctx, slug }: { readonly ctx: Ctx; readonly slug: string }): ReactElement {
  const [m, load] = useRun<RealmMeta>();
  useEffect(() => {
    load(() => adminGet<RealmMeta>(ctx.instance, `platform/realms/${encodeURIComponent(slug)}`));
  }, [load, ctx.instance, slug]);
  return (
    <Show l={m}>
      {(r) => (
        <dl className={ROWS} data-testid="realm-meta">
          <div>
            <dt>{t("platformSlug")}</dt>
            <dd className={MONO}>{r.slug}</dd>
          </div>
          <div>
            <dt>{t("platformIssuer")}</dt>
            <dd className={MONO}>{r.issuer ?? t("none")}</dd>
          </div>
          <div>
            <dt>{t("platformKeys")}</dt>
            <dd data-testid="realm-key-state" data-state={r.key_state ?? "unavailable"}>
              {keyState(r.key_state)}
            </dd>
          </div>
          {typeof r.signing_available_at === "string" && (
            <div>
              <dt>{t("platformSigningAt")}</dt>
              <dd>{at(r.signing_available_at)}</dd>
            </div>
          )}
          {r.domain !== undefined && (
            <div>
              <dt>{t("domainId")}</dt>
              <dd className={MONO}>{r.domain}</dd>
            </div>
          )}
          {r.placement !== undefined && (
            <div>
              <dt>{t("platformPlacement")}</dt>
              <dd className={MONO}>{r.placement}</dd>
            </div>
          )}
          {r.kex_share !== undefined && (
            <div>
              <dt>{t("platformKexShare")}</dt>
              <dd className={MONO}>{r.kex_share}</dd>
            </div>
          )}
          {r.budget !== undefined && r.budget !== null && (
            <div>
              <dt>{t("platformBudget")}</dt>
              <dd>
                {t("platformBudgetValue", {
                  exercises: r.budget.exercises_per_day,
                  projections: r.budget.projections_per_day,
                })}
              </dd>
            </div>
          )}
          {r.created_at !== undefined && (
            <div>
              <dt>{t("platformCreated")}</dt>
              <dd>{at(r.created_at)}</dd>
            </div>
          )}
        </dl>
      )}
    </Show>
  );
}

/** The realms or sandbox domains of the chosen tenant, and a new one. */
function TenantRealms({
  ctx,
  sandbox,
}: {
  readonly ctx: Ctx;
  readonly sandbox: boolean;
}): ReactElement {
  const [version, setVersion] = useState(0);
  const tenants = useTenants(ctx, 0);
  const [tenant, setTenant] = useState("");
  const [open, setOpen] = useState<string | undefined>(undefined);
  const [list, load] = useRun<Items<RealmMeta>>();
  const kind = sandbox ? "sandbox-domains" : "realms";
  useEffect(() => {
    if (tenant === "") return;
    load(() =>
      adminGet<Items<RealmMeta>>(
        ctx.instance,
        `platform/tenants/${encodeURIComponent(tenant)}/${kind}`,
      ),
    );
  }, [load, ctx.instance, tenant, kind, version]);
  const created = () => {
    setVersion((v) => v + 1);
  };
  return (
    <div
      data-testid={sandbox ? "platform-sandboxes" : "platform-realms"}
      className="flex flex-col gap-4"
    >
      <p className="text-muted-foreground">
        {sandbox ? t("platformSandboxesIntro") : t("platformRealmsIntro")}
      </p>
      <p className={HINT}>{t("platformBoundary")}</p>
      <Show l={tenants}>
        {(p) => (
          <TenantPicker
            id={`${kind}-tenant`}
            tenants={p.items}
            value={tenant}
            onChange={(v) => {
              setTenant(v);
              setOpen(undefined);
            }}
          />
        )}
      </Show>
      {tenant !== "" && (
        <Show l={list}>
          {(p) =>
            p.items.length === 0 ? (
              <p className={HINT}>{t("none")}</p>
            ) : (
              <Table data-testid={`${kind}-list`} className="caption-top">
                <TableCaption className="sr-only">
                  {sandbox ? t("screenSandboxes") : t("screenRealms")}
                </TableCaption>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead scope="col">{t("platformSlug")}</TableHead>
                    <TableHead scope="col">{t("platformStatus")}</TableHead>
                    <TableHead scope="col">{t("platformCreated")}</TableHead>
                    {!sandbox && <TableHead scope="col">{t("platformConsoleLink")}</TableHead>}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {p.items.map((r) => (
                    <TableRow key={r.slug}>
                      <TableCell>
                        <span className="flex flex-wrap items-center gap-2">
                          <Button
                            variant={open === r.slug ? "tinted" : "outline"}
                            size="sm"
                            aria-expanded={open === r.slug}
                            onClick={() => {
                              setOpen(open === r.slug ? undefined : r.slug);
                            }}
                          >
                            <span className={MONO}>{r.slug}</span>
                          </Button>
                          {r.sandbox === true && (
                            <Badge variant="outline">{t("platformSandbox")}</Badge>
                          )}
                        </span>
                      </TableCell>
                      <TableCell>{r.status ?? ""}</TableCell>
                      <TableCell>{at(r.created_at)}</TableCell>
                      {!sandbox && (
                        <TableCell className="whitespace-normal">
                          <ConsoleLink slug={r.slug} />
                        </TableCell>
                      )}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )
          }
        </Show>
      )}
      {open !== undefined && (
        <Panel id={`${kind}-details`} title={t("platformRealmDetails", { slug: open })}>
          <RealmDetails ctx={ctx} slug={open} />
        </Panel>
      )}
      <CreateRealm ctx={ctx} tenant={tenant} sandbox={sandbox} onCreated={created} />
    </div>
  );
}

/** Platform ▸ Realms. */
export function Realms({ ctx }: { readonly ctx: Ctx }): ReactElement {
  return <TenantRealms ctx={ctx} sandbox={false} />;
}

/** Platform ▸ Sandbox domains (OP-151 m.3 (m), X21). */
export function Sandboxes({ ctx }: { readonly ctx: Ctx }): ReactElement {
  return <TenantRealms ctx={ctx} sandbox />;
}

/** Platform ▸ Operator health: the deployment's readiness checks, by name. */
export function Operator({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const [h, load] = useRun<Health>();
  useEffect(() => {
    load(() => adminGet<Health>(ctx.instance, "platform/operator/health"));
  }, [load, ctx.instance]);
  return (
    <div data-testid="platform-operator" className="flex flex-col gap-4">
      <p className="text-muted-foreground">{t("platformOperatorIntro")}</p>
      <Show l={h}>
        {(v) => (
          <>
            <p data-testid="operator-status" data-status={v.status}>
              {v.status === "ready" ? t("platformReady") : t("platformDegraded")}
            </p>
            <ul data-testid="operator-checks" className="flex flex-col gap-1 text-sm">
              {v.checks.map((c) => (
                <li key={c.name} className="flex items-center gap-2" data-ok={c.ok}>
                  <span className={MONO}>{c.name}</span>
                  <Badge variant={c.ok ? "secondary" : "destructive"}>
                    {c.ok ? t("platformCheckOk") : t("platformCheckFailing")}
                  </Badge>
                </li>
              ))}
            </ul>
          </>
        )}
      </Show>
    </div>
  );
}
