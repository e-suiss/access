// OP-159 m.41 (b), (c), TN-119, OP-151 m.2 M2, INV-29, X31: the Platform section. Tenants, the
// environments and sandbox domains in them, an environment's metadata with the state of its signing keys, and
// the deployment's readiness. Nothing here shows or changes an environment's accounts, apps, authority,
// records or settings: managing an environment means signing in to it. Each creation is one signed
// `idp.platform.*` Exercise on the viewer's own Grant. OP-159 m.42 (d): each environment shows its
// console link.
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState, type ReactElement } from "react";
import * as v from "valibot";

import { Badge } from "@access/ui/components/badge";
import { Button } from "@access/ui/components/button";
import { Field as FieldRoot, FieldLabel } from "@access/ui/components/field";
import { NativeSelect, NativeSelectOption } from "@access/ui/components/native-select";

import { DataTable } from "../DataTable.js";
import { t } from "../i18n/index.js";
import { adminGet, items, type WriteResult } from "../lib/admin.js";
import { consoleLink } from "../lib/links.js";
import { platformChange, type PlatformChange } from "../lib/platform.js";
import { ACTIONS, CHOICE, CHOICE_LABEL, FORM, HINT, MONO, Notice, ROWS } from "../ui.js";
import {
  at,
  type Ctx,
  Field,
  type Loaded,
  loaded,
  Panel,
  readKey,
  Show,
  useLoad,
  useRun,
} from "./parts.js";

const Tenant = v.looseObject({
  tenant_id: v.string(),
  status: v.string(),
  placement: v.string(),
  created_at: v.exactOptional(v.string()),
});

type Tenant = v.InferOutput<typeof Tenant>;

const KeyState = v.picklist(["pending", "published", "signing", "unavailable"]);

const EnvironmentMeta = v.looseObject({
  slug: v.string(),
  tenant_id: v.exactOptional(v.string()),
  issuer: v.exactOptional(v.nullable(v.string())),
  status: v.exactOptional(v.string()),
  placement: v.exactOptional(v.string()),
  domain: v.exactOptional(v.string()),
  sandbox: v.exactOptional(v.boolean()),
  budget: v.exactOptional(
    v.nullable(v.looseObject({ exercises_per_day: v.string(), projections_per_day: v.string() })),
  ),
  created_at: v.exactOptional(v.string()),
  key_state: v.exactOptional(KeyState),
  signing_available_at: v.exactOptional(v.nullable(v.string())),
  kex_share: v.exactOptional(v.string()),
});

type EnvironmentMeta = v.InferOutput<typeof EnvironmentMeta>;

const Health = v.looseObject({
  status: v.picklist(["ready", "degraded"]),
  checks: v.array(v.looseObject({ name: v.string(), ok: v.boolean() })),
});

const Tenants_ = items(Tenant);

const Environments_ = items(EnvironmentMeta);

function keyState(s: EnvironmentMeta["key_state"]): string {
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

/** OP-159 m.42 (d): the console link of environment `slug`. */
function ConsoleLink({ slug }: { readonly slug: string }): ReactElement {
  return (
    <Link
      to="/$environment"
      params={{ environment: slug }}
      data-testid="environment-console-link"
      className={`${MONO} break-all text-primary underline underline-offset-2 hover:text-foreground`}
    >
      {consoleLink(slug)}
    </Link>
  );
}

/** The key of the tenants read, which a new tenant invalidates. */
function tenantsKey(ctx: Ctx) {
  return readKey(ctx, "platform/tenants");
}

/** The tenants. */
function useTenants(ctx: Ctx): Loaded<v.InferOutput<typeof Tenants_>> {
  const list = useLoad(tenantsKey(ctx), () => adminGet(ctx.instance, "platform/tenants", Tenants_));
  return list;
}

/** The tenant an environment list and a creation are in. */
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
  const list = useTenants(ctx);
  const [placement, setPlacement] = useState("");
  const [w, write] = useRun<WriteResult>([tenantsKey(ctx)]);
  return (
    <div data-testid="platform-tenants" className="flex flex-col gap-4">
      <p className="text-muted-foreground">{t("platformTenantsIntro")}</p>
      <Show l={list}>
        {(p) =>
          p.items.length === 0 ? (
            <p className={HINT}>{t("none")}</p>
          ) : (
            <DataTable
              data-testid="tenant-list"
              caption={t("screenTenants")}
              label={t("screenTenants")}
              rows={p.items}
              rowKey={(x) => x.tenant_id}
              columns={[
                {
                  id: "tenant",
                  header: t("platformTenant"),
                  className: MONO,
                  cell: (x) => x.tenant_id,
                },
                { id: "status", header: t("platformStatus"), cell: (x) => x.status },
                {
                  id: "placement",
                  header: t("platformPlacement"),
                  className: MONO,
                  cell: (x) => x.placement,
                },
                { id: "created", header: t("platformCreated"), cell: (x) => at(x.created_at) },
              ]}
            />
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
            write(() =>
              platformChange(ctx.instance, ctx.confirm, ctx.session.environment, {
                operation: "createTenant",
                action: "tenant_create",
                path: "platform/tenants",
                body,
              }),
            );
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

/** A new environment or sandbox domain in `tenant`, its founding root the viewer's choice (TN-111). */
function CreateEnvironment({
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
  const prefix = sandbox ? "sandbox" : "environment";
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
          operation: "createEnvironment",
          action: "environment_create",
          tenant,
          path: `platform/tenants/${encodeURIComponent(tenant)}/envs`,
          body,
        };
    const wanted = slug;
    write(async () => {
      const r = await platformChange(ctx.instance, ctx.confirm, ctx.session.environment, c);
      setMade(wanted);
      onCreated();
      return r;
    });
  };
  return (
    <Panel
      id={`${prefix}-create`}
      title={sandbox ? t("platformSandboxCreate") : t("platformEnvironmentCreate")}
    >
      <p className={HINT}>
        {sandbox ? t("platformSandboxCreateHint") : t("platformEnvironmentCreateHint")}
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
            {sandbox ? t("platformSandboxCreateSend") : t("platformEnvironmentCreateSend")}
          </Button>
        </div>
      </form>
      <Recorded w={w} />
      {!sandbox && w.status === "done" && made !== "" && (
        <p data-testid="environment-console-created">
          {t("platformConsoleLinkCreated")} <ConsoleLink slug={made} />
        </p>
      )}
    </Panel>
  );
}

/** One environment's metadata and the state of its signing keys. */
function EnvironmentDetails({
  ctx,
  slug,
}: {
  readonly ctx: Ctx;
  readonly slug: string;
}): ReactElement {
  const m = useLoad(readKey(ctx, "platform/envs", slug), () =>
    adminGet(ctx.instance, `platform/envs/${encodeURIComponent(slug)}`, EnvironmentMeta),
  );
  return (
    <Show l={m}>
      {(r) => (
        <dl className={ROWS} data-testid="environment-meta">
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
            <dd data-testid="environment-key-state" data-state={r.key_state ?? "unavailable"}>
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

/** The environments or sandbox domains of the chosen tenant, and a new one. */
function TenantEnvironments({
  ctx,
  sandbox,
}: {
  readonly ctx: Ctx;
  readonly sandbox: boolean;
}): ReactElement {
  const client = useQueryClient();
  const tenants = useTenants(ctx);
  const [tenant, setTenant] = useState("");
  const [open, setOpen] = useState<string | undefined>(undefined);
  const kind = sandbox ? "sandbox-domains" : "envs";
  const listKey = readKey(ctx, "platform/tenants", tenant, kind);
  const list = useQuery({
    queryKey: listKey,
    queryFn: () =>
      adminGet(
        ctx.instance,
        `platform/tenants/${encodeURIComponent(tenant)}/${kind}`,
        Environments_,
      ),
    enabled: tenant !== "",
  });
  const created = () => {
    void client.invalidateQueries({ queryKey: listKey });
  };
  return (
    <div
      data-testid={sandbox ? "platform-sandboxes" : "platform-environments"}
      className="flex flex-col gap-4"
    >
      <p className="text-muted-foreground">
        {sandbox ? t("platformSandboxesIntro") : t("platformEnvironmentsIntro")}
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
        <Show l={loaded(list)}>
          {(p) =>
            p.items.length === 0 ? (
              <p className={HINT}>{t("none")}</p>
            ) : (
              <DataTable
                data-testid={`${kind}-list`}
                caption={sandbox ? t("screenSandboxes") : t("screenEnvironments")}
                label={sandbox ? t("screenSandboxes") : t("screenEnvironments")}
                rows={p.items}
                rowKey={(r) => r.slug}
                columns={[
                  {
                    id: "slug",
                    header: t("platformSlug"),
                    cell: (r) => (
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
                    ),
                  },
                  { id: "status", header: t("platformStatus"), cell: (r) => r.status ?? "" },
                  { id: "created", header: t("platformCreated"), cell: (r) => at(r.created_at) },
                  ...(sandbox
                    ? []
                    : [
                        {
                          id: "link",
                          header: t("platformConsoleLink"),
                          className: "whitespace-normal",
                          cell: (r: EnvironmentMeta) => <ConsoleLink slug={r.slug} />,
                        },
                      ]),
                ]}
              />
            )
          }
        </Show>
      )}
      {open !== undefined && (
        <Panel id={`${kind}-details`} title={t("platformEnvironmentDetails", { slug: open })}>
          <EnvironmentDetails ctx={ctx} slug={open} />
        </Panel>
      )}
      <CreateEnvironment ctx={ctx} tenant={tenant} sandbox={sandbox} onCreated={created} />
    </div>
  );
}

/** Platform ▸ Environments. */
export function Environments({ ctx }: { readonly ctx: Ctx }): ReactElement {
  return <TenantEnvironments ctx={ctx} sandbox={false} />;
}

/** Platform ▸ Sandbox domains (OP-151 m.3 (m), X21). */
export function Sandboxes({ ctx }: { readonly ctx: Ctx }): ReactElement {
  return <TenantEnvironments ctx={ctx} sandbox />;
}

/** Platform ▸ Operator health: the deployment's readiness checks, by name. */
export function Operator({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const h = useLoad(readKey(ctx, "platform/operator/health"), () =>
    adminGet(ctx.instance, "platform/operator/health", Health),
  );
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
