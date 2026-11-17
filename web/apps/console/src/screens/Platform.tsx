// OP-159 m.41 (b), (c), m.47 (c), (h), TN-119, OP-151 m.2 M2, INV-29, X31: the Platform section.
// Tenants with their founding, suspension and placement; the environments and sandbox domains in
// them, an environment's metadata with the state of its signing keys; and the deployment's
// readiness. Nothing here opens an environment or shows or changes an environment's accounts, apps,
// authority, records or settings: a tenant's founder and administrators do that in its primary
// environment. Each change is one signed `idp.platform.*` Exercise on the viewer's own Grant.
// OP-159 m.42 (d): each primary environment and environment shows its console link.

import { Badge } from "@access/ui/components/badge";
import { Button } from "@access/ui/components/button";
import { FieldLabel, Field as FieldRoot } from "@access/ui/components/field";
import { NativeSelect, NativeSelectOption } from "@access/ui/components/native-select";
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { type ReactElement, useState } from "react";
import * as v from "valibot";

import { DataTable } from "../DataTable.js";
import { t } from "../i18n/index.js";
import { adminGet, items, type WriteResult } from "../lib/admin.js";
import { consoleLink } from "../lib/links.js";
import { type PlatformChange, platformChange } from "../lib/platform.js";
import { ACTIONS, FORM, HINT, MONO, Notice, ROWS } from "../ui.js";
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
  display_name: v.exactOptional(v.nullable(v.string())),
  primary_slug: v.exactOptional(v.nullable(v.string())),
  founding: v.exactOptional(v.nullable(v.picklist(["pending", "completed", "expired"]))),
  status: v.picklist(["provisioning", "active", "suspended", "deleted"]),
  placement: v.string(),
  created_at: v.exactOptional(v.string()),
});

type Tenant = v.InferOutput<typeof Tenant>;

const KeyState = v.picklist(["pending", "published", "signing", "unavailable"]);

const EnvironmentMeta = v.looseObject({
  slug: v.string(),
  kind: v.exactOptional(v.picklist(["standard", "primary"])),
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
            {tenantName(x)}
          </NativeSelectOption>
        ))}
      </NativeSelect>
    </FieldRoot>
  );
}

function tenantName(x: Tenant): string {
  return x.display_name ?? x.tenant_id;
}

function statusText(s: Tenant["status"]): string {
  if (s === "provisioning") return t("platformTenantProvisioning");
  if (s === "suspended") return t("platformTenantSuspended");
  if (s === "deleted") return t("platformTenantDeleted");
  return t("platformTenantActive");
}

function foundingText(f: Tenant["founding"]): string {
  if (f === "pending") return t("platformFoundingPending");
  if (f === "expired") return t("platformFoundingExpired");
  if (f === "completed") return t("platformFoundingCompleted");
  return t("none");
}

const SLUG = /^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/;

const EMAIL = /^[^\s@]+@[^\s@]+$/;

/** A new tenant awaiting its founder (OP-159 m.47 (c)). */
function CreateTenant({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [email, setEmail] = useState("");
  const [placement, setPlacement] = useState("");
  const [made, setMade] = useState("");
  const [w, write] = useRun<WriteResult>([tenantsKey(ctx)]);
  const ready =
    name.trim() !== "" &&
    name.trim().length <= 120 &&
    SLUG.test(slug) &&
    slug !== "api" &&
    slug !== "assets" &&
    EMAIL.test(email.trim());
  return (
    <Panel id="tenant-create" title={t("platformTenantCreate")}>
      <p className={HINT}>{t("platformTenantCreateHint")}</p>
      <form
        className={FORM}
        onSubmit={(e) => {
          e.preventDefault();
          if (!ready) return;
          const body: Record<string, unknown> = {
            display_name: name.trim(),
            primary_slug: slug,
            founder_email: email.trim(),
            ...(placement === "" ? {} : { placement }),
          };
          const wanted = slug;
          write(async () => {
            const r = await platformChange(ctx.instance, ctx.confirm, ctx.session.environment, {
              operation: "createTenant",
              action: "tenant_create",
              path: "platform/tenants",
              body,
            });
            setMade(wanted);
            return r;
          });
        }}
      >
        <Field id="tenant-name" label={t("platformTenantName")} value={name} onChange={setName} />
        <Field
          id="tenant-slug"
          label={t("platformPrimarySlug")}
          hint={t("platformPrimarySlugHint")}
          value={slug}
          onChange={(v) => {
            setSlug(v.trim().toLowerCase());
          }}
        />
        <Field
          id="tenant-founder"
          label={t("platformFounderEmail")}
          hint={t("platformFounderEmailHint")}
          value={email}
          onChange={setEmail}
        />
        <Field
          id="tenant-placement"
          label={t("platformPlacementOptional")}
          value={placement}
          onChange={(v) => {
            setPlacement(v.trim());
          }}
        />
        <div className={ACTIONS}>
          <Button type="submit" disabled={!ready}>
            {t("platformTenantCreateSend")}
          </Button>
        </div>
      </form>
      <Recorded w={w} />
      {w.status === "done" && made !== "" && (
        <p data-testid="tenant-console-created">
          {t("platformTenantConsoleCreated")} <ConsoleLink slug={made} />
        </p>
      )}
    </Panel>
  );
}

/** One tenant's changes: a new founder invitation, suspension, reactivation, placement. */
function TenantActions({
  ctx,
  tenant,
}: {
  readonly ctx: Ctx;
  readonly tenant: Tenant;
}): ReactElement {
  const [email, setEmail] = useState("");
  const [placement, setPlacement] = useState("");
  const [w, write] = useRun<WriteResult>([tenantsKey(ctx)]);
  const id = tenant.tenant_id;
  const base = `platform/tenants/${encodeURIComponent(id)}`;
  const send = (c: Omit<PlatformChange, "tenant">) => {
    write(() =>
      platformChange(ctx.instance, ctx.confirm, ctx.session.environment, { ...c, tenant: id }),
    );
  };
  const founding = tenant.founding === "pending" || tenant.founding === "expired";
  return (
    <Panel id="tenant-actions" title={t("platformTenantDetails", { name: tenantName(tenant) })}>
      <dl className={ROWS} data-testid="tenant-meta">
        <div>
          <dt>{t("platformTenant")}</dt>
          <dd className={MONO}>{id}</dd>
        </div>
        <div>
          <dt>{t("platformFounding")}</dt>
          <dd>{foundingText(tenant.founding)}</dd>
        </div>
      </dl>
      {founding && (
        <form
          className={FORM}
          onSubmit={(e) => {
            e.preventDefault();
            if (!EMAIL.test(email.trim())) return;
            send({
              operation: "reinviteFounder",
              action: "tenant_create",
              path: `${base}/reinvite-founder`,
              body: { founder_email: email.trim() },
            });
          }}
        >
          <Field
            id="tenant-reinvite-email"
            label={t("platformFounderEmail")}
            hint={t("platformReinviteHint")}
            value={email}
            onChange={setEmail}
          />
          <div className={ACTIONS}>
            <Button type="submit" variant="outline" disabled={!EMAIL.test(email.trim())}>
              {t("platformReinvite")}
            </Button>
          </div>
        </form>
      )}
      <div className={ACTIONS}>
        {tenant.status === "active" && (
          <Button
            variant="destructive"
            onClick={() => {
              send({
                operation: "suspendTenant",
                action: "tenant_suspend",
                path: `${base}/suspend`,
                body: {},
              });
            }}
          >
            {t("platformSuspend")}
          </Button>
        )}
        {tenant.status === "suspended" && (
          <Button
            variant="outline"
            onClick={() => {
              send({
                operation: "reactivateTenant",
                action: "tenant_reactivate",
                path: `${base}/reactivate`,
                body: {},
              });
            }}
          >
            {t("platformReactivate")}
          </Button>
        )}
      </div>
      <form
        className={FORM}
        onSubmit={(e) => {
          e.preventDefault();
          if (placement === "") return;
          send({
            operation: "moveTenantPlacement",
            action: "tenant_placement",
            path: `${base}/placement`,
            body: { placement },
          });
        }}
      >
        <Field
          id="tenant-move-placement"
          label={t("platformPlacementNew")}
          hint={t("platformPlacementNewHint", { placement: tenant.placement })}
          value={placement}
          onChange={(v) => {
            setPlacement(v.trim());
          }}
        />
        <div className={ACTIONS}>
          <Button type="submit" variant="outline" disabled={placement === ""}>
            {t("platformPlacementMove")}
          </Button>
        </div>
      </form>
      <Recorded w={w} />
    </Panel>
  );
}

/** Platform ▸ Tenants: every tenant, its changes and a new one. */
export function Tenants({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const list = useTenants(ctx);
  const [open, setOpen] = useState<string | undefined>(undefined);
  const chosen =
    list.status === "done" ? list.value.items.find((x) => x.tenant_id === open) : undefined;
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
              rowProps={(x) => ({ "data-tenant": x.tenant_id })}
              columns={[
                {
                  id: "tenant",
                  header: t("platformTenantName"),
                  rowHeader: true,
                  cell: tenantName,
                },
                {
                  id: "primary",
                  header: t("platformPrimarySlug"),
                  className: "whitespace-normal",
                  cell: (x) =>
                    typeof x.primary_slug === "string" ? (
                      <span className="flex flex-col gap-1">
                        <span className={MONO}>{x.primary_slug}</span>
                        <ConsoleLink slug={x.primary_slug} />
                      </span>
                    ) : (
                      ""
                    ),
                },
                { id: "status", header: t("platformStatus"), cell: (x) => statusText(x.status) },
                {
                  id: "founding",
                  header: t("platformFounding"),
                  cell: (x) => foundingText(x.founding),
                },
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
      <Show l={list}>
        {(p) =>
          p.items.length === 0 ? null : (
            <TenantPicker
              id="tenant-change"
              tenants={p.items}
              value={open ?? ""}
              onChange={(v) => {
                setOpen(v === "" ? undefined : v);
              }}
            />
          )
        }
      </Show>
      {chosen !== undefined && <TenantActions key={chosen.tenant_id} ctx={ctx} tenant={chosen} />}
      <CreateTenant ctx={ctx} />
    </div>
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
                        {r.kind === "primary" && (
                          <Badge variant="outline">{t("tenantPrimary")}</Badge>
                        )}
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
