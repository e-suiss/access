// OP-159 m.47 (a), (e), (f), (h), TN-138, TN-140: the tenant's home at `/console/{management}`. The
// tenant's environments, each a link to its console, which the session administers without a new
// sign-in; a new environment; the administrators with their role and status, an invitation, a new
// owner and a removal. Each change is one signed `idp.tenant.*` Exercise; a control shows only when
// the eligibility check says the viewer can exercise its action (IA-5). The tenant's texts and
// addresses render as text (TN-131).

import { Badge } from "@access/ui/components/badge";
import { Button } from "@access/ui/components/button";
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { type ReactElement, useState } from "react";

import { DataTable } from "../DataTable.js";
import { t } from "../i18n/index.js";
import type { WriteResult } from "../lib/admin.js";
import { consoleLink } from "../lib/links.js";
import { tenantActionsQuery } from "../lib/sections.js";
import {
  addOwner,
  createEnvironment,
  type IssuerStyle,
  inviteAdmin,
  removeAdmin,
  type TenantAdmin,
  type TenantEnvironment,
  tenantAdminsQuery,
  tenantEnvironmentsQuery,
} from "../lib/tenant.js";
import { ACTIONS, CHOICE, CHOICE_LABEL, FORM, HINT, MONO, Notice, Page } from "../ui.js";
import { at, type Ctx, Field, type Loaded, loaded, Panel, Show, useRun } from "./parts.js";

const SLUG = /^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/;

const EMAIL = /^[^\s@]+@[^\s@]+$/;

function Recorded({ w }: { readonly w: Loaded<WriteResult> }): ReactElement {
  return (
    <Show l={w}>
      {(r) => <Notice role="status">{t("changeRecorded", { exercise: r.exercise_id })}</Notice>}
    </Show>
  );
}

function EnvironmentLink({ slug }: { readonly slug: string }): ReactElement {
  return (
    <Link
      to="/$environment"
      params={{ environment: slug }}
      data-testid="tenant-environment-link"
      className={`${MONO} text-primary underline underline-offset-2 hover:text-foreground`}
    >
      {slug}
    </Link>
  );
}

function Environments({
  environments,
}: {
  readonly environments: readonly TenantEnvironment[];
}): ReactElement {
  const rows = [...environments].sort((a, b) =>
    a.kind === b.kind ? a.slug.localeCompare(b.slug) : a.kind === "management" ? -1 : 1,
  );
  return (
    <DataTable
      data-testid="tenant-environments"
      caption={t("tenantEnvironments")}
      label={t("tenantEnvironments")}
      rows={rows}
      rowKey={(e) => e.slug}
      rowProps={(e) => ({ "data-slug": e.slug })}
      columns={[
        {
          id: "slug",
          header: t("platformSlug"),
          rowHeader: true,
          cell: (e) => (
            <span className="flex flex-wrap items-center gap-2">
              <EnvironmentLink slug={e.slug} />
              {e.kind === "management" && <Badge variant="outline">{t("tenantManagement")}</Badge>}
              {e.sandbox && <Badge variant="outline">{t("platformSandbox")}</Badge>}
            </span>
          ),
        },
        { id: "issuer", header: t("platformIssuer"), className: MONO, cell: (e) => e.issuer },
        { id: "created", header: t("platformCreated"), cell: (e) => at(e.created_at) },
      ]}
    />
  );
}

/** A new environment of the tenant (OP-159 m.47 (h)). */
function CreateEnvironment({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const management = ctx.session.environment;
  const [slug, setSlug] = useState("");
  const [sandbox, setSandbox] = useState(false);
  const [style, setStyle] = useState<IssuerStyle>("path");
  const [made, setMade] = useState("");
  const [w, write] = useRun<WriteResult>([
    tenantEnvironmentsQuery(ctx.instance, management).queryKey,
  ]);
  const valid = SLUG.test(slug) && slug !== "api" && slug !== "assets";
  return (
    <Panel id="tenant-environment-create" title={t("tenantEnvironmentCreate")}>
      <p className={HINT}>{t("tenantEnvironmentCreateHint")}</p>
      <form
        className={FORM}
        onSubmit={(e) => {
          e.preventDefault();
          if (!valid) return;
          const wanted = slug;
          write(async () => {
            const r = await createEnvironment(ctx.instance, ctx.confirm, management, {
              slug: wanted,
              sandbox,
              issuer_style: style,
            });
            setMade(wanted);
            return r;
          });
        }}
      >
        <Field
          id="tenant-environment-slug"
          label={t("platformSlug")}
          hint={t("platformSlugHint")}
          value={slug}
          onChange={(v) => {
            setSlug(v.trim().toLowerCase());
          }}
        />
        <label className={CHOICE_LABEL}>
          <input
            className={CHOICE}
            type="checkbox"
            checked={sandbox}
            onChange={(e) => {
              setSandbox(e.target.checked);
            }}
          />
          {t("tenantEnvironmentSandbox")}
        </label>
        <fieldset className="flex flex-col gap-2">
          <legend className="mb-1 text-sm font-semibold">{t("platformIssuerStyle")}</legend>
          {(["path", "subdomain"] as const).map((s) => (
            <label key={s} className={CHOICE_LABEL}>
              <input
                className={CHOICE}
                type="radio"
                name="tenant-environment-style"
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
        <div className={ACTIONS}>
          <Button type="submit" disabled={!valid}>
            {t("tenantEnvironmentCreateSend")}
          </Button>
        </div>
      </form>
      <Recorded w={w} />
      {w.status === "done" && made !== "" && (
        <p data-testid="tenant-environment-created">
          {t("platformConsoleLinkCreated")}{" "}
          <Link
            to="/$environment"
            params={{ environment: made }}
            className={`${MONO} break-all text-primary underline underline-offset-2 hover:text-foreground`}
          >
            {consoleLink(made)}
          </Link>
        </p>
      )}
    </Panel>
  );
}

function roleText(a: TenantAdmin): string {
  return a.role === "owner" ? t("tenantRoleOwner") : t("tenantRoleAdmin");
}

function statusText(a: TenantAdmin): string {
  if (a.status === "invited") return t("tenantStatusInvited");
  if (a.status === "removed") return t("tenantStatusRemoved");
  return t("tenantStatusActive");
}

/** The administrators, an invitation, a new owner and a removal (OP-159 m.47 (e), (f)). */
function Administrators({
  ctx,
  can,
}: {
  readonly ctx: Ctx;
  readonly can: ReadonlySet<string>;
}): ReactElement {
  const management = ctx.session.environment;
  const query = tenantAdminsQuery(ctx.instance, management);
  const list = loaded(useQuery(query));
  const [email, setEmail] = useState("");
  const [invited, invite] = useRun<WriteResult>([query.queryKey]);
  const [changed, act] = useRun<WriteResult>([query.queryKey]);
  return (
    <section aria-labelledby="tenant-admins-title" className="flex flex-col gap-4">
      <h2 id="tenant-admins-title" className="text-lg font-semibold">
        {t("tenantAdmins")}
      </h2>
      <p className={HINT}>{t("tenantAdminsIntro")}</p>
      <Show l={list}>
        {(admins) =>
          admins.length === 0 ? (
            <p className={HINT}>{t("none")}</p>
          ) : (
            <DataTable
              data-testid="tenant-admins"
              caption={t("tenantAdmins")}
              label={t("tenantAdmins")}
              rows={admins}
              rowKey={(a) => a.id}
              rowProps={(a) => ({ "data-admin": a.id })}
              columns={[
                {
                  id: "identifier",
                  header: t("tenantAdminIdentifier"),
                  rowHeader: true,
                  className: MONO,
                  cell: (a) => a.identifier,
                },
                {
                  id: "role",
                  header: t("tenantAdminRole"),
                  cell: (a) => (
                    <Badge variant={a.role === "owner" ? "secondary" : "outline"}>
                      {roleText(a)}
                    </Badge>
                  ),
                },
                { id: "status", header: t("platformStatus"), cell: statusText },
                { id: "since", header: t("tenantAdminSince"), cell: (a) => at(a.since) },
                {
                  id: "actions",
                  header: t("tenantAdminActions"),
                  cell: (a) => (
                    <span className="flex flex-wrap gap-2">
                      {can.has("owner_add") && a.role === "admin" && a.status === "active" && (
                        <Button
                          size="sm"
                          variant="outline"
                          aria-label={t("tenantMakeOwnerOf", { who: a.identifier })}
                          onClick={() => {
                            act(() => addOwner(ctx.instance, ctx.confirm, management, a.id));
                          }}
                        >
                          {t("tenantMakeOwner")}
                        </Button>
                      )}
                      {can.has("admin_remove") && a.status !== "removed" && (
                        <Button
                          size="sm"
                          variant="outline"
                          aria-label={t("tenantRemoveOf", { who: a.identifier })}
                          onClick={() => {
                            act(() => removeAdmin(ctx.instance, ctx.confirm, management, a.id));
                          }}
                        >
                          {t("tenantRemove")}
                        </Button>
                      )}
                    </span>
                  ),
                },
              ]}
            />
          )
        }
      </Show>
      <div data-testid="tenant-admin-change">
        <Recorded w={changed} />
      </div>
      {can.has("admin_invite") && (
        <Panel id="tenant-admin-invite" title={t("tenantInvite")}>
          <p className={HINT}>{t("tenantInviteHint")}</p>
          <form
            className={FORM}
            onSubmit={(e) => {
              e.preventDefault();
              const to = email.trim();
              if (!EMAIL.test(to)) return;
              invite(async () => {
                const r = await inviteAdmin(ctx.instance, ctx.confirm, management, to);
                setEmail("");
                return r;
              });
            }}
          >
            <Field
              id="tenant-admin-email"
              label={t("tenantInviteEmail")}
              value={email}
              onChange={setEmail}
            />
            <div className={ACTIONS}>
              <Button type="submit" disabled={!EMAIL.test(email.trim())}>
                {t("tenantInviteSend")}
              </Button>
            </div>
          </form>
          <Recorded w={invited} />
        </Panel>
      )}
    </section>
  );
}

export function TenantHome({
  ctx,
  environments,
}: {
  readonly ctx: Ctx;
  readonly environments: readonly TenantEnvironment[];
}): ReactElement {
  const actions = useQuery(
    tenantActionsQuery(ctx.instance, ctx.session.environment, ctx.session.account),
  );
  const can: ReadonlySet<string> = actions.data ?? new Set();
  return (
    <Page
      title={t("tenantHomeTitle")}
      intro={t("tenantHomeIntro", { environment: ctx.session.environment })}
      data-testid="tenant-home"
    >
      <section aria-labelledby="tenant-environments-title" className="flex flex-col gap-4">
        <h2 id="tenant-environments-title" className="text-lg font-semibold">
          {t("tenantEnvironments")}
        </h2>
        <p className={HINT}>{t("tenantEnvironmentsIntro")}</p>
        <Environments environments={environments} />
        {can.has("environment_create") && <CreateEnvironment ctx={ctx} />}
      </section>
      <Administrators ctx={ctx} can={can} />
    </Page>
  );
}
