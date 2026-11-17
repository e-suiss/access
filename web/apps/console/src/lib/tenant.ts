// OP-159 m.47 (a), (f), (h), m.49, TN-140, TN-143: the tenant as its primary environment answers
// it. The tenant's environments and administrators are read from `/admin/v1/envs/{primary}/tenant/…`;
// every change there is drafted, shown on the signature screen as the Kernel decoded it, signed and
// sent as one `idp.tenant.*` Exercise, as every console change is.
import { queryOptions, skipToken } from "@tanstack/react-query";
import * as v from "valibot";

import { adminGet, change, items, type WriteResult } from "./admin.js";
import { Problem } from "./api.js";
import type { Confirm, Instance } from "./instance.js";

export const TenantEnvironment = v.looseObject({
  slug: v.string(),
  kind: v.picklist(["standard", "primary"]),
  issuer: v.string(),
  created_at: v.string(),
  sandbox: v.boolean(),
});

export type TenantEnvironment = v.InferOutput<typeof TenantEnvironment>;

export const TenantAdmin = v.looseObject({
  id: v.string(),
  identifier: v.string(),
  role: v.picklist(["owner", "admin"]),
  status: v.picklist(["invited", "active", "removed"]),
  since: v.string(),
  // OP-159 m.49 (d): the environments it administers; null is the whole tenant
  environments: v.exactOptional(v.nullable(v.array(v.string()))),
});

export type TenantAdmin = v.InferOutput<typeof TenantAdmin>;

const Environments = items(TenantEnvironment);

const Admins = items(TenantAdmin);

function base(primary: string): string {
  return `envs/${encodeURIComponent(primary)}/tenant`;
}

/**
 * The tenant's environments when `primary` is its primary environment; `null` when it is
 * not one, or the viewer may not read them (OP-159 m.47 (a)).
 */
async function tenantEnvironments(
  instance: Instance,
  primary: string,
): Promise<readonly TenantEnvironment[] | null> {
  try {
    return (await adminGet(instance, `${base(primary)}/environments`, Environments)).items;
  } catch (e: unknown) {
    if (e instanceof Problem && e.status >= 400 && e.status < 500) return null;
    throw e;
  }
}

// OP-159 m.46 (d)
/** The tenant's environments, read once for the session's own Instance. */
export function tenantEnvironmentsQuery(instance: Instance | undefined, primary: string) {
  return queryOptions({
    queryKey: ["tenant", primary, instance?.id, "environments"] as const,
    queryFn:
      instance === undefined || instance.environment !== undefined
        ? skipToken
        : () => tenantEnvironments(instance, primary),
    staleTime: 300_000,
  });
}

/** The tenant's administrators, with their role and status. */
export function tenantAdminsQuery(instance: Instance, primary: string) {
  return queryOptions({
    queryKey: ["tenant", primary, instance.id, "admins"] as const,
    queryFn: async () => (await adminGet(instance, `${base(primary)}/admins`, Admins)).items,
  });
}

/** How a new environment's issuer is addressed. */
export type IssuerStyle = "path" | "subdomain";

// OP-159 m.47 (h)
/** A new environment of the tenant (`createTenantEnvironment`). */
export function createEnvironment(
  instance: Instance,
  confirm: Confirm,
  primary: string,
  body: { readonly slug: string; readonly sandbox: boolean; readonly issuer_style: IssuerStyle },
): Promise<WriteResult> {
  return change(instance, confirm, primary, {
    operation: "createTenantEnvironment",
    method: "POST",
    path: "tenant/environments",
    body,
  });
}

// OP-159 m.47 (f)
/**
 * An invitation to administer the tenant (`inviteTenantAdmin`); `environments` names the slugs it
 * administers, none the whole tenant (OP-159 m.49 (d)).
 */
export function inviteAdmin(
  instance: Instance,
  confirm: Confirm,
  primary: string,
  email: string,
  environments: readonly string[] = [],
): Promise<WriteResult> {
  return change(instance, confirm, primary, {
    operation: "inviteTenantAdmin",
    method: "POST",
    path: "tenant/admins",
    body: environments.length === 0 ? { email } : { email, environments: [...environments].sort() },
  });
}

// OP-159 m.47 (e)
/** Makes administrator `id` an owner (`addTenantOwner`). */
export function addOwner(
  instance: Instance,
  confirm: Confirm,
  primary: string,
  id: string,
): Promise<WriteResult> {
  return change(instance, confirm, primary, {
    operation: "addTenantOwner",
    key: id,
    method: "POST",
    path: `tenant/admins/${encodeURIComponent(id)}/owner`,
    body: {},
  });
}

// OP-159 m.47 (f)
/** Removes administrator `id` (`removeTenantAdmin`); the last owner stays (`last-tenant-owner`). */
export function removeAdmin(
  instance: Instance,
  confirm: Confirm,
  primary: string,
  id: string,
): Promise<WriteResult> {
  return change(instance, confirm, primary, {
    operation: "removeTenantAdmin",
    key: id,
    method: "POST",
    path: `tenant/admins/${encodeURIComponent(id)}/remove`,
    body: {},
  });
}
