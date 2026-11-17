// OP-159 m.47 (a), (f), (h), TN-138, TN-140: the tenant as its management environment answers it. The
// tenant's environments and administrators are read from `/admin/v1/envs/{management}/tenant/…`;
// every change there is drafted, shown on the signature screen as the Kernel decoded it, signed and
// sent as one `idp.tenant.*` Exercise, as every console change is.
import { queryOptions, skipToken } from "@tanstack/react-query";
import * as v from "valibot";

import { adminGet, change, items, type WriteResult } from "./admin.js";
import { Problem } from "./api.js";
import type { Confirm, Instance } from "./instance.js";

export const TenantEnvironment = v.looseObject({
  slug: v.string(),
  kind: v.picklist(["standard", "management"]),
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
});

export type TenantAdmin = v.InferOutput<typeof TenantAdmin>;

const Environments = items(TenantEnvironment);

const SettingsRecorded = v.looseObject({ signin_policy_recorded: v.exactOptional(v.boolean()) });

/**
 * OP-159 m.48 (c): the sign-in requirements a management environment reads from its kind until its
 * founder records them: e-mail and passkey, a second factor required, accounts by invitation only,
 * no social sign-in method.
 */
export const MANAGEMENT_DEFAULTS = {
  methods: ["email", "passkey"],
  required_fields: ["email"],
  mfa_required: true,
  domain_allow: [],
  domain_deny: [],
  registration: "invite_only",
} as const;

const Admins = items(TenantAdmin);

function base(management: string): string {
  return `envs/${encodeURIComponent(management)}/tenant`;
}

/**
 * The tenant's environments when `management` is its management environment; `null` when it is
 * not one, or the viewer may not read them (OP-159 m.47 (a)).
 */
async function tenantEnvironments(
  instance: Instance,
  management: string,
): Promise<readonly TenantEnvironment[] | null> {
  try {
    return (await adminGet(instance, `${base(management)}/environments`, Environments)).items;
  } catch (e: unknown) {
    if (e instanceof Problem && e.status >= 400 && e.status < 500) return null;
    throw e;
  }
}

// OP-159 m.46 (d)
/** The tenant's environments, read once for the session's own Instance. */
export function tenantEnvironmentsQuery(instance: Instance | undefined, management: string) {
  return queryOptions({
    queryKey: ["tenant", management, instance?.id, "environments"] as const,
    queryFn:
      instance === undefined || instance.environment !== undefined
        ? skipToken
        : () => tenantEnvironments(instance, management),
    staleTime: 300_000,
  });
}

/** The tenant's administrators, with their role and status. */
export function tenantAdminsQuery(instance: Instance, management: string) {
  return queryOptions({
    queryKey: ["tenant", management, instance.id, "admins"] as const,
    queryFn: async () => (await adminGet(instance, `${base(management)}/admins`, Admins)).items,
  });
}

// OP-159 m.48 (c)
/** Whether the management environment still reads its sign-in requirements from its kind. */
export function defaultsPendingQuery(instance: Instance, management: string) {
  return queryOptions({
    queryKey: ["tenant", management, instance.id, "defaults"] as const,
    queryFn: async () =>
      (
        await adminGet(
          instance,
          `envs/${encodeURIComponent(management)}/settings`,
          SettingsRecorded,
        )
      ).signin_policy_recorded === false,
  });
}

/** Records the management defaults as the environment's sign-in requirements: one signature. */
export function recordDefaults(
  instance: Instance,
  confirm: Confirm,
  management: string,
): Promise<WriteResult> {
  return change(instance, confirm, management, {
    operation: "putSigninPolicy",
    method: "PUT",
    path: "settings/signin-policy",
    body: MANAGEMENT_DEFAULTS,
  });
}

/** How a new environment's issuer is addressed. */
export type IssuerStyle = "path" | "subdomain";

// OP-159 m.47 (h)
/** A new environment of the tenant (`createTenantEnvironment`). */
export function createEnvironment(
  instance: Instance,
  confirm: Confirm,
  management: string,
  body: { readonly slug: string; readonly sandbox: boolean; readonly issuer_style: IssuerStyle },
): Promise<WriteResult> {
  return change(instance, confirm, management, {
    operation: "createTenantEnvironment",
    method: "POST",
    path: "tenant/environments",
    body,
  });
}

// OP-159 m.47 (f)
/** An invitation to administer the tenant (`inviteTenantAdmin`). */
export function inviteAdmin(
  instance: Instance,
  confirm: Confirm,
  management: string,
  email: string,
): Promise<WriteResult> {
  return change(instance, confirm, management, {
    operation: "inviteTenantAdmin",
    method: "POST",
    path: "tenant/admins",
    body: { email },
  });
}

// OP-159 m.47 (e)
/** Makes administrator `id` an owner (`addTenantOwner`). */
export function addOwner(
  instance: Instance,
  confirm: Confirm,
  management: string,
  id: string,
): Promise<WriteResult> {
  return change(instance, confirm, management, {
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
  management: string,
  id: string,
): Promise<WriteResult> {
  return change(instance, confirm, management, {
    operation: "removeTenantAdmin",
    key: id,
    method: "POST",
    path: `tenant/admins/${encodeURIComponent(id)}/remove`,
    body: {},
  });
}
