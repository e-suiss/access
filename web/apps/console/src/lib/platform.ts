// OP-159 m.41, TN-119, OP-151 m.2 M2: platform administration through the admin proxy. Reads are
// metadata the platform surface names, never a realm's content (INV-29, X31). Every write is drafted
// first (`POST platform/intents`, a read), checked, shown on the signature screen as the Kernel
// decoded it, and only then signed on the viewer's own basis for the action and sent as one
// `idp.platform.*` Exercise.
import { loadKernel } from "@esuiss/access";

import { search } from "./adp.js";
import { call, fromB64url, Problem } from "./api.js";
import { draftHolds, type IntentDraft, problemOf, type WriteResult } from "./admin.js";
import { adminWrite, type Confirm, type Instance, NotSigned, readProof } from "./instance.js";
import { draft } from "./intents.js";
import { type Basis, basisCbor, type HoldingRef } from "./meta.js";

/** The platform actions (`idp.platform.*`). */
export type PlatformAction = "tenant_create" | "realm_create" | "sandbox_create";

/** One platform write the console sends. */
export interface PlatformChange {
  readonly operation: "createTenant" | "createRealm" | "createSandboxDomain";
  readonly action: PlatformAction;
  /** The tenant a realm or sandbox domain is created in. */
  readonly tenant?: string;
  readonly path: string;
  readonly body: Readonly<Record<string, unknown>>;
}

interface HeldGrant extends HoldingRef {
  readonly actions: readonly { readonly namespace?: string; readonly name?: string }[];
}

async function eligibleOn(subject: string, set: unknown): Promise<boolean> {
  const r = await call("/proxy/adp/eligibility:check", { method: "POST", body: { subject, set } });
  if (!r.ok) return false;
  const v = (await r.json()) as { eligible?: unknown };
  return v.eligible === true;
}

/**
 * OP-159 m.41 (a), INV-29, IA-5: the basis a platform write is signed on. The realm's root Anchor
 * when the viewer is eligible on it; otherwise the first of the viewer's own holdings that names
 * the action and is eligible; otherwise none, and nothing is signed.
 */
export async function platformBasis(
  instance: Instance,
  realm: string,
  action: PlatformAction,
): Promise<Basis | undefined> {
  const subject = instance.party;
  if (subject === undefined) return undefined;
  try {
    const d = await draft(
      instance,
      {
        action: { namespace: "idp.platform", name: action, major: 1 },
        resources: [{ namespace: "idp", path: [realm] }],
      },
      "check",
    );
    const probe = d.probe;
    if (probe === undefined) return undefined;
    if (await eligibleOn(subject, { ...probe, intent: d.intent })) {
      const root = probe["basis"] as { readonly anchor?: unknown } | undefined;
      return typeof root?.anchor === "string" ? { anchor: root.anchor } : undefined;
    }
    const held = await search<HeldGrant>(instance, "holdings", {});
    for (const h of held.results) {
      if (!h.actions.some((a) => a.namespace === "idp.platform" && a.name === action)) continue;
      const holding = { grant: h.grant, holder: h.holder, since: h.since };
      if (await eligibleOn(subject, { ...probe, basis: { holding }, intent: d.intent })) {
        return { holding };
      }
    }
  } catch {
    return undefined;
  }
  return undefined;
}

/** Drafts `c`: a read (OP-151 m.11 (a)) that changes nothing. */
async function draftPlatform(instance: Instance, c: PlatformChange): Promise<IntentDraft> {
  const path = "platform/intents";
  const body: Record<string, unknown> = { operation: c.operation, body: c.body };
  if (c.tenant !== undefined) body["key"] = c.tenant;
  const r = await call(`/proxy/admin/${path}`, {
    method: "POST",
    body,
    headers: { "x-access-ais": await readProof(instance, "POST", `/admin/v1/${path}`) },
  });
  if (!r.ok) throw await problemOf(r);
  return (await r.json()) as IntentDraft;
}

/** Drafts, checks, shows and, once the user signs, sends `c`; resolves with the Exercise. */
export async function platformChange(
  instance: Instance,
  confirm: Confirm,
  realm: string,
  c: PlatformChange,
): Promise<WriteResult> {
  const d = await draftPlatform(instance, c);
  const asked = { operation: c.operation, method: "POST" as const, path: c.path, body: c.body };
  const keyed = c.tenant === undefined ? asked : { ...asked, key: c.tenant };
  if (!(await draftHolds(instance, keyed, d))) throw new NotSigned("mismatch");
  const basis = await platformBasis(instance, realm, c.action);
  if (basis === undefined) throw new Problem(403, "exercise-not-allowed", undefined);
  const k = await loadKernel();
  const r = await adminWrite(
    instance,
    confirm,
    "POST",
    c.path,
    fromB64url(d.intent),
    d.body,
    d.pep,
    undefined,
    basisCbor(k, basis),
  );
  if (!r.ok) throw await problemOf(r);
  return (await r.json()) as WriteResult;
}
