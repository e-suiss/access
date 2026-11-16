// TN-128, PI-4, PI-7, Ek B 3088: authority reads (explain, search) go to ADP as the viewer's own
// `check`, signed in this browser. The BFF adds no credential, so without this browser's key a
// read is the anonymous reader's and sees Public only. Nothing here is recorded.
import { loadKernel } from "@esuiss/access";
import * as v from "valibot";

import { b64url, call, Problem } from "./api.js";
import { draft, type Wanted } from "./intents.js";
import {
  ADP_PEP,
  type Confirm,
  decodedStatement,
  type Instance,
  nonce,
  NotSigned,
  sign,
} from "./instance.js";

/** The search kinds the console reads (L1-ADP-16, OP-151 m.13 (d)). */
export type SearchKind =
  | "subject"
  | "resource"
  | "action"
  | "roles"
  | "role"
  | "admin-grant"
  | "holdings"
  | "changes"
  | "bulk-impact"
  | "sources"
  | "schema-publications"
  | "change-impact"
  | "revocation-impact"
  | "compromise-impact";

/** A search page's `page` member (OP-151 m.8 (g)). */
const Page = v.object({
  next_token: v.exactOptional(v.string()),
  total: v.exactOptional(v.number()),
  has_more: v.exactOptional(v.boolean()),
});

export type Page = Readonly<v.InferOutput<typeof Page>>;

// OP-159 m.46 (f)
/** A search answer whose results `item` reads. */
function searchAnswer<T>(item: v.GenericSchema<unknown, T>) {
  return v.object({ results: v.array(item), page: v.optional(Page, {}) });
}

/** One of the viewer's own holdings, as the `holdings` search answers (IA-5). */
export const Holding = v.looseObject({
  grant: v.string(),
  holder: v.string(),
  since: v.number(),
  actions: v.array(
    v.looseObject({ namespace: v.exactOptional(v.string()), name: v.exactOptional(v.string()) }),
  ),
});

export type Holding = v.InferOutput<typeof Holding>;

/** The viewer's own holdings (IA-5, OP-152 m.7 (b)). */
export async function holdings(instance: Instance): Promise<readonly Holding[]> {
  return (await search(instance, "holdings", {}, undefined, Holding)).results;
}

/** An eligibility check's answer: only a literal `true` is eligible (fail closed). */
export const Eligibility = v.looseObject({ eligible: v.optional(v.unknown()) });

export interface SearchAnswer<T> {
  readonly results: readonly T[];
  readonly page: Page;
}

async function signedContext(instance: Instance, w: Wanted): Promise<Record<string, unknown>> {
  const k = await loadKernel();
  const d = await draft(instance, w, "check");
  const n = nonce();
  const statement = k.aisStatement(
    instance.domain,
    n,
    k.intentDigest(d.envelope),
    "check",
    ADP_PEP,
    new Uint8Array(),
    instance.basis,
    BigInt(Date.now()),
    new Uint8Array(),
  );
  return {
    domain: b64url(instance.domain),
    mode: "check",
    nonce: b64url(n),
    intent: d.intent,
    basis: { public: instance.publicBasis },
    capacity: "own",
    ais: await sign(instance.key, k, instance.kid, statement),
  };
}

async function failed(r: Response): Promise<Problem> {
  let code = "unknown";
  try {
    const p = v.parse(v.looseObject({ code: v.optional(v.unknown()) }), await r.json());
    if (typeof p.code === "string") code = p.code;
  } catch {
    code = "unknown";
  }
  return new Problem(r.status, code, undefined);
}

async function answer<T>(r: Response, schema: v.GenericSchema<unknown, T>): Promise<T> {
  if (!r.ok) throw await failed(r);
  return v.parse(schema, await r.json());
}

/** The search intent of `kind`: `access.read` on `access.search:[kind]`. */
export function searchIntent(kind: SearchKind): Wanted {
  return {
    action: { namespace: "access", name: "read", major: 1 },
    resources: [{ namespace: "access.search", path: [kind] }],
  };
}

/** One search page of `kind` for `query`, read as the viewer. */
export async function search<T = unknown>(
  instance: Instance,
  kind: SearchKind,
  query: Readonly<Record<string, unknown>>,
  token?: string,
  item: v.GenericSchema<unknown, T> = v.unknown() as v.GenericSchema<unknown, T>,
): Promise<SearchAnswer<T>> {
  const context = await signedContext(instance, searchIntent(kind));
  const body: Record<string, unknown> = { context: { ...context, query } };
  if (token !== undefined && token !== "") body["page"] = { token };
  return answer(
    await call(`/proxy/adp/search/${kind}`, { method: "POST", body }),
    searchAnswer(item),
  );
}

/** The scope an explanation is read at (OP-141 m.38 (a)). */
export type Scope = "requester" | "viewer" | "audit";

/** A decision explained: the ADP decision body. */
const Explained = v.looseObject({
  decision: v.exactOptional(v.boolean()),
  context: v.exactOptional(v.record(v.string(), v.unknown())),
});

export type Explained = Readonly<v.InferOutput<typeof Explained>>;

/**
 * The explanation of `w` for the viewer: advisory now, or of recorded decision `record` at
 * `scope` (E-1). The AuthZEN carriers name the intent's action and first resource (L1-ADP-5).
 */
export async function explain(
  instance: Instance,
  subject: string,
  w: Wanted,
  record?: { readonly position: number; readonly scope: Scope },
): Promise<Explained> {
  const context = await signedContext(instance, w);
  const first = w.resources[0];
  const body = {
    subject: { type: "access_party", id: subject },
    action: { name: w.action.name },
    resource: { type: first?.namespace ?? "", id: (first?.path ?? []).join("/") },
    context: {
      ...context,
      ...(record === undefined ? {} : { record: record.position, scope: record.scope }),
    },
  };
  return answer(await call("/proxy/adp/explain", { method: "POST", body }), Explained);
}

/**
 * OP-151 m.8 (b): an audit export is itself an Exercise (`access.audit_export`) with typed
 * `from`, `to` and `disclosure`. The signature screen shows the Kernel's decoding of the drafted
 * intent; only after the user signs is the commit sent, and the package is fetched by sending
 * the committed request again.
 */
export async function exportAudit(
  instance: Instance,
  confirm: Confirm,
  subject: string,
  environment: string,
  range: { readonly from: number; readonly to: number; readonly disclosure: "redacted" | "full" },
): Promise<Exported> {
  const k = await loadKernel();
  const w: Wanted = {
    action: { namespace: "access", name: "audit_export", major: 1 },
    resources: [{ namespace: "access.audit", path: [environment] }],
    params: range,
  };
  const d = await draft(instance, w, "commit");
  const n = nonce();
  const statement = k.aisStatement(
    instance.domain,
    n,
    k.intentDigest(d.envelope),
    "commit",
    ADP_PEP,
    new Uint8Array(),
    instance.basis,
    BigInt(Date.now()),
    new Uint8Array(),
  );
  const shown = decodedStatement(k, statement);
  if (shown.intent !== d.decoded.digest) throw new NotSigned("mismatch");
  if (!(await confirm({ statement: shown, intents: [d.decoded] })))
    throw new NotSigned("cancelled");
  const body = {
    subject: { type: "access_party", id: subject },
    action: { name: w.action.name },
    resource: { type: "access.audit", id: environment },
    context: {
      domain: b64url(instance.domain),
      mode: "commit",
      nonce: b64url(n),
      intent: d.intent,
      basis: { public: instance.publicBasis },
      capacity: "own",
      ais: await sign(instance.key, k, instance.kid, statement),
    },
  };
  // TN-110, OP-151 m.19: the commit is the single write; the package is the same request again
  const decided = await answer(
    await call("/proxy/adp/evaluation", { method: "POST", body }),
    Explained,
  );
  if (decided.decision !== true) throw new Problem(403, "exercise-not-allowed", undefined);
  const exercise = decided.context?.["exercise"];
  const r = await call("/proxy/adp/audit/export", {
    method: "POST",
    body,
    headers: { accept: "application/cbor-seq" },
  });
  if (!r.ok) throw await failed(r);
  const bytes = await r.blob();
  return {
    exercise: typeof exercise === "string" ? exercise : "",
    package: new Blob([bytes], { type: "application/cbor-seq" }),
  };
}

/** An export committed and fetched: its Exercise and the Record Export Package (RFC 8742). */
export interface Exported {
  readonly exercise: string;
  readonly package: Blob;
}

/**
 * The decision lab's Check (§8.17.10.4): would `w` be allowed for `subject` now? An eligibility
 * check on a drafted intent: never recorded and never a promise (E-2).
 */
export async function check(instance: Instance, subject: string, w: Wanted): Promise<boolean> {
  const d = await draft(instance, w, "check");
  if (d.probe === undefined) throw new Problem(502, "malformed", undefined);
  const r = await call("/proxy/adp/eligibility:check", {
    method: "POST",
    body: { subject, set: { ...d.probe, intent: d.intent } },
  });
  if (!r.ok) throw new Problem(r.status, "unavailable", undefined);
  const a = v.safeParse(Eligibility, await r.json());
  if (!a.success || typeof a.output.eligible !== "boolean") {
    throw new Problem(502, "malformed", undefined);
  }
  return a.output.eligible;
}
