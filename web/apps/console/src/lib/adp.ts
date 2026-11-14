// TN-128, PI-4, PI-7, Ek B 3088: authority reads (explain, search) go to ADP as the viewer's own
// `check`, signed in this browser. The BFF adds no credential, so without this browser's key a
// read is the anonymous reader's and sees Public only. Nothing here is recorded.
import { loadKernel } from "@esuiss/access";

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
export interface Page {
  readonly next_token?: string;
  readonly total?: number;
  readonly has_more?: boolean;
}

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

async function answer<T>(r: Response): Promise<T> {
  if (!r.ok) {
    let code = "unknown";
    try {
      const p = (await r.json()) as { code?: unknown };
      if (typeof p.code === "string") code = p.code;
    } catch {
      code = "unknown";
    }
    throw new Problem(r.status, code, undefined);
  }
  return (await r.json()) as T;
}

/** The search intent of `kind`: `access.read` on `access.search:[kind]`. */
export function searchIntent(kind: SearchKind): Wanted {
  return {
    action: { namespace: "access", name: "read", major: 1 },
    resources: [{ namespace: "access.search", path: [kind] }],
  };
}

/** One search page of `kind` for `query`, read as the viewer. */
export async function search<T>(
  instance: Instance,
  kind: SearchKind,
  query: Readonly<Record<string, unknown>>,
  token?: string,
): Promise<SearchAnswer<T>> {
  const context = await signedContext(instance, searchIntent(kind));
  const body: Record<string, unknown> = { context: { ...context, query } };
  if (token !== undefined && token !== "") body["page"] = { token };
  return answer<SearchAnswer<T>>(await call(`/proxy/adp/search/${kind}`, { method: "POST", body }));
}

/** The scope an explanation is read at (OP-141 m.38 (a)). */
export type Scope = "requester" | "viewer" | "audit";

/** A decision explained: the ADP decision body. */
export interface Explained {
  readonly decision?: boolean;
  readonly context?: Readonly<Record<string, unknown>>;
}

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
  return answer<Explained>(await call("/proxy/adp/explain", { method: "POST", body }));
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
  realm: string,
  range: { readonly from: number; readonly to: number; readonly disclosure: "redacted" | "full" },
): Promise<Exported> {
  const k = await loadKernel();
  const w: Wanted = {
    action: { namespace: "access", name: "audit_export", major: 1 },
    resources: [{ namespace: "access.audit", path: [realm] }],
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
    resource: { type: "access.audit", id: realm },
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
  const decided = await answer<Explained>(
    await call("/proxy/adp/evaluation", { method: "POST", body }),
  );
  if (decided.decision !== true) throw new Problem(403, "exercise-not-allowed", undefined);
  const exercise = decided.context?.["exercise"];
  const r = await call("/proxy/adp/audit/export", {
    method: "POST",
    body,
    headers: { accept: "application/cbor-seq" },
  });
  if (!r.ok) await answer<unknown>(r);
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
  const v = (await r.json()) as { eligible?: unknown };
  if (typeof v.eligible !== "boolean") throw new Problem(502, "malformed", undefined);
  return v.eligible;
}
