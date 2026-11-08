// OP-151 m.20 (b), OP-152 m.7 (d), TN-110, L1-ADP-17, L1-ADP-18: meta-action writes and schema
// publication. The console names a payload in its JSON form and never encodes CBOR: the BFF
// drafts the intent with the payload digest and answers the payload bytes, the Kernel decodes
// the drafted intent for the signature screen, and only after the user signs is the commit sent
// to ADP as one Exercise. A bulk change is one Exercise per item, all shown on one screen.
import { loadKernel } from "@esuiss/access";

import { API, b64url, call, fromB64url, json, Problem } from "./api.js";
import {
  ADP_PEP,
  type Confirm,
  type DecodedIntent,
  decodedIntent,
  decodedStatement,
  type Instance,
  nonce,
  NotSigned,
  readProof,
  sign,
} from "./instance.js";

/** A meta payload in the JSON form of L1-ADP-17: `{"<meta-action>": {...}}`. */
export type MetaPayload = Readonly<Record<string, unknown>>;

interface MetaDraft {
  readonly intent: {
    readonly resources: readonly { readonly namespace: string; readonly path: readonly string[] }[];
  };
  readonly envelope: string;
  readonly payload: string;
  readonly basis?: { readonly anchor: string };
}

/** The meta-action a payload names. */
export function actionOf(payload: MetaPayload): string {
  const [name] = Object.keys(payload);
  return name ?? "";
}

interface Prepared {
  readonly draft: MetaDraft;
  readonly envelope: Uint8Array;
  readonly decoded: DecodedIntent;
  readonly name: string;
}

async function prepare(instance: Instance, payload: MetaPayload): Promise<Prepared> {
  const name = actionOf(payload);
  const draft = await json<MetaDraft>("/intents", {
    method: "POST",
    body: { action: { namespace: "access", name, major: 1 }, payload, mode: "commit" },
    headers: { "x-access-ais": await readProof(instance, "POST", `${API}/intents`) },
  });
  const k = await loadKernel();
  const envelope = fromB64url(draft.envelope);
  const decoded = decodedIntent(k, envelope);
  // TN-110: the drafted intent is the meta-action asked for, on an object of the core
  if (
    decoded.action.namespace !== "access" ||
    decoded.action.name !== name ||
    !decoded.resources.every((r) => r.namespace.startsWith("access."))
  ) {
    throw new NotSigned("mismatch");
  }
  return { draft, envelope, decoded, name };
}

/** What one committed write answered. */
export interface MetaResult {
  readonly decision: boolean;
  readonly outcome: string;
  readonly exercise?: string;
}

/**
 * Drafts every payload, shows all of them on one signature screen and, once the user signs,
 * commits each as its own Exercise, in order; stops at the first one not allowed.
 */
export async function metaWrites(
  instance: Instance,
  confirm: Confirm,
  subject: string,
  payloads: readonly MetaPayload[],
): Promise<readonly MetaResult[]> {
  if (payloads.length === 0) return [];
  const k = await loadKernel();
  const prepared = await Promise.all(payloads.map((p) => prepare(instance, p)));
  const signed = prepared.map((p) => {
    const n = nonce();
    const anchor = p.draft.basis?.anchor;
    if (anchor === undefined) throw new NotSigned("mismatch");
    const basis = k.exerciseBasis("anchor", fromB64url(anchor));
    const statement = k.aisStatement(
      instance.domain,
      n,
      k.intentDigest(p.envelope),
      "commit",
      ADP_PEP,
      new Uint8Array(),
      basis,
      BigInt(Date.now()),
      new Uint8Array(),
    );
    const shown = decodedStatement(k, statement);
    if (shown.intent !== p.decoded.digest) throw new NotSigned("mismatch");
    return { p, n, anchor, statement, shown };
  });
  const first = signed[0];
  if (first === undefined) return [];
  if (!(await confirm({ statement: first.shown, intents: prepared.map((p) => p.decoded) }))) {
    throw new NotSigned("cancelled");
  }
  const out: MetaResult[] = [];
  for (const s of signed) {
    const resource = s.p.draft.intent.resources[0];
    const body = {
      subject: { type: "access_party", id: subject },
      action: { name: s.p.name },
      resource: { type: resource?.namespace ?? "", id: (resource?.path ?? []).join("/") },
      context: {
        domain: b64url(instance.domain),
        mode: "commit",
        nonce: b64url(s.n),
        intent: s.p.draft.intent,
        payload: s.p.draft.payload,
        basis: { anchor: s.anchor },
        capacity: "own",
        ais: await sign(instance.key, k, instance.kid, s.statement),
      },
    };
    const r = await call("/proxy/adp/evaluation", { method: "POST", body });
    if (!r.ok) throw new Problem(r.status, "unavailable", undefined);
    const v = (await r.json()) as {
      decision?: unknown;
      context?: { outcome?: unknown; exercise?: unknown };
    };
    const result: MetaResult = {
      decision: v.decision === true,
      outcome: typeof v.context?.outcome === "string" ? v.context.outcome : "deny",
      ...(typeof v.context?.exercise === "string" ? { exercise: v.context.exercise } : {}),
    };
    out.push(result);
    if (!result.decision) break;
  }
  return out;
}

/** One meta write: [`metaWrites`] with a single payload. */
export async function metaWrite(
  instance: Instance,
  confirm: Confirm,
  subject: string,
  payload: MetaPayload,
): Promise<MetaResult> {
  const [r] = await metaWrites(instance, confirm, subject, [payload]);
  if (r === undefined) throw new Problem(502, "malformed", undefined);
  return r;
}

/** A Schema Publication Package draft (L1-ADP-18). */
export interface PackageDraft {
  readonly namespace: string;
  readonly catalog_version: number;
  readonly actions: readonly Readonly<Record<string, unknown>>[];
  readonly classes: readonly {
    readonly action: string;
    readonly parameter: string;
    readonly class: string;
  }[];
}

/** What a publish answered: kept, or refused with its E12 warnings. */
export type Published =
  | {
      readonly kept: true;
      readonly fingerprint: string;
      readonly new_actions: readonly string[];
      readonly existing_grants_unchanged: boolean;
    }
  | {
      readonly kept: false;
      readonly warnings: readonly { readonly parameter: string; readonly reason: string }[];
    };

async function checkContext(
  instance: Instance,
  ask: Readonly<Record<string, unknown>>,
): Promise<Record<string, unknown>> {
  const k = await loadKernel();
  const d = await json<{ intent: unknown; envelope: string }>("/intents", {
    method: "POST",
    body: { ...ask, mode: "check" },
    headers: { "x-access-ais": await readProof(instance, "POST", `${API}/intents`) },
  });
  const envelope = fromB64url(d.envelope);
  const decoded = decodedIntent(k, envelope);
  const action = ask["action"] as { name: string };
  if (decoded.action.namespace !== "access" || decoded.action.name !== action.name) {
    throw new NotSigned("mismatch");
  }
  const n = nonce();
  const statement = k.aisStatement(
    instance.domain,
    n,
    k.intentDigest(envelope),
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

/**
 * Publishes `pkg` to `domains` as this browser's Party (L1-ADP-18). There is no accept here:
 * each domain accepts only by its own protected change (X21).
 */
export async function publish(
  instance: Instance,
  pkg: PackageDraft,
  domains: readonly string[],
): Promise<Published> {
  const context = await checkContext(instance, {
    action: { namespace: "access", name: "publish", major: 1 },
    resources: [{ namespace: "access.publication", path: [pkg.namespace] }],
    package: pkg,
  });
  const r = await call("/proxy/adp/publications", {
    method: "POST",
    body: { context, package: pkg, domains },
  });
  const v = (await r.json()) as Record<string, unknown>;
  if (r.status === 422 && Array.isArray(v["warnings"])) {
    return {
      kept: false,
      warnings: v["warnings"] as { parameter: string; reason: string }[],
    };
  }
  if (r.status !== 201) {
    throw new Problem(r.status, typeof v["code"] === "string" ? v["code"] : "unknown", undefined);
  }
  return {
    kept: true,
    fingerprint: String(v["fingerprint"]),
    new_actions: (v["new_actions"] as string[] | undefined) ?? [],
    existing_grants_unchanged: v["existing_grants_unchanged"] === true,
  };
}

/** Where the caller's own publication stands (L1-ADP-18). */
export interface PublicationStatus {
  readonly pending_acceptance: readonly string[];
  readonly accepted_in: readonly string[];
}

export async function publicationStatus(
  instance: Instance,
  namespace: string,
  fingerprint: string,
  domains: readonly string[],
): Promise<PublicationStatus> {
  const context = await checkContext(instance, {
    action: { namespace: "access", name: "read", major: 1 },
    resources: [{ namespace: "access.publication", path: [namespace] }],
  });
  return json<PublicationStatus>("/proxy/adp/publications:status", {
    method: "POST",
    body: { context, fingerprint, domains },
  });
}
