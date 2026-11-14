// TN-110, MD-14, OP-151 m.11 (a): realm administration through the admin proxy. Reads carry a
// read proof; every change is drafted first (a read), checked, shown on the signature screen as
// the Kernel decoded it, and only then signed and sent as one Exercise.
import { loadKernel } from "@esuiss/access";

import { b64url, call, fromB64url, Problem } from "./api.js";
import {
  adminRead,
  adminWrite,
  type Confirm,
  type Instance,
  NotSigned,
  readProof,
} from "./instance.js";

async function problemOf(r: Response): Promise<Problem> {
  try {
    const p = (await r.json()) as { code?: unknown; reason?: unknown };
    return new Problem(
      r.status,
      typeof p.code === "string" ? p.code : "unknown",
      typeof p.reason === "string" ? p.reason : undefined,
    );
  } catch {
    return new Problem(r.status, "unknown", undefined);
  }
}

/** A management read of `/admin/v1/{path}`; anything but 2xx throws its [`Problem`]. */
export async function adminGet<T>(instance: Instance, path: string): Promise<T> {
  const r = await adminRead(instance, path);
  if (!r.ok) throw await problemOf(r);
  return (await r.json()) as T;
}

/** A management read and its `ETag`, which a `PUT` or `PATCH` of it sends as `If-Match` (OP-65). */
export async function adminGetTagged(
  instance: Instance,
  path: string,
): Promise<{ readonly value: unknown; readonly etag?: string }> {
  const r = await adminRead(instance, path);
  if (!r.ok) throw await problemOf(r);
  const etag = r.headers.get("etag");
  return { value: (await r.json()) as unknown, ...(etag === null ? {} : { etag }) };
}

/** What a draft returns (`IntentDraft`). */
export interface IntentDraft {
  readonly operation: string;
  readonly key?: string | null;
  readonly body: Readonly<Record<string, unknown>>;
  readonly domain: string;
  readonly pep: string;
  readonly intent: string;
  readonly intent_digest: string;
}

/** What a write returns (`WriteResult`). */
export interface WriteResult {
  readonly exercise_id: string;
  readonly position: unknown;
  readonly resource?: unknown;
  readonly irreversible?: boolean;
}

/** One change a screen asks for. */
export interface Change {
  readonly operation: string;
  readonly key?: string;
  readonly method: "POST" | "PUT" | "PATCH";
  readonly path: string;
  readonly body: Readonly<Record<string, unknown>>;
  /** The resource's `ETag` for a `PUT` or `PATCH` (OP-65). */
  readonly ifMatch?: string;
}

function same(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

/**
 * Whether `d` is the draft of `c` for this Instance's domain: the operation asked for, every
 * member sent back unchanged, and `intent_digest` the digest of the very `intent` bytes.
 */
export async function draftHolds(instance: Instance, c: Change, d: IntentDraft): Promise<boolean> {
  if (d.operation !== c.operation || (c.key ?? null) !== (d.key ?? null)) return false;
  if (d.domain !== b64url(instance.domain)) return false;
  if (!Object.entries(c.body).every(([k, v]) => same(d.body[k], v))) return false;
  const k = await loadKernel();
  return b64url(k.intentDigest(fromB64url(d.intent))) === d.intent_digest;
}

/** Drafts `c` in realm `slug`: a read (OP-151 m.11 (a)) that changes nothing. */
export async function draftChange(
  instance: Instance,
  slug: string,
  c: Change,
): Promise<IntentDraft> {
  const path = `realms/${encodeURIComponent(slug)}/intents`;
  const body: Record<string, unknown> = { operation: c.operation, body: c.body };
  if (c.key !== undefined) body["key"] = c.key;
  const r = await call(`/proxy/admin/${path}`, {
    method: "POST",
    body,
    headers: { "x-access-ais": await readProof(instance, "POST", `/admin/v1/${path}`) },
  });
  if (!r.ok) throw await problemOf(r);
  return (await r.json()) as IntentDraft;
}

/** Drafts, checks, shows and, once the user signs, sends `c`; resolves with the Exercise. */
export async function change(
  instance: Instance,
  confirm: Confirm,
  slug: string,
  c: Change,
): Promise<WriteResult> {
  const d = await draftChange(instance, slug, c);
  if (!(await draftHolds(instance, c, d))) throw new NotSigned("mismatch");
  const r = await adminWrite(
    instance,
    confirm,
    c.method,
    `realms/${encodeURIComponent(slug)}/${c.path}`,
    fromB64url(d.intent),
    d.body,
    d.pep,
    c.ifMatch,
  );
  if (!r.ok) throw await problemOf(r);
  return (await r.json()) as WriteResult;
}
