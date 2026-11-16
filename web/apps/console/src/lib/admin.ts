// TN-110, MD-14, OP-151 m.11 (a): environment administration through the admin proxy. Reads carry a
// read proof; every change is drafted first (a read), checked, shown on the signature screen as
// the Kernel decoded it, and only then signed and sent as one Exercise.
import { loadKernel } from "@esuiss/access";
import * as v from "valibot";

import { answer, b64url, call, fromB64url, problemOf } from "./api.js";
import {
  adminRead,
  adminWrite,
  type Confirm,
  type Instance,
  NotSigned,
  readProof,
} from "./instance.js";

// OP-159 m.46 (f)
/**
 * A management read of `/admin/v1/{path}` as `schema` reads it; anything but 2xx throws its
 * [`Problem`], and an answer of another shape throws before anything is shown.
 */
export async function adminGet<S extends v.GenericSchema>(
  instance: Instance,
  path: string,
  schema: S,
): Promise<v.InferOutput<S>> {
  return answer(await adminRead(instance, path), schema);
}

/**
 * A management read whose answer is not yet read by a schema: only JSON is checked. Each screen
 * moves to [`adminGet`] with its own schema (OP-159 m.46 (f)).
 */
export async function adminGetAs<T>(instance: Instance, path: string): Promise<T> {
  const value: unknown = await answer(await adminRead(instance, path), v.unknown());
  return value as T;
}

/** A list answer whose items `item` reads. */
export function items<S extends v.GenericSchema>(item: S) {
  return v.object({ items: v.array(item) });
}

/** A management read and its `ETag`, which a `PUT` or `PATCH` of it sends as `If-Match` (OP-65). */
export async function adminGetTagged(
  instance: Instance,
  path: string,
): Promise<{ readonly value: unknown; readonly etag?: string }> {
  const r = await adminRead(instance, path);
  if (!r.ok) throw await problemOf(r);
  const etag = r.headers.get("etag");
  const value: unknown = await r.json();
  return { value, ...(etag === null ? {} : { etag }) };
}

/** What a draft returns (`IntentDraft`). */
export const IntentDraft = v.looseObject({
  operation: v.string(),
  key: v.nullish(v.string()),
  body: v.record(v.string(), v.unknown()),
  domain: v.string(),
  pep: v.string(),
  intent: v.string(),
  intent_digest: v.string(),
});

export type IntentDraft = v.InferOutput<typeof IntentDraft>;

/** What a write returns (`WriteResult`). */
export const WriteResult = v.looseObject({
  exercise_id: v.string(),
  position: v.unknown(),
  resource: v.exactOptional(v.unknown()),
  irreversible: v.exactOptional(v.boolean()),
});

export type WriteResult = v.InferOutput<typeof WriteResult>;

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
  const own = digestBytes(k.intentDigest(fromB64url(d.intent)));
  return own !== undefined && b64url(own) === d.intent_digest;
}

/** The hash bytes of a CBOR `digest` (`[alg, bstr]` or a bare `bstr`); the API sends them bare. */
export function digestBytes(cbor: Uint8Array): Uint8Array | undefined {
  let at = 0;
  if (cbor[at] === 0x82) {
    at += 1;
    const alg = cbor[at];
    if (alg === undefined) return undefined;
    if (alg <= 0x37) at += 1;
    else if (alg === 0x38) at += 2;
    else if (alg === 0x39) at += 3;
    else return undefined;
  }
  const head = cbor[at];
  if (head === undefined) return undefined;
  let len: number;
  if (head >= 0x40 && head <= 0x57) {
    len = head - 0x40;
    at += 1;
  } else if (head === 0x58) {
    len = cbor[at + 1] ?? -1;
    at += 2;
  } else {
    return undefined;
  }
  return len >= 0 && at + len === cbor.length ? cbor.slice(at) : undefined;
}

/** Drafts `c` in environment `slug`: a read (OP-151 m.11 (a)) that changes nothing. */
export async function draftChange(
  instance: Instance,
  slug: string,
  c: Change,
): Promise<IntentDraft> {
  const path = `envs/${encodeURIComponent(slug)}/intents`;
  const body: Record<string, unknown> = { operation: c.operation, body: c.body };
  if (c.key !== undefined) body["key"] = c.key;
  const r = await call(`/proxy/admin/${path}`, {
    method: "POST",
    body,
    headers: { "x-access-ais": await readProof(instance, "POST", `/admin/v1/${path}`) },
  });
  return answer(r, IntentDraft);
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
    `envs/${encodeURIComponent(slug)}/${c.path}`,
    fromB64url(d.intent),
    d.body,
    d.pep,
    c.ifMatch,
  );
  return answer(r, WriteResult);
}
