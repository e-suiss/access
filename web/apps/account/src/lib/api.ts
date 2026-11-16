// OP-153 m.3 (w), TN-131: the account pages speak to their BFF and to the environment's Frontend API,
// both on the environment's own origin; every state change carries the session's CSRF token.
import * as v from "valibot";

const SLUG = /^\/env\/([a-z0-9-]+)\/account(?:\/|$)/.exec(location.pathname)?.[1];

/** The page's own path: `/account` at a host issuer, `/env/{slug}/account` at a path one. */
export const PAGE = SLUG === undefined ? "/account" : `/env/${SLUG}/account`;

/** The BFF's API. */
export const API = `${PAGE}/api`;

/** The environment's Frontend API prefix. */
export const FRONTEND = SLUG === undefined ? "" : `/env/${SLUG}`;

const CSRF_COOKIE = "__Host-access-account-csrf";

/** An RFC 9457 problem. */
export class Problem extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
  ) {
    super(code);
  }
}

function csrfToken(): string | undefined {
  for (const part of document.cookie.split(";")) {
    const [name, value] = part.trim().split("=", 2);
    if (name === CSRF_COOKIE && value !== undefined) return value;
  }
  return undefined;
}

export interface Call {
  readonly method?: "GET" | "POST" | "PUT" | "DELETE";
  readonly body?: unknown;
  readonly headers?: Readonly<Record<string, string>>;
}

async function send(url: string, c: Call, idempotent: boolean): Promise<Response> {
  const method = c.method ?? "GET";
  const headers: Record<string, string> = { accept: "application/json", ...c.headers };
  if (method !== "GET") {
    const token = csrfToken();
    if (token !== undefined) headers["x-csrf-token"] = token;
    // OP-65
    if (idempotent) headers["idempotency-key"] = crypto.randomUUID();
  }
  const init: RequestInit = { method, headers, credentials: "same-origin", cache: "no-store" };
  if (c.body !== undefined) {
    headers["content-type"] = "application/json";
    init.body = JSON.stringify(c.body);
  }
  return fetch(url, init);
}

/** A BFF call. */
export function call(path: string, c: Call = {}): Promise<Response> {
  return send(`${API}${path}`, c, false);
}

/** A Frontend API call (`/v1/...`): cookie only, an `Idempotency-Key` on every write. */
export function frontend(path: string, c: Call = {}): Promise<Response> {
  return send(`${FRONTEND}${path}`, c, true);
}

const ProblemBody = v.object({ code: v.optional(v.string()), type: v.optional(v.string()) });

async function problemOf(r: Response): Promise<Problem> {
  const p = v.safeParse(ProblemBody, await r.json().catch(() => null));
  if (!p.success) return new Problem(r.status, "unknown");
  if (p.output.code !== undefined) return new Problem(r.status, p.output.code);
  if (p.output.type !== undefined)
    return new Problem(r.status, p.output.type.split(":").pop() ?? "");
  return new Problem(r.status, "unknown");
}

/** The code of an answer whose JSON is not what the page reads: shown as any other failure. */
export const MALFORMED = "malformed-answer";

/** A 2xx answer's JSON checked against `schema`; anything else throws its [`Problem`]. */
export async function json<S extends v.GenericSchema>(
  r: Response | Promise<Response>,
  schema: S,
): Promise<v.InferOutput<S>>;
/** A 2xx answer whose body the page does not read; anything else throws its [`Problem`]. */
export async function json(r: Response | Promise<Response>): Promise<unknown>;
export async function json(
  r: Response | Promise<Response>,
  schema?: v.GenericSchema,
): Promise<unknown> {
  const answer = await r;
  if (!answer.ok) throw await problemOf(answer);
  if (schema === undefined) return undefined;
  const body: unknown = answer.status === 204 ? undefined : await answer.json().catch(() => null);
  const parsed = v.safeParse(schema, body);
  if (!parsed.success) throw new Problem(answer.status, MALFORMED);
  return parsed.output;
}

/** What the account pages read of `GET …/account/api/session`. */
export const SessionInfo = v.object({
  environment: v.string(),
  account: v.string(),
  instance: v.nullable(v.string()),
  pep: v.string(),
});
export type SessionInfo = v.InferOutput<typeof SessionInfo>;

/** Who is signed in. */
export function session(): Promise<SessionInfo> {
  return json(call("/session"), SessionInfo);
}

export function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

export function fromB64url(text: string): Uint8Array {
  const s = atob(text.replaceAll("-", "+").replaceAll("_", "/"));
  return Uint8Array.from(s, (c) => c.charCodeAt(0));
}
