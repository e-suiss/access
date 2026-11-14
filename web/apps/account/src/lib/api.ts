// OP-153 m.3 (w), TN-131: the account pages speak to their BFF and to the realm's Frontend API,
// both on the realm's own origin; every state change carries the session's CSRF token.

const SLUG = /^\/realms\/([a-z0-9-]+)\/account(?:\/|$)/.exec(location.pathname)?.[1];

/** The page's own path: `/account` at a host issuer, `/realms/{slug}/account` at a path one. */
export const PAGE = SLUG === undefined ? "/account" : `/realms/${SLUG}/account`;

/** The BFF's API. */
export const API = `${PAGE}/api`;

/** The realm's Frontend API prefix. */
export const FRONTEND = SLUG === undefined ? "" : `/realms/${SLUG}`;

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

async function problemOf(r: Response): Promise<Problem> {
  try {
    const p = (await r.json()) as { code?: unknown; type?: unknown };
    if (typeof p.code === "string") return new Problem(r.status, p.code);
    if (typeof p.type === "string") return new Problem(r.status, p.type.split(":").pop() ?? "");
  } catch {
    return new Problem(r.status, "unknown");
  }
  return new Problem(r.status, "unknown");
}

/** The JSON of a 2xx answer; anything else throws its [`Problem`]. */
export async function json<T>(r: Response | Promise<Response>): Promise<T> {
  const answer = await r;
  if (!answer.ok) throw await problemOf(answer);
  if (answer.status === 204) return undefined as T;
  return (await answer.json()) as T;
}

/** What `GET …/account/api/session` answers. */
export interface SessionInfo {
  readonly realm: string;
  readonly domain: string;
  readonly account: string;
  readonly expires_at: string;
  readonly party: string | null;
  readonly instance: string | null;
  readonly instance_id: string | null;
  readonly step_up_needed: boolean;
  readonly pep: string;
  readonly api: string;
  readonly frontend: string;
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
