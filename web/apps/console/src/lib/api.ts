// TN-128, TN-131: the console speaks only to its BFF, on its own origin
import * as v from "valibot";

export const API = "/console/api";

const CSRF_COOKIE = "__Host-access-console-csrf";

/** An RFC 9457 problem the BFF answered with. */
export class Problem extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly reason: string | undefined,
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
  readonly method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  readonly body?: unknown;
  readonly headers?: Readonly<Record<string, string>>;
}

/** A BFF call: same origin, the session cookie, and the CSRF token on every state change. */
export async function call(path: string, c: Call = {}): Promise<Response> {
  const method = c.method ?? "GET";
  const headers: Record<string, string> = { accept: "application/json", ...c.headers };
  if (method !== "GET") {
    const token = csrfToken();
    if (token !== undefined) headers["x-csrf-token"] = token;
  }
  const init: RequestInit = { method, headers, credentials: "same-origin", cache: "no-store" };
  if (c.body !== undefined) {
    headers["content-type"] = "application/json";
    init.body = JSON.stringify(c.body);
  }
  return fetch(`${API}${path}`, init);
}

const ProblemBody = v.looseObject({
  code: v.optional(v.unknown()),
  reason: v.optional(v.unknown()),
});

/** The RFC 9457 problem of a failed answer; an unreadable body is `unknown`. */
export async function problemOf(r: Response): Promise<Problem> {
  try {
    const p = v.parse(ProblemBody, await r.json());
    return new Problem(
      r.status,
      typeof p.code === "string" ? p.code : "unknown",
      typeof p.reason === "string" ? p.reason : undefined,
    );
  } catch {
    return new Problem(r.status, "unknown", undefined);
  }
}

// OP-159 m.46 (f)
/** The JSON of a 2xx `r` as `schema` reads it; anything else throws, so nothing unchecked is shown. */
export async function answer<S extends v.GenericSchema>(
  r: Response,
  schema: S,
): Promise<v.InferOutput<S>> {
  if (!r.ok) throw await problemOf(r);
  return v.parse(schema, await r.json());
}

/** A BFF call whose JSON answer `schema` reads; anything but 2xx throws its [`Problem`]. */
export async function json<S extends v.GenericSchema>(
  path: string,
  schema: S,
  c: Call = {},
): Promise<v.InferOutput<S>> {
  return answer(await call(path, c), schema);
}

/** A BFF call whose answer carries nothing the console reads; anything but 2xx throws. */
export async function send(path: string, c: Call = {}): Promise<void> {
  const r = await call(path, c);
  if (!r.ok) throw await problemOf(r);
}

export const SessionInfo = v.object({
  account: v.string(),
  display_name: v.string(),
  environment: v.string(),
  domain: v.string(),
  expires_at: v.string(),
  idle_timeout_s: v.string(),
  instance: v.nullable(v.string()),
  // OP-159 m.47 (g), TN-142
  environments: v.array(v.string()),
});

export type SessionInfo = Readonly<v.InferOutput<typeof SessionInfo>>;

export const SessionRow = v.object({
  id: v.string(),
  kind: v.string(),
  created_at: v.string(),
  last_seen_at: v.string(),
  current: v.boolean(),
});

export type SessionRow = Readonly<v.InferOutput<typeof SessionRow>>;

export function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

export function fromB64url(text: string): Uint8Array {
  const s = atob(text.replaceAll("-", "+").replaceAll("_", "/"));
  return Uint8Array.from(s, (c) => c.charCodeAt(0));
}
