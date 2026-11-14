// TN-128, TN-131: the console speaks only to its BFF, on its own origin
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

/** A BFF call whose JSON answer is `T`; anything but 2xx throws its [`Problem`]. */
export async function json<T>(path: string, c: Call = {}): Promise<T> {
  const r = await call(path, c);
  if (!r.ok) throw await problemOf(r);
  if (r.status === 204) return undefined as T;
  return (await r.json()) as T;
}

export interface SessionInfo {
  readonly account: string;
  readonly display_name: string;
  readonly realm: string;
  readonly domain: string;
  readonly expires_at: string;
  readonly idle_timeout_s: string;
  readonly instance: string | null;
}

export interface SessionRow {
  readonly id: string;
  readonly kind: string;
  readonly created_at: string;
  readonly last_seen_at: string;
  readonly current: boolean;
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
