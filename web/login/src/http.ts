// OP-65, OP-150 m.3 (r): the hosted pages call the realm's Frontend API on their own origin only;
// every write carries JSON and an `Idempotency-Key`.
import { under } from "./base.js";

/** A JSON answer, or the RFC 9457 problem code and status of a refusal. */
export type JsonAnswer<T> =
  | { readonly ok: true; readonly status: number; readonly body: T }
  | {
      readonly ok: false;
      readonly status: number;
      readonly code: string;
      readonly body: Record<string, unknown>;
    };

function codeOf(body: Record<string, unknown>): string {
  if (typeof body["code"] === "string") return body["code"];
  const type = body["type"];
  if (typeof type === "string") return type.split(":").pop() ?? "unknown";
  return "unknown";
}

async function call<T>(path: string, init: RequestInit): Promise<JsonAnswer<T>> {
  try {
    const response = await fetch(under(path), {
      ...init,
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
    });
    const type = response.headers.get("content-type") ?? "";
    const body: unknown =
      response.status !== 204 && type.includes("json") ? await response.json() : {};
    const record =
      typeof body === "object" && body !== null && !Array.isArray(body)
        ? (body as Record<string, unknown>)
        : {};
    if (response.ok) return { ok: true, status: response.status, body: body as T };
    return { ok: false, status: response.status, code: codeOf(record), body: record };
  } catch {
    return { ok: false, status: 0, code: "unavailable", body: {} };
  }
}

/** `GET` a JSON resource. */
export function getJson<T>(path: string): Promise<JsonAnswer<T>> {
  return call<T>(path, { method: "GET", headers: { Accept: "application/json" } });
}

/** `POST` a JSON body. */
export function postJson<T>(path: string, body: unknown): Promise<JsonAnswer<T>> {
  return call<T>(path, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "Idempotency-Key": crypto.randomUUID(),
    },
    body: JSON.stringify(body ?? {}),
  });
}

/** Leaves for `target` when it is an http(s) URL. */
export function follow(target: string): void {
  const url = new URL(target, window.location.origin);
  if (url.protocol === "https:" || url.protocol === "http:") window.location.assign(url.href);
}

/** The authorization request that sent the browser to this page, when `return_to` names this
 * realm's own `/authorize` on this origin (TN-104, X41); otherwise `null`. */
export function returnTo(): string | null {
  const raw = new URL(window.location.href).searchParams.get("return_to");
  if (raw === null) return null;
  try {
    const url = new URL(raw, window.location.origin);
    const base = window.location.pathname.replace(/\/login(?:\/.*)?$/, "");
    const ok =
      url.origin === window.location.origin &&
      url.pathname === `${base}/authorize` &&
      url.search.length > 1 &&
      url.hash === "";
    return ok ? url.href : null;
  } catch {
    return null;
  }
}
