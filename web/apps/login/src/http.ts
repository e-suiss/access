// OP-65, OP-150 m.3 (r), OP-159 m.46 (f): the hosted pages call the environment's Frontend API on
// their own origin only; every write carries JSON and an `Idempotency-Key`, and every answer is read
// by its schema at the boundary, so nothing unchecked is shown.
import * as v from "valibot";

import { under } from "./base.js";

/** A JSON answer as its schema read it, or the RFC 9457 problem code and status of a refusal. */
export type JsonAnswer<T> =
  | { readonly ok: true; readonly status: number; readonly body: T }
  | {
      readonly ok: false;
      readonly status: number;
      readonly code: string;
      readonly body: Readonly<Record<string, unknown>>;
    };

const Problem = v.looseObject({ code: v.optional(v.unknown()), type: v.optional(v.unknown()) });

const Body = v.record(v.string(), v.unknown());

function codeOf(body: unknown): string {
  const p = v.safeParse(Problem, body);
  if (!p.success) return "unknown";
  if (typeof p.output.code === "string") return p.output.code;
  if (typeof p.output.type === "string") return p.output.type.split(":").pop() ?? "unknown";
  return "unknown";
}

async function call<S extends v.GenericSchema>(
  path: string,
  init: RequestInit,
  schema: S,
): Promise<JsonAnswer<v.InferOutput<S>>> {
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
    if (response.ok) {
      const read = v.safeParse(schema, body);
      return read.success
        ? { ok: true, status: response.status, body: read.output }
        : { ok: false, status: response.status, code: "malformed", body: {} };
    }
    const record = v.safeParse(Body, body);
    return {
      ok: false,
      status: response.status,
      code: codeOf(body),
      body: record.success ? record.output : {},
    };
  } catch {
    return { ok: false, status: 0, code: "unavailable", body: {} };
  }
}

/** An answer whose body the page does not read. */
export const Empty = v.unknown();

/** `GET` a JSON resource as `schema` reads it. */
export function getJson<S extends v.GenericSchema>(
  path: string,
  schema: S,
): Promise<JsonAnswer<v.InferOutput<S>>> {
  return call(path, { method: "GET", headers: { Accept: "application/json" } }, schema);
}

/** `POST` a JSON body; the answer as `schema` reads it. */
export function postJson<S extends v.GenericSchema>(
  path: string,
  body: unknown,
  schema: S,
): Promise<JsonAnswer<v.InferOutput<S>>> {
  return call(
    path,
    {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "Idempotency-Key": crypto.randomUUID(),
      },
      body: JSON.stringify(body ?? {}),
    },
    schema,
  );
}

/** Leaves for `target` when it is an http(s) URL. */
export function follow(target: string): void {
  const url = new URL(target, window.location.origin);
  if (url.protocol === "https:" || url.protocol === "http:") window.location.assign(url.href);
}

/** The request that sent the browser to this page, when `return_to` names this environment's own
 * `/authorize` (TN-104, X41), or its SAML or WS-Federation flow (`/saml/sso?flow=…`,
 * `/wsfed?flow=…`, OP-155 m.3 (c)), on this origin; otherwise `null`. */
export function returnTo(): string | null {
  const raw = new URL(window.location.href).searchParams.get("return_to");
  if (raw === null) return null;
  try {
    const url = new URL(raw, window.location.origin);
    const base = window.location.pathname.replace(/\/login(?:\/.*)?$/, "");
    const flow = /^\?flow=[A-Za-z0-9_-]{1,64}$/.test(url.search);
    const ok =
      url.origin === window.location.origin &&
      url.hash === "" &&
      ((url.pathname === `${base}/authorize` && url.search.length > 1) ||
        ((url.pathname === `${base}/saml/sso` || url.pathname === `${base}/wsfed`) && flow));
    return ok ? url.href : null;
  } catch {
    return null;
  }
}
