import { under } from "./base.js";
import {
  flowsPath,
  parseUi,
  stepUpPath,
  type FlowKind,
  type LoginUi,
  type Submission,
} from "./contract.js";

export type Answer =
  | { readonly kind: "ui"; readonly ui: LoginUi }
  | { readonly kind: "expired" }
  | { readonly kind: "failed" };

async function answer(response: Response): Promise<Answer> {
  if (response.status === 410) return { kind: "expired" };
  const type = response.headers.get("content-type") ?? "";
  if (!type.startsWith("application/json")) return { kind: "failed" };
  const ui = parseUi(await response.json());
  return ui === null ? { kind: "failed" } : { kind: "ui", ui };
}

async function call(path: string, init: RequestInit): Promise<Answer> {
  try {
    const response = await fetch(under(path), {
      ...init,
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
    });
    return await answer(response);
  } catch {
    return { kind: "failed" };
  }
}

function headers(): HeadersInit {
  // OP-65
  return { "Content-Type": "application/json", "Idempotency-Key": crypto.randomUUID() };
}

/** A new flow; a sign-up flow names its kind (OP-153 m.3 (g)). */
export function createFlow(kind: FlowKind = "login"): Promise<Answer> {
  return call(flowsPath, {
    method: "POST",
    headers: headers(),
    ...(kind === "login" ? {} : { body: JSON.stringify({ kind }) }),
  });
}

// TN-44, RFC 9470: re-authenticates the live session in place; `acr` is advisory
export function stepUp(acr: string | null): Promise<Answer> {
  return call(stepUpPath, {
    method: "POST",
    headers: headers(),
    body: JSON.stringify(acr === null ? { max_age: 0 } : { max_age: 0, acr }),
  });
}

export function getFlow(flow: string): Promise<Answer> {
  return call(`${flowsPath}/${encodeURIComponent(flow)}`, { method: "GET" });
}

export function submit(ui: LoginUi, submission: Submission): Promise<Answer> {
  return call(ui.action, {
    method: "POST",
    headers: headers(),
    body: JSON.stringify(submission),
  });
}
