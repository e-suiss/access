// §9.4.1, §9.9.5, §11.15, AG-34, AGI-7, OP-154 m.3 (y): Access over A2A. A task message carries
// no authority; an Agent Card is a Claim whose signer the domain must accept; nothing here is
// OAuth `interaction_required` (AGI-4).

import type { Exercise, Plan, Step } from "./contract.js";
import { ROUTE_REMEDIATION, type Route } from "./decision.js";

export const EXTENSION = "urn:suiss:access:a2a:authority:v1";

export const CARD_TYP = "JOSE";

export type TaskState =
  | "TASK_STATE_WORKING"
  | "TASK_STATE_INPUT_REQUIRED"
  | "TASK_STATE_AUTH_REQUIRED"
  | "TASK_STATE_FAILED";

/** The task state of a step (§9.9.5 A2A row). */
export function taskState(step: Step): TaskState {
  switch (step.step) {
    case "proceed":
      return "TASK_STATE_WORKING";
    case "wait":
      return step.routes.every((r) => r === "self-authenticate" || r === "issuer")
        ? "TASK_STATE_AUTH_REQUIRED"
        : "TASK_STATE_INPUT_REQUIRED";
    default:
      return "TASK_STATE_FAILED";
  }
}

function codes(routes: readonly Route[]): string[] {
  return [...new Set(routes.map((r) => ROUTE_REMEDIATION[r]))];
}

/** The extension member of a task in `step`; `undefined` for an ALLOW or no decision. */
export function requireAction(
  ex: Exercise,
  step: Step,
): { state: TaskState; member: Record<string, unknown> } | undefined {
  const state = taskState(step);
  if (step.step === "wait") {
    let bin = "";
    for (const b of ex.nonce) bin += String.fromCharCode(b);
    const nonce = btoa(bin).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
    return {
      state,
      member: {
        [EXTENSION]: {
          kind: "require_action",
          exercise_ref: { domain: ex.domain, nonce, intent: ex.intentDigest },
          remediation: codes(step.routes),
        },
      },
    };
  }
  if (step.step === "stop") {
    return {
      state,
      member: { [EXTENSION]: { kind: "deny", classes: step.blockers.map((b) => b.class) } },
    };
  }
  return undefined;
}

/** The extension member naming the Exercise that caused a task: an audit link only. */
export function causal(exercise: string): Record<string, unknown> {
  return { [EXTENSION]: { kind: "causal", exercise } };
}

export type Inbound =
  | { readonly kind: "causal"; readonly exercise: string }
  | {
      readonly kind: "require_action";
      readonly domain: string;
      readonly nonce: string;
      readonly remediation: readonly string[];
    }
  | { readonly kind: "deny" }
  | { readonly kind: "continuation"; readonly exercise: string; readonly horizon: number };

/** Reads the extension member of a message's `metadata`; nothing else in it is read. */
export function inbound(metadata: unknown): Inbound {
  const m = (metadata as Record<string, unknown> | null)?.[EXTENSION] as
    Record<string, unknown> | undefined;
  if (m === undefined) throw new Error("absent");
  const kind = m["kind"];
  if (kind === "causal" && typeof m["exercise"] === "string") {
    return { kind, exercise: m["exercise"] };
  }
  if (kind === "require_action") {
    const r = m["exercise_ref"] as Record<string, unknown> | undefined;
    const rem = m["remediation"];
    if (
      typeof r?.["domain"] === "string" &&
      typeof r["nonce"] === "string" &&
      Array.isArray(rem) &&
      rem.every((c) => typeof c === "string")
    ) {
      return { kind, domain: r["domain"], nonce: r["nonce"], remediation: rem };
    }
  }
  if (kind === "deny") return { kind };
  if (
    kind === "continuation" &&
    typeof m["exercise"] === "string" &&
    typeof m["horizon"] === "number"
  ) {
    return { kind, exercise: m["exercise"], horizon: m["horizon"] };
  }
  throw new Error("malformed");
}

/** The receiving agent's own Exercise for a task: its own basis, the cause as `upstream_exercise`. */
export function separateExercise(plan: Plan, cause: Inbound): Plan {
  if (cause.kind !== "causal") return plan;
  const context = { ...((plan.intent["context"] ?? {}) as Record<string, unknown>) };
  context["upstream_exercise"] = cause.exercise;
  return { ...plan, intent: { ...plan.intent, context } };
}

function utf16Compare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** RFC 8785: members sorted by UTF-16 code units, no whitespace, ECMAScript escaping. */
export function jcs(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(jcs).join(",")}]`;
  const entries = Object.entries(v as Record<string, unknown>).sort(([a], [b]) =>
    utf16Compare(a, b),
  );
  return `{${entries.map(([k, x]) => `${JSON.stringify(k)}:${jcs(x)}`).join(",")}}`;
}

function b64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function b64urlDecode(text: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) throw new Error("card-malformed");
  const bin = atob(text.replaceAll("-", "+").replaceAll("_", "/"));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function unsigned(card: Record<string, unknown>): string {
  const rest = Object.fromEntries(Object.entries(card).filter(([k]) => k !== "signatures"));
  return jcs(rest);
}

/** The JWS signing input of `card` for the key `kid` (base64url thumbprint). */
export function cardSigningInput(card: Record<string, unknown>, kid: string): string {
  const header = JSON.stringify({ alg: "ES256", kid, typ: CARD_TYP });
  return `${b64url(new TextEncoder().encode(header))}.${b64url(new TextEncoder().encode(unsigned(card)))}`;
}

export interface Card {
  readonly signer: string;
  /** The card's `name`, as data. */
  readonly name: string;
  /** The card in JCS form, as data. */
  readonly card: string;
}

/**
 * Verifies `card` (AG-34, AGI-7): one entry of `signatures`, exactly `{protected, signature}`,
 * verifies as ES256 over the JCS form under a key in `accepted` (kid → key), the keys the
 * domain's Acceptance names. Anything else is not a Claim and throws.
 */
export async function verifyCard(
  card: Record<string, unknown>,
  accepted: ReadonlyMap<string, CryptoKey>,
): Promise<Card> {
  const name = card["name"];
  if (typeof name !== "string") throw new Error("card-malformed");
  const signatures = card["signatures"];
  if (!Array.isArray(signatures) || signatures.length === 0) throw new Error("card-unsigned");
  const payload = b64url(new TextEncoder().encode(unsigned(card)));
  for (const s of signatures as unknown[]) {
    const entry = s as Record<string, unknown> | null;
    if (entry === null || typeof entry !== "object" || Object.keys(entry).length !== 2) {
      throw new Error("card-malformed");
    }
    const { protected: p, signature } = entry;
    if (typeof p !== "string" || typeof signature !== "string") throw new Error("card-malformed");
    let header: Record<string, unknown>;
    try {
      header = JSON.parse(new TextDecoder().decode(b64urlDecode(p))) as Record<string, unknown>;
    } catch {
      throw new Error("card-malformed");
    }
    const keys = Object.keys(header).sort().join(",");
    const kid = header["kid"];
    if (keys !== "alg,kid,typ" || header["alg"] !== "ES256" || header["typ"] !== CARD_TYP) continue;
    if (typeof kid !== "string") continue;
    const key = accepted.get(kid);
    if (key === undefined) continue;
    const ok = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      b64urlDecode(signature),
      new TextEncoder().encode(`${p}.${payload}`),
    );
    if (ok) return { signer: kid, name, card: unsigned(card) };
  }
  throw new Error("card-signer-not-accepted");
}

function https(v: unknown): string | undefined {
  return typeof v === "string" && v.startsWith("https://") ? v : undefined;
}

/** The identity plane's `securitySchemes` entries from the realm's OpenID discovery document. */
export function securitySchemes(
  discovery: Record<string, unknown>,
): Record<string, unknown> | undefined {
  const issuer = https(discovery["issuer"]);
  const token = https(discovery["token_endpoint"]);
  if (issuer === undefined || token === undefined) return undefined;
  const g = discovery["grant_types_supported"];
  const grants = Array.isArray(g) ? g.filter((x) => typeof x === "string") : ["authorization_code"];
  const flows: Record<string, unknown> = {};
  const authorize = https(discovery["authorization_endpoint"]);
  if (authorize !== undefined && grants.includes("authorization_code")) {
    flows["authorizationCode"] = { authorizationUrl: authorize, tokenUrl: token, scopes: {} };
  }
  if (grants.includes("client_credentials"))
    flows["clientCredentials"] = { tokenUrl: token, scopes: {} };
  const device = https(discovery["device_authorization_endpoint"]);
  if (device !== undefined && grants.includes("urn:ietf:params:oauth:grant-type:device_code")) {
    flows["deviceCode"] = { deviceAuthorizationUrl: device, tokenUrl: token, scopes: {} };
  }
  const out: Record<string, unknown> = {
    access_openid: {
      type: "openIdConnect",
      openIdConnectUrl: `${issuer}/.well-known/openid-configuration`,
    },
    access_oauth2: { type: "oauth2", flows },
  };
  if (discovery["tls_client_certificate_bound_access_tokens"] === true) {
    out["access_mtls"] = { type: "mutualTLS" };
  }
  return out;
}
