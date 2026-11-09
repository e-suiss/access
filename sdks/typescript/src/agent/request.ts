// §8.17.5.2, §8.18.4, A-6, A-11, A-12, OP-149 m.9: what the agent hands its coordinator, its own
// status read, and how it names itself. The agent never writes the canonical summary a person
// sees; its own words are only the "Requester's note".

import type { Exercise, Signs, Step } from "./contract.js";
import type { Route } from "./decision.js";

export interface Requester {
  readonly party: string;
  readonly instance?: string;
}

export interface WorkRefs {
  readonly work?: string;
  readonly commitment?: string;
  readonly gate?: string;
}

export interface Handoff {
  /** The `authority-request` JSON (conformance/cddl/authority-request.schema.json). */
  readonly request: Record<string, unknown>;
  readonly routes: readonly Route[];
  /** `true` after a `require_action`: the agent asks again under the same nonce. */
  readonly sameNonce: boolean;
}

function b64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

/** The `authority-request` for `ex`; a note of 1 to 1024 characters is required (A-6). */
export function authorityRequest(
  ex: Exercise,
  requester: Requester,
  note: string,
  refs: WorkRefs,
  requireAction: boolean,
): Record<string, unknown> {
  const n = Array.from(note).length;
  if (n < 1 || n > 1024) throw new Error("note");
  const intent = ex.plan.intent;
  const resources = intent["resources"] as readonly Record<string, unknown>[] | undefined;
  const first = resources?.[0];
  if (first === undefined) throw new Error("intent");
  const validity = intent["validity"] as { until?: unknown } | undefined;
  const out: Record<string, unknown> = {
    requester:
      requester.instance === undefined
        ? { party: requester.party }
        : { party: requester.party, instance: requester.instance },
    action: intent["action"],
    resource: { incarnation: 0, ...first },
    params: intent["params"] ?? {},
    capacity: ex.capacity,
    reason: note,
    expires_at: validity?.until,
  };
  if (refs.work !== undefined) out["work_ref"] = refs.work;
  if (refs.commitment !== undefined) out["commitment_ref"] = refs.commitment;
  if (refs.gate !== undefined) out["gate_ref"] = refs.gate;
  if (requireAction) {
    out["require_action"] = { domain: ex.domain, nonce: b64url(ex.nonce), intent: ex.intentDigest };
  }
  return out;
}

/** The handoff after `step`, or `undefined` when none is needed. */
export function handoff(
  ex: Exercise,
  step: Step,
  requester: Requester,
  note: string,
  refs: WorkRefs,
): Handoff | undefined {
  if (step.step === "wait") {
    return {
      request: authorityRequest(ex, requester, note, refs, true),
      routes: step.routes,
      sameNonce: true,
    };
  }
  if (step.step === "stop") {
    return {
      request: authorityRequest(ex, requester, note, refs, false),
      routes: ["coordinator"],
      sameNonce: false,
    };
  }
  return undefined;
}

/** A-12: the agent badge a user-facing surface shows; `party_kind` is always `agent`. */
export function disclosure(
  instance: string,
  agent: string,
  operator: string,
  capacity: "own" | { readonly for: string },
): Record<string, string> {
  const out: Record<string, string> = { party_kind: "agent", agent, instance, operator };
  if (capacity !== "own") out["principal"] = capacity.for;
  return out;
}

/** The `Signature-Agent` header value naming the key directory (Web Bot Auth): `https` only. */
export function signatureAgent(directory: string): string | undefined {
  return /^https:\/\/[\x21-\x7e]+$/.test(directory) && !/["\\]/.test(directory)
    ? `"${directory}"`
    : undefined;
}

export const STATUS_PATH = "/access/v1/search/agent-status";

/**
 * A-11: the signed `agent-status` search body. The search intent (`access:read` on
 * `access.search/agent-status`), its digest and the domain's meta-anchor basis are the
 * caller's, from the Kernel.
 */
export async function statusBody(
  domain: string,
  pep: string,
  nonce: Uint8Array,
  search: { intent: Record<string, unknown>; intentDigest: string; basis: Record<string, unknown> },
  sign: Signs,
): Promise<string> {
  const { intent, intentDigest, basis } = search;
  const capacity = "own" as const;
  const ais = await sign({ domain, pep, mode: "check", nonce, intentDigest, basis, capacity });
  if (ais === undefined) throw new Error("signature");
  return JSON.stringify({
    context: {
      domain,
      mode: "check",
      nonce: b64url(nonce),
      ais: b64url(ais),
      basis,
      capacity,
      intent,
      query: {},
    },
  });
}

export interface Status {
  readonly instance: string;
  readonly party: string;
  readonly live: boolean;
  readonly holdings: readonly {
    readonly grant: string;
    readonly actions: readonly string[];
    readonly until?: number;
    readonly budgets: readonly { dimension: string; capacity: number; remaining: number }[];
  }[];
}

/** A-11, E26: exactly one advisory `agent_status` result; anything else throws. */
export function readStatus(reply: { status: number; body: string } | undefined): Status {
  if (reply?.status !== 200) throw new Error("status");
  const root = JSON.parse(reply.body) as Record<string, unknown>;
  const context = root["context"] as Record<string, unknown> | undefined;
  const results = root["results"];
  if (context?.["advisory"] !== true || !Array.isArray(results) || results.length !== 1) {
    throw new Error("malformed");
  }
  const r = results[0] as Record<string, unknown>;
  if (r["type"] !== "agent_status") throw new Error("malformed");
  return r as unknown as Status;
}
