// §9.5, §9.5.2 k.6, L2-RCP-3, X21, TI-9, MD-8: the PEP's side of an Access decision. Anything
// other than a verified ALLOW for this intent, this audience and this nonce is a denial; there is
// no fail-open option.

import type { Kernel } from "./index.js";
import { type Reason, reasons } from "./reason.js";

/** Largest decision body read (§14.6). */
export const MAX_DECISION_BYTES = 64 * 1024;

/** Default deadline for one decision. */
export const DEFAULT_TIMEOUT_MS = 2000;

export interface DecisionAsk {
  /** The decision point's evaluation URL. */
  readonly url: string;
  /** The AuthZEN evaluation body with the Access members in `context` (L1-ADP-5…8). */
  readonly body: unknown;
  /** Canonical CBOR of the domain's verified `domain-metadata` (`verifyMetadata`). */
  readonly metadata: Uint8Array;
  /** Canonical CBOR of the domain digest. */
  readonly domain: Uint8Array;
  /** This PEP's identity: the receipt's audience. */
  readonly audience: string;
  /** Canonical CBOR of the intent digest. */
  readonly intent: Uint8Array;
  /** The request nonce the statement carries. */
  readonly nonce: Uint8Array;
  /** The Exercise continued, for `continue` mode. */
  readonly continued?: Uint8Array;
  /** Trusted time, Unix milliseconds; without it nothing is authorized. */
  readonly now: bigint | undefined;
  /** The position the protected content was written at (§13.4 U60). */
  readonly contentPosition?: bigint;
  readonly timeoutMs?: number;
}

/** A verified ALLOW: the receipt payload and the position it reflects. */
export interface Authorized {
  readonly allowed: true;
  readonly receipt: Uint8Array;
  readonly position: bigint;
}

/** Why no effect happens: `decision` (Access refused), `unverified` or `unknown`. */
export interface Denied {
  readonly allowed: false;
  readonly class: "decision" | "unverified" | "unknown";
  readonly code: string;
  readonly reasons: readonly Reason[];
}

function denied(cls: Denied["class"], code: string, why: readonly Reason[] = []): Denied {
  return { allowed: false, class: cls, code, reasons: why };
}

function b64urlDecode(text: string): Uint8Array | undefined {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) return undefined;
  const pad = "=".repeat((4 - (text.length % 4)) % 4);
  try {
    const bin = atob(text.replaceAll("-", "+").replaceAll("_", "/") + pad);
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
  } catch {
    return undefined;
  }
}

function message(e: unknown): string {
  return e instanceof Error ? e.message : "error";
}

/**
 * Asks the decision point and verifies the answer: 200 with a decision; `decision: true`; a
 * receipt that the Kernel verifies for this domain, audience, intent and time; that names the
 * Exercise of this nonce; and that is not older than the protected content.
 */
export async function authorize(
  kernel: Kernel,
  fetchFn: typeof fetch,
  ask: DecisionAsk,
): Promise<Authorized | Denied> {
  if (ask.now === undefined) return denied("unknown", "clock");
  let response: Response;
  try {
    response = await fetchFn(ask.url, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(ask.body),
      signal: AbortSignal.timeout(ask.timeoutMs ?? DEFAULT_TIMEOUT_MS),
    });
  } catch {
    return denied("unknown", "unavailable");
  }
  if (response.status !== 200) return denied("unknown", "status");
  let body: unknown;
  try {
    const text = await response.text();
    if (text.length > MAX_DECISION_BYTES) return denied("unknown", "malformed");
    body = JSON.parse(text);
  } catch {
    return denied("unknown", "malformed");
  }
  const root = typeof body === "object" && body !== null ? (body as Record<string, unknown>) : {};
  const decision = root["decision"];
  if (typeof decision !== "boolean") return denied("unknown", "malformed");
  const context =
    typeof root["context"] === "object" && root["context"] !== null
      ? (root["context"] as Record<string, unknown>)
      : {};
  if (!decision) {
    try {
      return denied("decision", "refused", reasons(body));
    } catch (e) {
      return denied("unknown", message(e));
    }
  }
  const receipt =
    typeof context["receipt"] === "object" && context["receipt"] !== null
      ? (context["receipt"] as Record<string, unknown>)
      : {};
  const sign1 = typeof receipt["sign1"] === "string" ? b64urlDecode(receipt["sign1"]) : undefined;
  const excerpt =
    typeof receipt["excerpt"] === "string" ? b64urlDecode(receipt["excerpt"]) : undefined;
  if (sign1 === undefined || excerpt === undefined) return denied("unverified", "receipt-missing");
  let payload: Uint8Array;
  let position: bigint;
  try {
    payload = kernel.verifyReceipt(
      ask.metadata,
      sign1,
      excerpt,
      ask.domain,
      ask.audience,
      ask.intent,
      ask.now,
    );
    position = kernel.receiptPosition(
      payload,
      ask.domain,
      ask.nonce,
      ask.continued ?? new Uint8Array(),
    );
  } catch (e) {
    return denied("unverified", message(e));
  }
  if (ask.contentPosition !== undefined && position < ask.contentPosition) {
    return denied("unverified", "content-position");
  }
  return { allowed: true, receipt: payload, position };
}

/**
 * Whether a Token Status List entry is valid (L2-STL-3): `false` when the entry is set and also
 * when the list cannot be inflated or read, never `true` on doubt.
 */
export async function statusValid(
  kernel: Kernel,
  token: Uint8Array,
  lst: Uint8Array,
  reference: Uint8Array,
  inflate: (lst: Uint8Array) => Promise<Uint8Array>,
): Promise<boolean> {
  try {
    return !kernel.statusLookup(token, await inflate(lst), reference);
  } catch {
    return false;
  }
}
