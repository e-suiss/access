// §8.18.2, A-1 to A-4, A-8 to A-10, OP-154 m.3 (w): one intent under one nonce, as the agent
// contract has it. The Instance key and the decision point are ports; the SDK holds neither.

import {
  type Blocker,
  type Decision,
  type Reply,
  type Route,
  type Unmet,
  type Unread,
  isUnread,
  read,
  routes,
} from "./decision.js";

/** The ADP JSON form of a basis (`{anchor}`, `{public}` or `{holding}`). */
export type Basis = Readonly<Record<string, unknown>>;

/** `"own"`, or `{ for: <principal id> }` for the principal's work (A-1). */
export type Capacity = "own" | { readonly for: string };

/**
 * What an agent plans: the intent in its ADP JSON form and its digest (base64url), with the
 * basis and capacity, which are optional only so that a plan read from configuration or a
 * model's output is refused here when one is missing (A-1).
 */
export interface Plan {
  readonly intent: Readonly<Record<string, unknown>>;
  readonly intentDigest: string;
  readonly basis?: Basis;
  readonly capacity?: Capacity;
}

export type AgentErrorCode =
  | "capacity"
  | "basis"
  | "nonce"
  | "nonce-closed"
  | "no-state-change"
  | "envelope-changed"
  | "not-waiting"
  | "structuring"
  | "stopped"
  | "signature";

export class AgentError extends Error {
  constructor(readonly code: AgentErrorCode) {
    super(code);
  }
}

/** What the Instance signs: the mode, the nonce and the Exercise continued. */
export interface ToSign {
  readonly domain: string;
  readonly pep: string;
  readonly mode: "commit" | "continue" | "check";
  readonly nonce: Uint8Array;
  readonly intentDigest: string;
  readonly basis: Basis;
  readonly capacity: Capacity;
  readonly exercise?: string;
}

/** The Instance key: the AIS `COSE_Sign1` bytes, `undefined` when it cannot sign. */
export type Signs = (s: ToSign) => Promise<Uint8Array | undefined>;

/** The decision point: one ADP evaluation body in, the reply out, `undefined` on a fault. */
export type Adp = (body: string) => Promise<Reply | undefined>;

/**
 * A proof for a waiting request (A-4, A-5): a recorded contribution's Exercise or a Claim.
 * There is no proof made of text, a chat answer or an elicitation result (EI-18, AGI-8).
 */
export type Proof =
  { readonly contribution: string } | { readonly claim: string } | { readonly claimRef: string };

/** A change of state that makes a new nonce meaningful after a DENY (A-3). */
export type Change =
  { readonly newGrant: Basis } | { readonly freshClaim: string } | { readonly budgetReset: true };

export interface Allowed {
  readonly exercise: string;
  readonly intentDigest: string;
}

export type Step =
  | { readonly step: "proceed"; readonly allowed: Allowed }
  | {
      readonly step: "wait";
      readonly routes: readonly Route[];
      readonly unmet: readonly Unmet[];
      readonly blockers: readonly Blocker[];
    }
  | { readonly step: "stop"; readonly blockers: readonly Blocker[] }
  | { readonly step: "unknown"; readonly unread: Unread };

export interface Advisory {
  readonly allowed: boolean;
  readonly routes: readonly Route[];
  readonly classes: readonly string[];
}

/** A-2: the effect's envelope must be the one allowed; any changed parameter is another intent. */
export function effect(allowed: Allowed, intentDigest: string): string {
  if (allowed.intentDigest !== intentDigest) throw new AgentError("envelope-changed");
  return allowed.exercise;
}

/** When a `budget-exhausted` window resets, if the DENY named one. */
export function resetsAt(blockers: readonly Blocker[]): number | undefined {
  const times = blockers
    .filter((b) => b.class === "budget-exhausted" && typeof b.remediation === "object")
    .map((b) => (b.remediation as { waitUntil: number }).waitUntil);
  return times.length === 0 ? undefined : Math.max(...times);
}

function b64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function b64urlDecode(text: string): Uint8Array | undefined {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) return undefined;
  try {
    const bin = atob(text.replaceAll("-", "+").replaceAll("_", "/"));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
  } catch {
    return undefined;
  }
}

/**
 * The Exercise a nonce names (OP-141 m.6): SHA-256 over `access/exercise/v1`, a zero byte and
 * the canonical CBOR of `[domain, nonce]`, base64url.
 */
export async function exerciseId(domain: string, nonce: Uint8Array): Promise<string | undefined> {
  const d = b64urlDecode(domain);
  if (d?.length !== 32 || nonce.length < 16 || nonce.length > 64) return undefined;
  const label = new TextEncoder().encode("access/exercise/v1");
  const head = nonce.length < 24 ? [0x40 + nonce.length] : [0x58, nonce.length];
  const input = new Uint8Array([
    ...label,
    0x00,
    0x82,
    0x82,
    0x2f,
    0x58,
    0x20,
    ...d,
    ...head,
    ...nonce,
  ]);
  return b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", input)));
}

function checkedNonce(nonce: Uint8Array): Uint8Array {
  if (nonce.length < 16 || nonce.length > 64) throw new AgentError("nonce");
  return nonce;
}

function proofJson(p: Proof): Record<string, string> {
  if ("contribution" in p) return { contribution: p.contribution };
  if ("claim" in p) return { claim: p.claim };
  return { claim_ref: p.claimRef };
}

type State = "open" | "waiting" | "allowed" | "closed";

/** One intent under one nonce. */
export class Exercise {
  readonly basis: Basis;
  readonly capacity: Capacity;
  readonly nonce: Uint8Array;
  private proofs: Proof[] = [];
  private state: State = "open";
  private closedBy: readonly Blocker[] = [];

  constructor(
    readonly domain: string,
    readonly pep: string,
    readonly plan: Plan,
    nonce: Uint8Array,
  ) {
    if (plan.capacity === undefined) throw new AgentError("capacity");
    if (plan.basis === undefined) throw new AgentError("basis");
    this.basis = plan.basis;
    this.capacity = plan.capacity;
    this.nonce = checkedNonce(nonce);
  }

  get intentDigest(): string {
    return this.plan.intentDigest;
  }

  private async body(
    mode: ToSign["mode"],
    nonce: Uint8Array,
    sign: Signs,
    exercise?: string,
  ): Promise<string> {
    const ais = await sign({
      domain: this.domain,
      pep: this.pep,
      mode,
      nonce,
      intentDigest: this.plan.intentDigest,
      basis: this.basis,
      capacity: this.capacity,
      ...(exercise === undefined ? {} : { exercise }),
    });
    if (ais === undefined) throw new AgentError("signature");
    const intent = this.plan.intent;
    const action = intent["action"] as { name?: unknown } | undefined;
    const first = (
      intent["resources"] as { namespace?: unknown; path?: unknown[] }[] | undefined
    )?.[0];
    const context: Record<string, unknown> = {
      domain: this.domain,
      mode,
      nonce: b64url(nonce),
      ais: b64url(ais),
      basis: this.basis,
      capacity: this.capacity,
      intent,
    };
    if (exercise !== undefined) context["exercise"] = exercise;
    if (this.proofs.length > 0 && mode !== "continue")
      context["proofs"] = this.proofs.map(proofJson);
    return JSON.stringify({
      subject: { type: "access_actor", id: "-" },
      action: { name: action?.name },
      resource: { type: first?.namespace, id: (first?.path ?? []).join("/") },
      context,
    });
  }

  /** Asks Access to `commit` this intent under its nonce (A-3: never after a DENY). */
  async ask(adp: Adp, sign: Signs): Promise<Step> {
    if (this.state === "closed") throw new AgentError("nonce-closed");
    const answered = read(await adp(await this.body("commit", this.nonce, sign)));
    if (isUnread(answered)) return { step: "unknown", unread: answered };
    if (answered.advisory) return { step: "unknown", unread: { unread: "malformed" } };
    const d: Decision = answered.decision;
    switch (d.outcome) {
      case "allow": {
        const own = await exerciseId(this.domain, this.nonce);
        if (own === undefined || (d.exercise !== undefined && d.exercise !== own)) {
          return { step: "unknown", unread: { unread: "malformed" } };
        }
        this.state = "allowed";
        return {
          step: "proceed",
          allowed: { exercise: own, intentDigest: this.plan.intentDigest },
        };
      }
      case "deny":
        this.state = "closed";
        this.closedBy = d.blockers;
        return { step: "stop", blockers: d.blockers };
      case "require_action":
        this.state = "waiting";
        return { step: "wait", routes: routes(d), unmet: d.unmet, blockers: d.blockers };
    }
  }

  /** Adds a proof to a waiting request; the next `ask` uses the same nonce (A-4). */
  prove(proof: Proof): void {
    if (this.state !== "waiting") throw new AgentError("not-waiting");
    const key = JSON.stringify(proofJson(proof));
    if (!this.proofs.some((p) => JSON.stringify(proofJson(p)) === key)) this.proofs.push(proof);
  }

  /** A new request for the same plan under a new nonce, after a DENY and a change of state (A-3). */
  renew(change: Change, nonce: Uint8Array, now: number): Exercise {
    if (this.state !== "closed") throw new AgentError("no-state-change");
    checkedNonce(nonce);
    if (b64url(nonce) === b64url(this.nonce)) throw new AgentError("nonce");
    let basis = this.basis;
    const proofs: Proof[] = [];
    if ("newGrant" in change) {
      if (JSON.stringify(change.newGrant) === JSON.stringify(this.basis)) {
        throw new AgentError("no-state-change");
      }
      basis = change.newGrant;
    } else if ("freshClaim" in change) {
      proofs.push({ claim: change.freshClaim });
    } else {
      const at = resetsAt(this.closedBy);
      if (at === undefined || now < at) throw new AgentError("no-state-change");
    }
    const next = new Exercise(this.domain, this.pep, { ...this.plan, basis }, nonce);
    next.proofs = proofs;
    return next;
  }

  /** Asks `check` under `nonce` (A-10): advisory, never recorded, never an ALLOW. */
  async check(nonce: Uint8Array, adp: Adp, sign: Signs): Promise<Advisory | Unread> {
    const answered = read(await adp(await this.body("check", checkedNonce(nonce), sign)));
    if (isUnread(answered)) return answered;
    if (!answered.advisory) return { unread: "malformed" };
    const d = answered.decision;
    return {
      allowed: d.outcome === "allow",
      routes: routes(d),
      classes: d.outcome === "deny" ? d.blockers.map((b) => b.class) : [],
    };
  }

  /** The `continue` body for `exercise` under `nonce` (A-8). */
  continueBody(exercise: string, nonce: Uint8Array, sign: Signs): Promise<string> {
    return this.body("continue", checkedNonce(nonce), sign, exercise);
  }
}

/**
 * A long-running effect's continuation (A-8, E31, AG-15): asked at the half-way point, at each
 * checkpoint and after a pause or takeover; a DENY or no answer stops it for good.
 */
export class Continuation {
  private last: number;
  private interruptedFlag = false;
  private stopped = false;
  private readonly checkpoints: number[];

  constructor(
    readonly exercise: string,
    private readonly started: number,
    readonly horizon: number,
    checkpoints: readonly number[],
  ) {
    this.last = started;
    this.checkpoints = checkpoints.filter((c) => c > started && c < horizon).sort((a, b) => a - b);
  }

  interrupted(): void {
    this.interruptedFlag = true;
  }

  due(now: number): boolean {
    const half = this.started + Math.floor((this.horizon - this.started) / 2);
    return (
      this.interruptedFlag ||
      (this.last < half && now >= half) ||
      this.checkpoints.some((c) => c > this.last && c <= now) ||
      now >= this.horizon
    );
  }

  mayStart(now: number): boolean {
    return !this.stopped && now < this.horizon && !this.due(now);
  }

  async ask(ex: Exercise, nonce: Uint8Array, now: number, adp: Adp, sign: Signs): Promise<boolean> {
    if (this.stopped) throw new AgentError("stopped");
    const answered = read(await adp(await ex.continueBody(this.exercise, nonce, sign)));
    const go =
      !isUnread(answered) &&
      !answered.advisory &&
      answered.decision.outcome === "allow" &&
      now < this.horizon;
    if (go) {
      this.last = now;
      this.interruptedFlag = false;
    } else {
      this.stopped = true;
    }
    return go;
  }
}

interface Refused {
  readonly action: string;
  readonly resources: string;
  readonly amounts: readonly (readonly [string, string, number])[];
}

function amounts(intent: Readonly<Record<string, unknown>>): [string, string, number][] {
  const params = (intent["params"] ?? {}) as Record<string, Record<string, unknown>>;
  const out: [string, string, number][] = [];
  for (const [k, v] of Object.entries(params)) {
    const a = v["amount"] as { value?: unknown; unit?: unknown } | undefined;
    if (a !== undefined && typeof a.value === "number" && typeof a.unit === "string") {
      out.push([k, a.unit, a.value]);
    } else if (typeof v["count"] === "number") {
      out.push([k, "count", v["count"]]);
    }
  }
  return out;
}

/** A-9, C27: a refused intent is not split under its amount. */
export class Refusals {
  private refused: Refused[] = [];

  record(ex: Exercise, step: Step): void {
    if (step.step !== "stop" && step.step !== "wait") return;
    this.refused.push({
      action: JSON.stringify(ex.plan.intent["action"]),
      resources: JSON.stringify(ex.plan.intent["resources"]),
      amounts: amounts(ex.plan.intent),
    });
  }

  admit(plan: Plan): void {
    const action = JSON.stringify(plan.intent["action"]);
    const resources = JSON.stringify(plan.intent["resources"]);
    const asked = amounts(plan.intent);
    const split = this.refused.some(
      (r) =>
        r.action === action &&
        r.resources === resources &&
        asked.some(([k, u, v]) => r.amounts.some(([rk, ru, rv]) => rk === k && ru === u && v < rv)),
    );
    if (split) throw new AgentError("structuring");
  }
}
