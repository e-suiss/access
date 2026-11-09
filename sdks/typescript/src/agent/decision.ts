// §8.18.1, §9.5, §9.6, P15, AGI-4: an ADP answer as the agent reads it. Free text, subcodes and
// labels stay data (A-7, SI-16); a term the actor cannot meet goes to its principal and is
// never OAuth `interaction_required` (§9.9.5 rule 1).

import { CLASSES, type ReasonClass } from "../reason.js";

/** Largest decision body read (§14.6). */
export const MAX_BODY = 64 * 1024;

export type Remediation =
  | "route-to-coordinator"
  | "refresh-claim"
  | "self-authenticate"
  | "not-satisfiable-by-actor"
  | "new-request-required"
  | { readonly waitUntil: number };

export type TermKind = "claim" | "authentication" | "contribution" | "foreign_authority";

export type Route =
  | "coordinator"
  | "principal-approval"
  | "principal-own-action"
  | "self-authenticate"
  | "issuer"
  | "wait-until"
  | "new-request";

export const ROUTE_REMEDIATION: Readonly<Record<Route, string>> = {
  coordinator: "route-to-coordinator",
  "principal-approval": "not-satisfiable-by-actor",
  "principal-own-action": "not-satisfiable-by-actor",
  "self-authenticate": "self-authenticate",
  issuer: "refresh-claim",
  "wait-until": "wait-until",
  "new-request": "new-request-required",
};

export interface Blocker {
  readonly class: ReasonClass;
  /** `undefined` when the code is unknown to this SDK. */
  readonly remediation?: Remediation;
  readonly hop?: number;
}

export interface Unmet {
  readonly kind: TermKind;
  /** A namespaced identifier, kept as data. */
  readonly class: string;
  readonly missing: number;
  readonly satisfiableByActor: boolean;
  readonly floors: Readonly<Record<string, number>>;
}

export type Decision =
  | { readonly outcome: "allow"; readonly exercise?: string }
  | { readonly outcome: "deny"; readonly blockers: readonly Blocker[] }
  | {
      readonly outcome: "require_action";
      readonly unmet: readonly Unmet[];
      readonly blockers: readonly Blocker[];
    };

export interface Answered {
  readonly decision: Decision;
  readonly advisory: boolean;
}

/** Why no decision was read: `unavailable`, `status`, `malformed` or `unknown-class`. */
export interface Unread {
  readonly unread: "unavailable" | "status" | "malformed" | "unknown-class";
  readonly status?: number;
}

/** What the transport got back; `undefined` when nothing came. */
export interface Reply {
  readonly status: number;
  readonly body: string;
}

const REMEDIATIONS = new Set([
  "route-to-coordinator",
  "refresh-claim",
  "self-authenticate",
  "not-satisfiable-by-actor",
  "new-request-required",
]);

const KINDS = new Set(["claim", "authentication", "contribution", "foreign_authority"]);

function record(v: unknown): Record<string, unknown> | undefined {
  return typeof v === "object" && v !== null && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : undefined;
}

function remediation(v: unknown): Remediation | undefined {
  if (typeof v === "string") return REMEDIATIONS.has(v) ? (v as Remediation) : undefined;
  const m = record(v);
  const keys = m === undefined ? [] : Object.keys(m);
  const t = m?.["wait_until"];
  if (keys.length === 1 && typeof t === "number" && Number.isSafeInteger(t) && t >= 0) {
    return { waitUntil: t };
  }
  return undefined;
}

class Refused extends Error {
  constructor(readonly why: Unread["unread"]) {
    super(why);
  }
}

function blocker(v: unknown): Blocker {
  const b = record(v);
  const c = b?.["class"];
  if (typeof c !== "string") throw new Refused("malformed");
  if (!(CLASSES as readonly string[]).includes(c)) throw new Refused("unknown-class");
  const hop = record(b?.["position"])?.["hop"];
  const r = remediation(b?.["remediation"]);
  return {
    class: c as ReasonClass,
    ...(r === undefined ? {} : { remediation: r }),
    ...(typeof hop === "number" ? { hop } : {}),
  };
}

function unmet(v: unknown): Unmet {
  const u = record(v);
  const term = record(u?.["term"]);
  const kind = term?.["proof_kind"];
  const cls = term?.["class"];
  const missing = u?.["missing"];
  const satisfiable = u?.["satisfiable_by_actor"];
  if (typeof kind !== "string" || !KINDS.has(kind)) throw new Refused("malformed");
  if (typeof cls !== "string") throw new Refused("malformed");
  if (typeof missing !== "number" || !Number.isSafeInteger(missing) || missing < 1) {
    throw new Refused("malformed");
  }
  if (typeof satisfiable !== "boolean") throw new Refused("malformed");
  const floors: Record<string, number> = {};
  const assurance = term?.["assurance"];
  if (assurance !== undefined) {
    const a = record(assurance);
    if (a === undefined) throw new Refused("malformed");
    for (const [dim, level] of Object.entries(a)) {
      if (typeof level !== "number" || !Number.isSafeInteger(level) || level < 0) {
        throw new Refused("malformed");
      }
      floors[dim] = level;
    }
  }
  return { kind: kind as TermKind, class: cls, missing, satisfiableByActor: satisfiable, floors };
}

/** Where an unmet term goes (§8.18.3). */
export function routeOf(u: Unmet): Route {
  if (!u.satisfiableByActor) {
    return u.kind === "contribution" ? "principal-approval" : "principal-own-action";
  }
  switch (u.kind) {
    case "contribution":
    case "foreign_authority":
      return "coordinator";
    case "authentication":
      return "self-authenticate";
    case "claim":
      return "issuer";
  }
}

function blockerRoute(b: Blocker): Route {
  const r = b.remediation;
  if (typeof r === "object") return "wait-until";
  switch (r) {
    case "refresh-claim":
      return "issuer";
    case "self-authenticate":
      return "self-authenticate";
    case "not-satisfiable-by-actor":
      return "principal-own-action";
    case "new-request-required":
      return "new-request";
    default:
      return "coordinator";
  }
}

const ROUTE_ORDER: readonly Route[] = [
  "coordinator",
  "principal-approval",
  "principal-own-action",
  "self-authenticate",
  "issuer",
  "wait-until",
  "new-request",
];

/** The routes of a `require_action`, one per term or waiting blocker, without repeats. */
export function routes(d: Decision): Route[] {
  if (d.outcome !== "require_action") return [];
  const all = new Set<Route>([...d.unmet.map(routeOf), ...d.blockers.map(blockerRoute)]);
  return ROUTE_ORDER.filter((r) => all.has(r));
}

function list<T>(context: Record<string, unknown>, name: string, each: (v: unknown) => T): T[] {
  const v = context[name];
  if (v === undefined) return [];
  if (!Array.isArray(v)) throw new Refused("malformed");
  return v.map(each);
}

/** Reads one ADP answer (L1-ADP-10, §9.5 R2). */
export function read(reply: Reply | undefined): Answered | Unread {
  if (reply === undefined) return { unread: "unavailable" };
  if (reply.status !== 200) return { unread: "status", status: reply.status };
  if (reply.body.length > MAX_BODY) return { unread: "malformed" };
  let root: Record<string, unknown> | undefined;
  try {
    root = record(JSON.parse(reply.body));
  } catch {
    return { unread: "malformed" };
  }
  const allowed = root?.["decision"];
  const context = record(root?.["context"]);
  if (typeof allowed !== "boolean" || context === undefined) return { unread: "malformed" };
  try {
    const blockers = list(context, "blockers", blocker);
    const terms = list(context, "unmet", unmet);
    const advisory = context["advisory"] === true;
    const outcome = context["outcome"];
    if (outcome === "allow" && allowed && blockers.length === 0 && terms.length === 0) {
      const e = context["exercise"];
      return {
        decision: typeof e === "string" ? { outcome, exercise: e } : { outcome },
        advisory,
      };
    }
    if (outcome === "deny" && !allowed) return { decision: { outcome, blockers }, advisory };
    if (outcome === "require_action" && !allowed && (terms.length > 0 || blockers.length > 0)) {
      return { decision: { outcome, unmet: terms, blockers }, advisory };
    }
    return { unread: "malformed" };
  } catch (e) {
    return { unread: e instanceof Refused ? e.why : "malformed" };
  }
}

export function isUnread(v: Answered | Unread): v is Unread {
  return "unread" in v;
}
