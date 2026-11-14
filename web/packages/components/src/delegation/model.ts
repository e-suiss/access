// §8.17.5.1–§8.17.5.9, §8.17.7.5–§8.17.7.7, §8.8, §8.11, X8–X10, X15, X16, XI-4, XI-7, XI-10, XI-19
/** The S1 Delegation sheet's model: drafts in, an exact typed preview out. It decides nothing
 * and signs nothing; a commit is the host's `grant.issue`/`grant.amend` Exercise of exactly the
 * previewed draft. Every input (template, natural language, precise editor) only drafts. */

/** Where a draft came from (§8.17.5.1, X9). */
export type DraftSource = "template" | "natural_language" | "editor";

/** In what capacity the recipient acts (§8.8, R1, XI-10): shown apart from provenance. */
export type Capacity = "on_your_behalf" | "on_behalf_of_org" | "own_use" | "as_yourself";

/** What the recipient is. */
export type RecipientKind = "human" | "agent";

/** How long it lasts (OP-153 m.3 (x)): there is no "forever". */
export type Validity =
  | { readonly kind: "until"; readonly atMs: number }
  | { readonly kind: "until_revoked"; readonly explicit: true };

/** One limit; an amount in minor units of `unit`. */
export interface Limit {
  readonly action: string;
  readonly amount: number;
  readonly unit: string;
  /** A limit of money the financial system also enforces (X15): shown on its own line. */
  readonly financial: boolean;
}

/** A natural-language phrase and the typed content it was read as (X9). */
export interface Interpretation {
  readonly phrase: string;
  readonly typed: string;
}

export interface Draft {
  readonly source: DraftSource;
  readonly to: { readonly name: string; readonly kind: RecipientKind };
  readonly canDo: readonly string[];
  /** The organization the viewer acts for, when not for themselves. */
  readonly actingAs: string | null;
  /** Required; a draft without one cannot be committed (X10). */
  readonly capacity: Capacity | null;
  readonly canPassOn: boolean;
  readonly limits: readonly Limit[];
  readonly requires: readonly string[];
  readonly valid: Validity | null;
  readonly interpretations: readonly Interpretation[];
}

/** What the viewer may give (their effective authority, viewer-scoped). */
export interface Viewer {
  /** Actions the viewer holds. */
  readonly holds: readonly string[];
  /** The viewer's own effective ceiling per action and unit. */
  readonly ceilings: readonly Limit[];
  /** Organizations the viewer holds authority for; `self` when they hold it as themselves. */
  readonly agency: { readonly self: boolean; readonly orgs: readonly string[] };
}

/** Day and its multiples in milliseconds. */
export const DAY_MS = 86_400_000;

/** OP-153 m.3 (x): an agent delegation ends; 30 days unless changed, never past 365. */
export const AGENT_DEFAULT_DAYS = 30;
export const AGENT_MAX_DAYS = 365;

/** OP-153 m.3 (x): "Give access once" lasts one hour unless changed, never past a day. */
export const ONCE_DEFAULT_MS = 3_600_000;
export const ONCE_MAX_MS = DAY_MS;

/** A fresh draft for `to` with the defaults of OP-153 m.3 (x) (X10): passing on is off, the
 * capacity is left for the viewer to choose, and an agent's delegation ends. */
export function newDraft(
  source: DraftSource,
  to: Draft["to"],
  canDo: readonly string[],
  nowMs: number,
): Draft {
  return {
    source,
    to,
    canDo,
    actingAs: null,
    capacity: null,
    canPassOn: false,
    limits: [],
    requires: [],
    valid:
      to.kind === "agent" ? { kind: "until", atMs: nowMs + AGENT_DEFAULT_DAYS * DAY_MS } : null,
    interpretations: [],
  };
}

/** The capacities the viewer may choose (§8.17.5.1, X10): derived from their agency, so a
 * viewer who holds only for Acme is never offered "on your behalf". */
export function capacityOptions(v: Viewer): Capacity[] {
  const out: Capacity[] = [];
  if (v.agency.self) {
    out.push("on_your_behalf", "own_use", "as_yourself");
  }
  if (v.agency.orgs.length > 0) {
    out.push("on_behalf_of_org");
  }
  return out;
}

/** A field outside the viewer's effective authority (§8.17.5.1). */
export interface OutOfAuthority {
  readonly field: "can_do" | "limit" | "capacity";
  readonly action: string;
  /** The viewer's ceiling and what the draft asks, for a limit. */
  readonly ceiling?: Limit;
  readonly asked?: Limit;
}

/** Every drafted field the viewer could not give: the preview marks them and the sheet cannot
 * commit until they are fixed. */
export function outOfAuthority(d: Draft, v: Viewer): OutOfAuthority[] {
  const out: OutOfAuthority[] = [];
  for (const a of d.canDo) {
    if (!v.holds.includes(a)) {
      out.push({ field: "can_do", action: a });
    }
  }
  for (const l of d.limits) {
    const c = v.ceilings.find((x) => x.action === l.action && x.unit === l.unit);
    if (c === undefined || l.amount > c.amount) {
      out.push(
        c === undefined
          ? { field: "limit", action: l.action, asked: l }
          : { field: "limit", action: l.action, ceiling: c, asked: l },
      );
    }
  }
  if (d.capacity !== null && !capacityOptions(v).includes(d.capacity)) {
    out.push({ field: "capacity", action: d.capacity });
  }
  return out;
}

/** The mandatory blocks of the exact preview, in their order (§8.17.5.1). */
export const BLOCKS = [
  "to",
  "can_do",
  "acting_as",
  "can_pass_on",
  "limits",
  "requires",
  "valid",
  "not_included",
  "interpretation",
] as const;

export type Block = (typeof BLOCKS)[number];

export interface Preview {
  readonly blocks: readonly { readonly block: Block; readonly lines: readonly string[] }[];
  readonly outOfAuthority: readonly OutOfAuthority[];
  /** Why it cannot be committed yet; empty when it can. */
  readonly blockers: readonly string[];
}

function amount(l: Limit): string {
  return `${(l.amount / 100).toLocaleString("en-US", { maximumFractionDigits: 2 })} ${l.unit}`;
}

/** What is never included (§8.17.5.1, X10): protected and future actions, and everything the
 * viewer does not hold, always said. */
export function notIncluded(d: Draft, v: Viewer): string[] {
  const out = ["Protected actions", "Actions added later"];
  const extra = v.holds.filter((a) => !d.canDo.includes(a));
  if (extra.length > 0) {
    out.push(`Everything else you hold: ${extra.join(", ")}`);
  }
  out.push("Anything you don't hold yourself");
  return out;
}

/** The exact typed preview of `d` for `v` at `nowMs`. The record gets the typed content, never
 * a sentence (X9). */
export function preview(d: Draft, v: Viewer, nowMs: number): Preview {
  const out = outOfAuthority(d, v);
  const lines = (block: Block): string[] => {
    switch (block) {
      case "to":
        return [`${d.to.name} (${d.to.kind === "agent" ? "agent" : "person"})`];
      case "can_do":
        return d.canDo.length > 0 ? [...d.canDo] : ["Nothing selected"];
      case "acting_as":
        return [d.actingAs ?? "Yourself", capacityLabel(d.capacity)];
      case "can_pass_on":
        return [d.canPassOn ? "Yes, to others they choose" : "No"];
      case "limits":
        return d.limits.length > 0
          ? d.limits.map((l) => `${l.action}: up to ${amount(l)}${l.financial ? " · Pay" : ""}`)
          : ["No limits beyond yours"];
      case "requires":
        return d.requires.length > 0 ? [...d.requires] : ["Nothing more"];
      case "valid":
        return [validText(d.valid, nowMs)];
      case "not_included":
        return notIncluded(d, v);
      case "interpretation":
        return d.interpretations.map((i) => `"${i.phrase}" → ${i.typed}`);
    }
  };
  const blockers: string[] = [];
  if (d.capacity === null) {
    blockers.push("Choose in what capacity they act");
  }
  if (d.valid === null) {
    blockers.push("Choose how long it lasts");
  }
  if (d.to.kind === "agent") {
    if (d.valid?.kind !== "until") {
      blockers.push("A delegation to an agent ends; choose an end date");
    } else if (d.valid.atMs - nowMs > AGENT_MAX_DAYS * DAY_MS) {
      blockers.push(`A delegation to an agent ends within ${String(AGENT_MAX_DAYS)} days`);
    }
  }
  for (const o of out) {
    blockers.push(outOfAuthorityText(o));
  }
  return {
    blocks: BLOCKS.map((block) => ({ block, lines: lines(block) })),
    outOfAuthority: out,
    blockers,
  };
}

/** "You can approve up to 2,000 TRY; you can't give 5,000" (§8.17.5.1). */
export function outOfAuthorityText(o: OutOfAuthority): string {
  if (o.field === "limit" && o.ceiling !== undefined && o.asked !== undefined) {
    return `You can approve up to ${amount(o.ceiling)}; you can't give ${amount(o.asked)}`;
  }
  if (o.field === "capacity") {
    return "You can't give it in that capacity";
  }
  return `You don't hold ${o.action}, so you can't give it`;
}

/** The capacity label, apart from where the authority came from (XI-10). */
export function capacityLabel(c: Capacity | null): string {
  switch (c) {
    case "on_your_behalf":
      return "On your behalf";
    case "on_behalf_of_org":
      return "On behalf of the organization";
    case "own_use":
      return "For their own use";
    case "as_yourself":
      return "As yourself";
    case null:
      return "Capacity not chosen";
  }
}

function validText(v: Validity | null, nowMs: number): string {
  if (v === null) {
    return "Not chosen";
  }
  if (v.kind === "until_revoked") {
    return "Until you turn it off";
  }
  const days = Math.max(0, Math.ceil((v.atMs - nowMs) / DAY_MS));
  return `Ends in ${String(days)} day${days === 1 ? "" : "s"}`;
}

/** Whether `v` may be chosen for `kind` (OP-153 m.3 (x)): "until you revoke" only between
 * people and only when chosen explicitly. */
export function validityAllowed(kind: RecipientKind, v: Validity): boolean {
  return v.kind === "until" || kind === "human";
}

/** The request the host turns into the Exercise: exactly the previewed draft, or nothing when
 * the preview still has blockers (XI-4). */
export interface GiveRequest {
  readonly action: "grant.issue" | "grant.amend";
  readonly draft: Draft;
}

export function giveRequest(
  d: Draft,
  v: Viewer,
  nowMs: number,
  amend: boolean,
): GiveRequest | null {
  return preview(d, v, nowMs).blockers.length === 0
    ? { action: amend ? "grant.amend" : "grant.issue", draft: d }
    : null;
}

/** Who asked for the sheet to open (§8.17.5.1, IA-1, X9, XI-7). */
export type Opener = "user" | "needs_attention" | "requester";

/** The trusted sheet opens directly only when the viewer started it; a requester's request
 * opens only from a Needs Attention item. */
export function mayOpen(by: Opener): boolean {
  return by === "user" || by === "needs_attention";
}

/** A change of an existing delegation (§8.17.7.5, X11). */
export type Change = "narrow" | "widen" | "same";

/** Narrowing needs no consent; anything that widens is an expansion and goes through the exact
 * preview again (asymmetric friction, §6.4, X11). */
export function classify(before: Draft, after: Draft): Change {
  const wider =
    after.canDo.some((a) => !before.canDo.includes(a)) ||
    (after.canPassOn && !before.canPassOn) ||
    after.limits.some((l) => {
      const b = before.limits.find((x) => x.action === l.action && x.unit === l.unit);
      return b === undefined || l.amount > b.amount;
    }) ||
    before.limits.some(
      (b) => !after.limits.some((l) => l.action === b.action && l.unit === b.unit),
    ) ||
    validEnd(after.valid) > validEnd(before.valid);
  if (wider) {
    return "widen";
  }
  const same = JSON.stringify(before) === JSON.stringify(after);
  return same ? "same" : "narrow";
}

function validEnd(v: Validity | null): number {
  if (v === null) {
    return 0;
  }
  return v.kind === "until" ? v.atMs : Number.POSITIVE_INFINITY;
}

/** One blocker of a viewer-scoped explain (§9.6, R8). */
export interface Blocker {
  readonly reasonClass: string;
  /** Whether the viewer could resolve it themselves (`relative_to_viewer`). */
  readonly resolvableByViewer: boolean;
  readonly text: string;
}

/** A just-in-time option (§8.17.5.2, X8). */
export type JitOption = "approve_request" | "give_once" | "give_similar" | "decline";

/** The options a request offers, from its reason classes and where in the chain the blocker is
 * (§8.17.5.2): approving is a contribution, giving access is `grant.issue`, and they are never
 * the same button (X8). */
export function jitOptions(blockers: readonly Blocker[]): JitOption[] {
  const out: JitOption[] = [];
  if (blockers.some((b) => b.reasonClass === "approval_pending")) {
    out.push("approve_request");
  }
  if (blockers.some((b) => b.reasonClass === "no_grant" && b.resolvableByViewer)) {
    out.push("give_once", "give_similar");
  }
  out.push("decline");
  return out;
}

/** "Give access once" (§8.17.5.2, R8): count 1, fixed parameters, short; offered only when the
 * viewer can resolve the blocker, and saying what would still block it otherwise. */
export interface GiveOnce {
  readonly count: 1;
  readonly untilMs: number;
  readonly stillBlockedBy: readonly string[];
}

export function giveOnce(
  blockers: readonly Blocker[],
  nowMs: number,
  ttlMs = ONCE_DEFAULT_MS,
): GiveOnce | null {
  if (!blockers.some((b) => b.resolvableByViewer)) {
    return null;
  }
  return {
    count: 1,
    untilMs: nowMs + Math.min(ttlMs, ONCE_MAX_MS),
    stillBlockedBy: blockers.filter((b) => !b.resolvableByViewer).map((b) => b.text),
  };
}

/** One link of a budget chain (§8.17.5.6, X15). */
export interface BudgetLink {
  readonly remaining: number;
  readonly unit: string;
  readonly resetsAtMs: number | null;
  readonly countedResultUnknown: number;
  readonly financial: boolean;
}

export interface BudgetView {
  /** The narrowest link: the effective remaining. */
  readonly remaining: number;
  readonly unit: string;
  readonly resetsAtMs: number | null;
  readonly countedResultUnknown: number;
  readonly exhausted: boolean;
  /** A financial limit, on its own line with the Pay badge. */
  readonly financial: BudgetLink | null;
}

export function budgetView(chain: readonly BudgetLink[]): BudgetView | null {
  const access = chain.filter((l) => !l.financial);
  const narrowest = access.reduce<BudgetLink | null>(
    (m, l) => (m === null || l.remaining < m.remaining ? l : m),
    null,
  );
  if (narrowest === null) {
    return null;
  }
  return {
    remaining: narrowest.remaining,
    unit: narrowest.unit,
    resetsAtMs: narrowest.resetsAtMs,
    countedResultUnknown: access.reduce((n, l) => n + l.countedResultUnknown, 0),
    exhausted: narrowest.remaining <= 0,
    financial: chain.find((l) => l.financial) ?? null,
  };
}

/** How the viewer holds a delegation, for the actions offered on it (§8.17.5.7, §8.17.5.9). */
export type Holding =
  | { readonly kind: "direct" }
  | { readonly kind: "role"; readonly role: string; readonly org: string }
  | { readonly kind: "given_by_me" };

/** An action on a delegation; never "Remember this", never automatic renewal (XI-19). */
export type HeldAction =
  "turn_off_for_me" | "ask_to_exclude" | "give_back" | "narrow" | "renew" | "create_again";

export function heldActions(h: Holding, expired: boolean): HeldAction[] {
  switch (h.kind) {
    case "role":
      return ["turn_off_for_me", "ask_to_exclude"];
    case "direct":
      return ["give_back"];
    case "given_by_me":
      return expired ? ["create_again"] : ["narrow", "renew"];
  }
}

/** "Ends in 3 days — used 12 times this week" (§8.17.7.7): only for a used delegation ending
 * within a week. */
export function endingHint(endsAtMs: number, usesThisWeek: number, nowMs: number): string | null {
  const left = endsAtMs - nowMs;
  if (left <= 0 || left > 7 * DAY_MS || usesThisWeek === 0) {
    return null;
  }
  const days = Math.ceil(left / DAY_MS);
  return `Ends in ${String(days)} day${days === 1 ? "" : "s"} — used ${String(usesThisWeek)} time${usesThisWeek === 1 ? "" : "s"} this week`;
}

/** "Root: Acme board, 2 of 3" (§8.8, §8.11): the word owner is never used. */
export function rootText(root: {
  readonly name: string;
  readonly threshold: number;
  readonly of: number;
}): string {
  return root.of > 1
    ? `Root: ${root.name}, ${String(root.threshold)} of ${String(root.of)}`
    : `Root: ${root.name}`;
}

/** "Give Finance Approver v4 to: everyone HR lists in Finance — currently 14" (§8.8,
 * §8.17.7.6): the selector and its current count. */
export function roleLine(role: string, selector: string, current: number): string {
  return `Give ${role} to: ${selector} — currently ${String(current)}`;
}

/** "Acme excluded you from this role on 7 Oct" (§8.17.5.7). */
export function exclusionText(org: string, atMs: number): string {
  const d = new Date(atMs);
  const month = d.toLocaleString("en-GB", { month: "short", timeZone: "UTC" });
  return `${org} excluded you from this role on ${String(d.getUTCDate())} ${month}`;
}

/** The three words and what each is (§8.8, R2, X8). */
export const TERMS = {
  approve: "Approve",
  giveAccess: "Give access",
  allowed: "Allowed",
} as const;
