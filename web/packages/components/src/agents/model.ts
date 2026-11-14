// XI-17, A-12, §6.4, §8.10, §8.13, §8.17.5.8, §8.17.7.1, §8.17.7.4, §8.17.7.5, §8.17.11.1,
// §12.4.1, E64, INV-18, X8, X13, X24, X30, XI-19, TN-133
/** What the agent surfaces show, from Access's own answers: an agent is always shown as an
 * agent; a report is a runtime's Claim and never Access's decision; a runtime's state is what the
 * runtime confirmed, or unknown. It decides nothing and signs nothing. */

type Json = Readonly<Record<string, unknown>>;

function obj(v: unknown): Json {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Json) : {};
}

function arr(v: unknown): readonly unknown[] {
  return Array.isArray(v) ? (v as unknown[]) : [];
}

function str(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

function num(v: unknown): number | undefined {
  return typeof v === "number" && Number.isSafeInteger(v) ? v : undefined;
}

/** A text and the plain-text values placed into it. */
export interface Line {
  readonly text: string;
  readonly args?: Readonly<Record<string, string>>;
}

/** An agent as a surface shows it (XI-17, A-12): never a person. */
export interface AgentFace {
  readonly party: string;
  /** The operator an accepted `operated_by` Claim names; absent when none is confirmed. */
  readonly operator?: string;
  /** Whom it acts for, when it acts on someone's behalf. */
  readonly actingFor?: string;
}

/** The agent face of a hub `agent` member, when the JSON says `party_kind: agent`. */
export function faceOf(
  agent: unknown,
  party: string | undefined,
  actingFor?: string,
): AgentFace | undefined {
  const a = obj(agent);
  const p = str(a["party"]) ?? party;
  if (a["party_kind"] !== "agent" || p === undefined) return undefined;
  const operator = str(a["operator"]);
  return {
    party: p,
    ...(operator === undefined ? {} : { operator }),
    ...(actingFor === undefined ? {} : { actingFor }),
  };
}

/** The badge's parts, in order: "Agent · Acting for X · operated by Y" (XI-17). */
export function badge(face: AgentFace, name: (party: string) => string): Line[] {
  const out: Line[] = [{ text: "agent.badge" }];
  if (face.actingFor !== undefined) {
    out.push({ text: "agent.acting_for", args: { agent: name(face.actingFor) } });
  }
  out.push(
    face.operator === undefined
      ? { text: "agent.operator_unknown" }
      : { text: "agent.operated_by", args: { operator: name(face.operator) } },
  );
  return out;
}

/** One executor report about a use (E64). */
export interface Report {
  readonly reporter: string;
  readonly outcome: "done" | "not-done" | "unknown";
  readonly evidence: readonly string[];
  readonly at?: number;
  /** Whether it applied the allowed intent (INV-19). */
  readonly sameIntent: boolean;
}

/** A confirmed control state (U5). */
export interface Control {
  readonly state: "on_hold" | "stopped_confirmed";
  readonly reporter: string;
}

/** What the runtimes reported about one use. */
export interface Reports {
  readonly attested: readonly Report[];
  readonly control: readonly Control[];
}

const OUTCOMES = new Set(["done", "not-done", "unknown"]);
const EVIDENCE = new Set(["upstream-confirmation", "independent-recheck", "browser-observation"]);

/** The reports of a hub `use` entry; anything it cannot read is left out, never guessed. */
export function reportsOf(entry: unknown): Reports {
  const r = obj(obj(entry)["reports"]);
  const attested: Report[] = [];
  for (const a of arr(r["attested"])) {
    const o = obj(a);
    const reporter = str(o["reporter"]);
    const outcome = str(o["outcome"]);
    if (reporter === undefined || outcome === undefined || !OUTCOMES.has(outcome)) continue;
    const at = num(o["at"]);
    attested.push({
      reporter,
      outcome: outcome as Report["outcome"],
      evidence: arr(o["evidence"]).filter(
        (e): e is string => typeof e === "string" && EVIDENCE.has(e),
      ),
      ...(at === undefined ? {} : { at }),
      sameIntent: o["intent"] === "same",
    });
  }
  const control: Control[] = [];
  for (const c of arr(r["control"])) {
    const o = obj(c);
    const reporter = str(o["reporter"]);
    const state = str(o["state"]);
    if (reporter === undefined || (state !== "on_hold" && state !== "stopped_confirmed")) continue;
    control.push({ state, reporter });
  }
  return { attested, control };
}

/** One outcome label with who reported it and how (§8.7, §8.8, §8.17.10.3, X30). */
export interface OutcomeLine {
  readonly text:
    | "outcome.attested_conforming"
    | "outcome.attested_nonconforming"
    | "outcome.not_done"
    | "outcome.unknown"
    | "outcome.unattested";
  readonly reporter?: string;
  readonly evidence: readonly string[];
}

/** The Activity's outcome lines: one per report, or "No report of the outcome yet". An agent's
 * own words are never one of them (X30): only a runtime's recorded report is. */
export function outcomeLines(r: Reports): OutcomeLine[] {
  if (r.attested.length === 0) return [{ text: "outcome.unattested", evidence: [] }];
  return r.attested.map((a) => ({
    text: !a.sameIntent
      ? "outcome.attested_nonconforming"
      : a.outcome === "done"
        ? "outcome.attested_conforming"
        : a.outcome === "not-done"
          ? "outcome.not_done"
          : "outcome.unknown",
    reporter: a.reporter,
    evidence: a.evidence.map((e) => `evidence.${e.replaceAll("-", "_")}`),
  }));
}

/** The runtime's state as the runtime confirmed it (§8.17.7.4, U5): never derived from Access. */
export type RuntimeState = "running" | "on_hold_confirmed" | "stopped" | "unknown";

/** The runtime state from the confirmed control states: the last one wins; none is unknown. */
export function runtimeOf(r: Reports): RuntimeState {
  const last = r.control.at(-1);
  if (last === undefined) return "unknown";
  return last.state === "stopped_confirmed" ? "stopped" : "on_hold_confirmed";
}

/** The runtime state from an executor's `Job` (executor-v1): a hold or stop counts only once an
 * `executor_control` Claim confirms it; an unconfirmed one, or a state it does not know, is
 * unknown. */
export function runtimeOfJob(job: unknown): RuntimeState {
  const j = obj(job);
  const state = str(j["state"]);
  const confirmed = j["confirmed"] === true;
  if (state === "running") return "running";
  if (state === "stopped") return confirmed ? "stopped" : "unknown";
  if (state === "completed" || state === "unknown" || state === undefined) return "unknown";
  return confirmed ? "on_hold_confirmed" : "unknown";
}

/** The status text of a runtime state. */
export function runtimeText(s: RuntimeState): string {
  return `agent.status.${s}`;
}

/** One allowed use still open after a revocation: its horizon (revocation-impact `exposed`). */
export interface Exposed {
  readonly exercise: string;
  readonly holder: string;
  readonly horizonMs: number;
}

/** The open uses of a `revocation_impact` answer. */
export function exposedOf(impact: unknown): Exposed[] {
  const out: Exposed[] = [];
  for (const e of arr(obj(impact)["exposed"])) {
    const o = obj(e);
    const exercise = str(o["exercise"]);
    const holder = str(o["holder"]);
    const horizonMs = num(o["horizon_ms"]);
    if (exercise !== undefined && holder !== undefined && horizonMs !== undefined) {
      out.push({ exercise, holder, horizonMs });
    }
  }
  return out;
}

/** The long-running indicator (§8.17.5.8, E31): the next authority check of each open task. */
export function nextCheck(exposed: readonly Exposed[], nowMs: number): number | undefined {
  const ahead = exposed.map((e) => e.horizonMs).filter((h) => h > nowMs);
  return ahead.length === 0 ? undefined : Math.min(...ahead);
}

/** The honest aftermath of a revocation for one open task (§8.13, §8.17.7.4): before its horizon
 * the runtime is within what was already allowed; after it, an effect is outside authority, and
 * only a report dated after the horizon says the runtime went on — only then is containment
 * offered. Access never says it stopped anything. */
export interface Aftermath {
  readonly runtime: RuntimeState;
  readonly next: Line;
  readonly containment: boolean;
}

export function aftermath(
  e: Exposed,
  r: Reports,
  nowMs: number,
  time: (ms: number) => string,
): Aftermath {
  const runtime = runtimeOf(r);
  const at = { time: time(e.horizonMs) };
  if (nowMs < e.horizonMs) {
    return { runtime, next: { text: "aftermath.within_window", args: at }, containment: false };
  }
  const went = runtime !== "stopped" && r.attested.some((a) => (a.at ?? 0) > e.horizonMs);
  return went
    ? { runtime, next: { text: "aftermath.ignoring", args: at }, containment: true }
    : { runtime, next: { text: "aftermath.after_window", args: at }, containment: false };
}

/** One row of the Stop interaction (§8.17.7.5, X13): Stop is two actions, shown as two rows. */
export interface StopRow {
  readonly owner: "executor" | "access";
  readonly line: Line;
}

/** The two rows of "Stop": what the runtime confirmed, and what Access recorded. There is no
 * single "Stopped" state. */
export function stopRows(
  runtime: RuntimeState,
  access: { readonly text: string; readonly args?: Readonly<Record<string, string>> },
): [StopRow, StopRow] {
  return [
    { owner: "executor", line: { text: runtimeText(runtime) } },
    { owner: "access", line: access },
  ];
}

/** One budget term of a holding as a short limit (XI-14). */
export function limitLine(term: unknown): Line | undefined {
  const t = obj(term);
  const capacity = num(t["capacity"]);
  if (capacity === undefined) return undefined;
  if (t["dimension"] === "count")
    return { text: "limit.count", args: { capacity: String(capacity) } };
  const unit = str(obj(t["dimension"])["amount"]);
  return unit === undefined
    ? undefined
    : { text: "limit.amount", args: { capacity: String(capacity), unit } };
}

/** A delegation the holder of `parent` passed on (§8.17.7.1, X31): its holder and its limits. */
export interface Passed {
  readonly grant: string;
  readonly holder: string;
  readonly limits: readonly Line[];
}

/** The sub-delegations of `parent` among the inventory rows: rows whose source is `parent`. */
export function passedOn(
  parent: string,
  rows: readonly {
    readonly grant: string;
    readonly source: Json;
    readonly who: { readonly party?: string };
    readonly limits: readonly unknown[];
  }[],
): Passed[] {
  return rows
    .filter((r) => r.source["grant"] === parent && r.who.party !== undefined)
    .map((r) => ({
      grant: r.grant,
      holder: r.who.party ?? "",
      limits: r.limits.map(limitLine).filter((l): l is Line => l !== undefined),
    }));
}

/** One approval the viewer gave a requester (§8.17.11.1). */
export interface Approval {
  readonly agent: string;
  readonly action: string;
  readonly atMs: number;
  /** An amount in minor units and its unit, when the request had one. */
  readonly amount?: { readonly value: number; readonly unit: string };
}

/** A suggestion to delegate what the viewer keeps approving (X8, XI-19): only a suggestion. */
export interface Suggestion {
  readonly agent: string;
  readonly action: string;
  readonly count: number;
  /** The largest amount approved, per unit: the suggested limit, never more. */
  readonly limit?: { readonly value: number; readonly unit: string };
}

/** How many similar approvals in a week make a suggestion (§8.17.11.1, PD). */
export const SUGGEST_AFTER = 5;
const WEEK_MS = 7 * 86_400_000;

/** Suggestions from the viewer's approvals of the past week: one per agent and action seen at
 * least [`SUGGEST_AFTER`] times with at most one unit. Accepting one only opens the S1 exact
 * preview; nothing is given until the viewer signs it there (XI-19). */
export function suggestions(approvals: readonly Approval[], nowMs: number): Suggestion[] {
  const groups = new Map<string, Approval[]>();
  for (const a of approvals) {
    if (a.atMs > nowMs || nowMs - a.atMs > WEEK_MS) continue;
    const k = JSON.stringify([a.agent, a.action]);
    groups.set(k, [...(groups.get(k) ?? []), a]);
  }
  const out: Suggestion[] = [];
  for (const list of groups.values()) {
    const first = list[0];
    if (first === undefined || list.length < SUGGEST_AFTER) continue;
    const units = new Set(list.map((a) => a.amount?.unit ?? ""));
    if (units.size !== 1) continue;
    const amounts = list.map((a) => a.amount).filter((m) => m !== undefined);
    const max = amounts.reduce<{ value: number; unit: string } | undefined>(
      (m, a) => (m === undefined || a.value > m.value ? a : m),
      undefined,
    );
    out.push({
      agent: first.agent,
      action: first.action,
      count: list.length,
      ...(max === undefined || amounts.length !== list.length ? {} : { limit: max }),
    });
  }
  return out;
}

/** One connected account and the agents that used it (§12.4.1, TN-133). */
export interface Connection {
  readonly connection: string;
  readonly upstream: string;
  readonly status: "active" | "pending" | "needs_reconnect" | "disconnected" | "unknown";
  readonly scopes: readonly string[];
  readonly used: readonly { readonly agent: string; readonly atMs?: number }[];
}

const STATUSES = new Set(["active", "pending", "needs_reconnect", "disconnected"]);

/** The connections of `GET /v1/account/vault/connections`; never a token. */
export function connectionsOf(answer: unknown): Connection[] {
  const out: Connection[] = [];
  for (const c of arr(obj(answer)["connections"])) {
    const o = obj(c);
    const connection = str(o["connection"]);
    if (connection === undefined) continue;
    const status = str(o["status"]) ?? "";
    const used = new Map<string, number | undefined>();
    for (const u of arr(o["used"])) {
      const agent = str(obj(u)["agent"]);
      if (agent === undefined) continue;
      const at = num(obj(u)["released_ms"]);
      const seen = used.get(agent);
      if (!used.has(agent) || (at !== undefined && (seen === undefined || at > seen))) {
        used.set(agent, at);
      }
    }
    out.push({
      connection,
      upstream: str(o["upstream"]) ?? str(o["resource"]) ?? connection,
      status: STATUSES.has(status) ? (status as Connection["status"]) : "unknown",
      scopes: arr(o["scopes"]).filter((s): s is string => typeof s === "string"),
      used: [...used].map(([agent, atMs]) => ({ agent, ...(atMs === undefined ? {} : { atMs }) })),
    });
  }
  return out;
}

/** The status text of a connection. */
export function connectionText(c: Connection): string {
  return c.status === "needs_reconnect"
    ? "agent_connections.needs_reconnect"
    : `agent_connections.${c.status}`;
}
