// §8.17.7, §6.4 XI-1, XI-5, XI-9, XI-10, XI-11, XI-14, XI-15, XI-16, XI-22, IA-2: the hub's rows
// from the domain's own answers, by the rules of services/experience (domain::hub). Every row
// names its owner and when it was read; a domain that did not answer is unknown, never empty.

type Json = Readonly<Record<string, unknown>>;

function str(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

function num(v: unknown): number | undefined {
  return typeof v === "number" ? v : undefined;
}

function obj(v: unknown): Json {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Json) : {};
}

function arr(v: unknown): readonly unknown[] {
  return Array.isArray(v) ? (v as unknown[]) : [];
}

/** In whose name a holding is used (XI-10). */
export interface Capacity {
  readonly text: "capacity.own_use" | "capacity.on_behalf_of" | "capacity.as_yourself";
  readonly party?: string;
}

/** An action a row offers (XI-11, XI-5). */
export interface Offer {
  readonly action: "revoke" | "narrow" | "suspend";
  readonly available: boolean;
  readonly whoCan?: "who_can.grantor";
  readonly steps: number;
}

export interface Row {
  readonly grant: string;
  readonly owner: "access";
  readonly asOf: number;
  readonly status: "status.current" | "status.needs_refresh";
  readonly who: {
    readonly kind: "party" | "everyone" | "group" | "foreign";
    readonly party?: string;
  };
  readonly capacity: readonly Capacity[];
  readonly what: readonly string[];
  readonly validUntil?: number;
  /** One per limit (XI-14). */
  readonly limits: readonly unknown[];
  readonly offers: readonly Offer[];
  readonly source: Json;
  readonly since?: number;
}

export interface RootRow {
  readonly anchor: string;
  readonly sole: boolean;
  readonly confirm: "root.sole_confirm" | "root.joint_confirm";
}

export interface ActivityRow {
  readonly pos: number;
  readonly at?: number;
  readonly text: "activity.by_you" | "activity.for_you";
  readonly capacity: Capacity;
  readonly grant?: string;
}

export interface ChangeRow {
  readonly pos: number;
  readonly at?: number;
  readonly kind: string;
  readonly text: string;
  readonly about: string;
  readonly ended: boolean;
  readonly own: boolean;
}

/** What one read came back as: its results, or nothing usable. */
export type Read =
  { readonly kind: "answered"; readonly results: readonly Json[] } | { readonly kind: "unknown" };

export interface Hub {
  readonly asOf: number;
  readonly status: "domain.current" | "domain.unreachable";
  readonly actingForYou: readonly Row[];
  readonly sharedFromYou: readonly Row[];
  readonly yourAuthority: readonly Row[];
  readonly roots: readonly RootRow[];
  readonly activity: readonly ActivityRow[];
  readonly changes: readonly ChangeRow[];
  /** Always says what is not shown (§8.17.7.2). */
  readonly notices: readonly string[];
}

function capacities(row: Json, yours: boolean): Capacity[] {
  const own: Capacity = { text: yours ? "capacity.as_yourself" : "capacity.own_use" };
  const out: Capacity[] = [];
  for (const c of arr(row["capacities"])) {
    if (c === "own") out.push(own);
    const p = str(obj(c)["for"]);
    if (p !== undefined) out.push({ text: "capacity.on_behalf_of", party: p });
  }
  return out.length === 0 ? [own] : out;
}

function who(holder: Json): Row["who"] {
  const party = str(holder["party"]);
  if (party !== undefined) return { kind: "party", party };
  if (Array.isArray(holder["group"])) return { kind: "group" };
  return { kind: holder["public"] !== undefined ? "everyone" : "foreign" };
}

function offers(row: Json, viewer: string, roots: ReadonlySet<string>): Offer[] {
  const source = obj(row["source"]);
  const fromRoot = roots.has(str(source["anchor"]) ?? "");
  const gave = str(source["holder"]) === viewer || fromRoot;
  const out: Offer[] = (["revoke", "narrow"] as const).map((action) =>
    gave
      ? { action, available: true, steps: 2 }
      : { action, available: false, whoCan: "who_can.grantor", steps: 2 },
  );
  if (fromRoot) out.push({ action: "suspend", available: true, steps: 2 });
  return out;
}

function row(
  v: Json,
  viewer: string,
  asOf: number,
  roots: ReadonlySet<string>,
): [string[], Row] | undefined {
  if (v["type"] !== "holding") return undefined;
  const groups = arr(v["groups"]).filter((g): g is string => typeof g === "string");
  const grant = str(v["grant"]);
  if (groups.length === 0 || grant === undefined) return undefined;
  const lapsed = v["member"] === false;
  const validUntil = num(obj(v["validity"])["until"]);
  const since = num(v["since"]);
  return [
    groups,
    {
      grant,
      owner: "access",
      asOf,
      status: lapsed ? "status.needs_refresh" : "status.current",
      who: who(obj(v["holder"])),
      capacity: capacities(v, groups.includes("your_authority")),
      what: arr(v["actions"]).map(
        (a) => `${str(obj(a)["namespace"]) ?? ""}:${str(obj(a)["name"]) ?? ""}`,
      ),
      ...(validUntil === undefined ? {} : { validUntil }),
      limits: arr(v["budget"]),
      offers: offers(v, viewer, roots),
      source: obj(v["source"]),
      ...(since === undefined ? {} : { since }),
    },
  ];
}

function activity(v: Json, viewer: string): ActivityRow | undefined {
  if (v["type"] !== "use" || typeof v["by_viewer"] !== "boolean") return undefined;
  const capacity = obj(v["capacity"]);
  const forWhom = str(capacity["for"]);
  // XI-22
  if (!v["by_viewer"] && forWhom !== viewer) return undefined;
  const pos = num(v["pos"]);
  if (pos === undefined) return undefined;
  const at = num(v["at"]);
  const grant = str(obj(v["basis"])["grant"]);
  return {
    pos,
    ...(at === undefined ? {} : { at }),
    text: v["by_viewer"] ? "activity.by_you" : "activity.for_you",
    capacity:
      forWhom === undefined
        ? { text: "capacity.as_yourself" }
        : { text: "capacity.on_behalf_of", party: forWhom },
    ...(grant === undefined ? {} : { grant }),
  };
}

function change(v: Json, known: (kind: string) => boolean): ChangeRow | undefined {
  if (v["type"] !== "change") return undefined;
  const kind = str(v["kind"]);
  const about = str(v["id"]);
  const pos = Number(str(v["position"]) ?? Number.NaN);
  if (kind === undefined || !known(kind) || about === undefined || !Number.isSafeInteger(pos)) {
    return undefined;
  }
  const ended = v["ended"] === true;
  const at = num(v["at"]);
  return {
    pos,
    ...(at === undefined ? {} : { at }),
    kind,
    text: ended ? `change.${kind}_ended` : `change.${kind}`,
    about,
    ended,
    own: v["own"] === true,
  };
}

/** The hub of `viewer` from one domain's three reads, assembled at `now`. */
export function assemble(
  viewer: string,
  now: number,
  inventory: Read,
  uses: Read,
  changes: Read,
  known: (kind: string) => boolean,
): Hub {
  const of = (r: Read): readonly Json[] => (r.kind === "answered" ? r.results : []);
  const unknown = [inventory, uses, changes].some((r) => r.kind === "unknown");
  const roots = new Set(
    of(inventory)
      .filter((v) => v["type"] === "root")
      .map((v) => str(v["anchor"]))
      .filter((a): a is string => a !== undefined),
  );
  const hub = {
    asOf: now,
    status: unknown ? ("domain.unreachable" as const) : ("domain.current" as const),
    actingForYou: [] as Row[],
    sharedFromYou: [] as Row[],
    yourAuthority: [] as Row[],
    roots: [] as RootRow[],
    activity: [] as ActivityRow[],
    changes: [] as ChangeRow[],
    notices: unknown
      ? ["hub.not_shown_unconnected", "hub.some_unknown"]
      : ["hub.not_shown_unconnected"],
  };
  for (const v of of(inventory)) {
    if (v["type"] === "root") {
      const anchor = str(v["anchor"]);
      const sole = v["sole"] === true;
      if (anchor !== undefined) {
        hub.roots.push({
          anchor,
          sole,
          confirm: sole ? "root.sole_confirm" : "root.joint_confirm",
        });
      }
      continue;
    }
    const r = row(v, viewer, now, roots);
    if (r === undefined) continue;
    const [groups, value] = r;
    if (groups.includes("acting_for_you")) hub.actingForYou.push(value);
    if (groups.includes("shared_from_you")) hub.sharedFromYou.push(value);
    if (groups.includes("your_authority")) hub.yourAuthority.push(value);
  }
  hub.activity = of(uses)
    .map((v) => activity(v, viewer))
    .filter((a): a is ActivityRow => a !== undefined)
    .sort((a, b) => (b.at ?? 0) - (a.at ?? 0) || b.pos - a.pos);
  hub.changes = of(changes)
    .map((v) => change(v, known))
    .filter((c): c is ChangeRow => c !== undefined)
    .sort((a, b) => (b.at ?? 0) - (a.at ?? 0) || b.pos - a.pos);
  return hub;
}
