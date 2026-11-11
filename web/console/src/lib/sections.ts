// IA-5, XI-11: Admin, Developer and Audit, and each screen inside them, are shown only when the
// viewer can exercise at least one action of it, as the eligibility check answers through the
// BFF's ADP read path for a drafted intent. No answer, an error or a refusal shows nothing
// (fail closed); there are no disabled stubs.
import { search } from "./adp.js";
import { call } from "./api.js";
import type { Instance } from "./instance.js";
import { draft, type Wanted } from "./intents.js";

export type Section = "admin" | "developer" | "audit";

/** The screens of each section (§8.17.4.1; "Sign-in settings" is the identity plane's, E34). */
export const SCREENS = {
  admin: [
    "roles",
    "people",
    "sources",
    "restrictions",
    "protected",
    "offboarding",
    "domain",
    "changes",
    "history",
    "organizations",
    "agents",
    "ssh",
    "siem",
    "linux",
    "proxy",
    "hr",
    "breakglass",
    "reviews",
    "support",
    "placement",
    "durability",
    "ratelimits",
    "sign-in",
  ],
  developer: ["schemas", "integrations", "lab", "logs"],
  audit: ["records", "replay", "revocation", "unknown", "containment", "export", "recovery"],
} as const satisfies Readonly<Record<Section, readonly string[]>>;

export type Screen = (typeof SCREENS)[Section][number];

/** One action a screen offers: what the eligibility check asks about. */
export interface Probe {
  readonly namespace: string;
  readonly name: string;
  readonly major: number;
  readonly resource: "domain" | "realm" | "audit";
}

const meta = (name: string): Probe => ({ namespace: "access", name, major: 1, resource: "domain" });
const idp = (namespace: string, name: string): Probe => ({
  namespace: `idp.${namespace}`,
  name,
  major: 1,
  resource: "realm",
});
/**
 * A screen whose lane has not served it yet asks nothing and so is never shown: there are no
 * disabled stubs (IA-5, OP-157 m.4 (a)). Its lane drops the wrapper.
 */
const planned = (probes: readonly Probe[]): readonly Probe[] => probes.slice(0, 0);
// OP-151 m.8 (h)
const AUDIT: Probe = { namespace: "access", name: "read", major: 1, resource: "audit" };

/** The actions behind each screen; a screen appears when any one of them is eligible. */
export const PROBES: Readonly<Record<Screen, readonly Probe[]>> = {
  roles: [meta("authority_set_define"), meta("grant_amend"), idp("realm", "delegated_admin")],
  people: [meta("instance_terminate"), idp("account", "suspend")],
  sources: [meta("acceptance_establish"), meta("acceptance_amend")],
  restrictions: [meta("policy_set")],
  protected: [meta("grant_issue")],
  offboarding: [meta("party_depart")],
  domain: [meta("anchor_amend")],
  changes: [meta("grant_issue"), meta("policy_set"), meta("acceptance_amend")],
  // §8.5 S7, §8.17.9.1, Ek B 3874: every meta-Exercise, which auditors read
  history: [AUDIT],
  // §8.5 S7, §12.3.8, Ek B 3735, 3808
  organizations: [idp("org", "create"), idp("org", "update"), idp("org", "invite")],
  // OP-154 m.3 (c), (e), XI-17
  agents: [idp("agent", "register"), idp("agent", "retire"), idp("agent", "sponsor_assign")],
  // OP-156 m.3 (o)
  ssh: [idp("ssh", "ca_enable"), idp("ssh", "ca_disable"), idp("ssh", "host_group_register")],
  // OP-156 m.3 (s)
  siem: [idp("export", "sink_register"), idp("export", "sink_retire")],
  // OP-156 m.3 (p)
  linux: [
    idp("linux", "host_register"),
    idp("linux", "host_retire"),
    idp("linux", "offline_policy"),
  ],
  // OP-156 m.3 (l), (m)
  proxy: [idp("proxy", "register"), idp("proxy", "retire"), idp("proxy", "plain_headers")],
  // OP-156 m.3 (q)
  hr: [idp("hr", "source_register"), idp("hr", "import"), idp("hr", "connector_register")],
  // OP-157 m.3 (h)
  breakglass: [
    idp("org", "member_breakglass"),
    idp("org", "member_breakglass_clear"),
    idp("org", "breakglass_review"),
  ],
  // OP-157 m.3 (w)
  reviews: [idp("review", "schedule"), idp("review", "schedule_close")],
  // OP-157 m.3 (c), (e), (g)
  support: planned([
    idp("support", "case_system_register"),
    idp("support", "case_system_retire"),
    idp("support", "artifact_policy"),
  ]),
  // OP-158 m.4 (a), m.3 (o)
  placement: planned([idp("realm", "residency"), idp("realm", "rehome")]),
  // OP-158 m.4 (a), m.3 (n), (p), (r)
  durability: planned([idp("realm", "dr_profile"), idp("realm", "dr_profile_close")]),
  // OP-158 m.4 (a), m.3 (v)
  ratelimits: planned([idp("realm", "rate_limit")]),
  "sign-in": [
    idp("realm", "signin_policy"),
    idp("realm", "branding"),
    idp("client", "register"),
    idp("upstream", "register"),
    // OP-156 m.3 (i)
    idp("domain", "register"),
  ],
  // L1-ADP-18: any Party may publish; the screen shows where versions stand, which auditors read
  schemas: [AUDIT, meta("acceptance_amend")],
  integrations: [idp("client", "register"), idp("client", "update")],
  lab: [AUDIT],
  logs: [AUDIT],
  records: [AUDIT],
  replay: [AUDIT],
  revocation: [AUDIT],
  unknown: [AUDIT],
  // §8.6, Ek B 3921
  containment: [meta("instance_terminate"), meta("grant_revoke")],
  export: [AUDIT],
  // OP-158 m.4 (a), m.3 (m)
  recovery: planned([meta("domain_recover"), meta("domain_handover")]),
};

/** The intent `probe` asks about in `realm`. */
const RESOURCE: Readonly<Record<Probe["resource"], string>> = {
  domain: "access.domain",
  // OP-151 m.19 (a): the realm's `idp` resources, as every `idp.*` change names them
  realm: "idp",
  audit: "access.audit",
};

export function probeIntent(realm: string, probe: Probe): Wanted {
  return {
    action: { namespace: probe.namespace, name: probe.name, major: probe.major },
    resources: [{ namespace: RESOURCE[probe.resource], path: [realm] }],
  };
}

/** One of the viewer's own holdings, as the `holdings` search answers (IA-5). */
interface Holding {
  readonly grant: string;
  readonly holder: string;
  readonly since: number;
  readonly actions: readonly { readonly namespace?: string; readonly name?: string }[];
}

async function asks(subject: string, set: unknown): Promise<boolean> {
  const r = await call("/proxy/adp/eligibility:check", {
    method: "POST",
    body: { subject, set },
  });
  if (!r.ok) return false;
  const v = (await r.json()) as { eligible?: unknown };
  return v.eligible === true;
}

async function eligible(
  instance: Instance,
  realm: string,
  probe: Probe,
  holdings: () => Promise<readonly Holding[]>,
): Promise<boolean> {
  // OP-149 m.10: the subject is the Party the device Instance acts for; without it, nothing
  const subject = instance.party;
  if (subject === undefined) return false;
  try {
    const d = await draft(instance, probeIntent(realm, probe), "check");
    // OP-151 m.20 (d): the set is the drafted probe, its domain, root basis and capacity
    if (d.probe === undefined) return false;
    if (await asks(subject, { ...d.probe, intent: d.intent })) return true;
    // OP-152 m.7 (b): a delegated admin is asked on each of its own holdings naming the action
    for (const h of await holdings()) {
      if (!h.actions.some((a) => a.namespace === probe.namespace && a.name === probe.name)) {
        continue;
      }
      const basis = { holding: { grant: h.grant, holder: h.holder, since: h.since } };
      if (await asks(subject, { ...d.probe, basis, intent: d.intent })) return true;
    }
    return false;
  } catch {
    return false;
  }
}

/**
 * One round of probes per device Instance and realm (§13.7.4): the check limit counts every
 * eligibility check of a console session, so a page that sets the same Instance again asks
 * nothing again.
 */
const rounds = new Map<string, Promise<ReadonlySet<Screen>>>();

/** The screens the viewer may see: any probe of the screen answered eligible. */
export function visibleScreens(instance: Instance, realm: string): Promise<ReadonlySet<Screen>> {
  const key = `${realm}/${instance.id}`;
  let round = rounds.get(key);
  if (round === undefined) {
    round = probeScreens(instance, realm);
    rounds.set(key, round);
  }
  return round;
}

async function probeScreens(instance: Instance, realm: string): Promise<ReadonlySet<Screen>> {
  const all = Object.keys(PROBES) as Screen[];
  const probes = new Map<string, Promise<boolean>>();
  let held: Promise<readonly Holding[]> | undefined;
  const holdings = (): Promise<readonly Holding[]> => {
    held ??= search<Holding>(instance, "holdings", {}).then(
      (a) => a.results,
      () => [],
    );
    return held;
  };
  const ask = (p: Probe) => {
    const key = `${p.namespace}/${p.name}/${String(p.major)}/${p.resource}`;
    let answer = probes.get(key);
    if (answer === undefined) {
      answer = eligible(instance, realm, p, holdings);
      probes.set(key, answer);
    }
    return answer;
  };
  const out = new Set<Screen>();
  await Promise.all(
    all.map(async (s) => {
      const answers = await Promise.all(PROBES[s].map(ask));
      if (answers.some(Boolean)) out.add(s);
    }),
  );
  return out;
}

/** The section a screen belongs to. */
export function sectionOf(screen: Screen): Section {
  for (const s of Object.keys(SCREENS) as Section[]) {
    if ((SCREENS[s] as readonly string[]).includes(screen)) return s;
  }
  return "admin";
}

/** The sections with at least one visible screen. */
export function visibleSections(screens: ReadonlySet<Screen>): ReadonlySet<Section> {
  const out = new Set<Section>();
  for (const s of screens) out.add(sectionOf(s));
  return out;
}
