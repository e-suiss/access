// IA-5, XI-11: Admin, Developer, Audit and Platform, and each screen inside them, are shown only
// when the viewer can exercise at least one action of it, as the eligibility check answers through the
// BFF's ADP read path for a drafted intent. No answer, an error or a refusal shows nothing
// (fail closed); there are no disabled stubs.
import { queryOptions, skipToken } from "@tanstack/react-query";
import * as v from "valibot";

import { Eligibility, type Holding, holdings as readHoldings } from "./adp.js";
import { call } from "./api.js";
import type { Instance } from "./instance.js";
import { draft, type Wanted } from "./intents.js";

export type Section = "admin" | "developer" | "audit" | "platform";

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
    "signing",
    "sign-in",
  ],
  developer: ["schemas", "integrations", "lab", "logs"],
  audit: ["records", "replay", "revocation", "unknown", "containment", "export", "recovery"],
  // OP-159 m.41 (b)
  platform: ["tenants", "envs", "sandboxes", "operator"],
} as const satisfies Readonly<Record<Section, readonly string[]>>;

export type Screen = (typeof SCREENS)[Section][number];

/** One action a screen offers: what the eligibility check asks about. */
export interface Probe {
  readonly namespace: string;
  readonly name: string;
  readonly major: number;
  readonly resource: "domain" | "environment" | "audit";
}

const meta = (name: string): Probe => ({ namespace: "access", name, major: 1, resource: "domain" });
const idp = (namespace: string, name: string): Probe => ({
  namespace: `idp.${namespace}`,
  name,
  major: 1,
  resource: "environment",
});
/**
 * A screen whose lane has not served it yet asks nothing and so is never shown: there are no
 * disabled stubs (IA-5, OP-157 m.4 (a)). Its lane drops the wrapper.
 */
const planned = (probes: readonly Probe[]): readonly Probe[] => probes.slice(0, 0);
// OP-159 m.41 (b), INV-29
const platform = (name: string): Probe => idp("platform", name);
// OP-159 m.47 (h): catalog version 2
const PLATFORM: readonly Probe[] = [
  platform("tenant_create"),
  platform("tenant_suspend"),
  platform("tenant_reactivate"),
  platform("tenant_placement"),
];
// OP-151 m.8 (h)
const AUDIT: Probe = { namespace: "access", name: "read", major: 1, resource: "audit" };

/** The actions behind each screen; a screen appears when any one of them is eligible. */
export const PROBES: Readonly<Record<Screen, readonly Probe[]>> = {
  roles: [meta("authority_set_define"), meta("grant_amend"), idp("environment", "delegated_admin")],
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
  placement: [idp("environment", "residency"), idp("environment", "rehome")],
  // OP-158 m.4 (a), m.3 (n), (p), (r)
  durability: [idp("environment", "dr_profile"), idp("environment", "dr_profile_close")],
  // OP-158 m.4 (a), m.3 (v)
  ratelimits: [idp("environment", "rate_limit")],
  // OP-159 m.4 (a), m.3 (o), (r), (t)
  signing: [
    idp("environment", "signing_profile"),
    idp("environment", "signing_profile_close"),
    idp("environment", "kex_share"),
  ],
  "sign-in": [
    idp("environment", "signin_policy"),
    idp("environment", "branding"),
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
  // OP-158 m.4 (a), m.3 (m): what an auditor reads; only `access-cli domain recover` recovers
  recovery: [AUDIT],
  // OP-159 m.41 (b)
  tenants: PLATFORM,
  envs: PLATFORM,
  sandboxes: PLATFORM,
  operator: PLATFORM,
};

/** The intent `probe` asks about in `environment`. */
const RESOURCE: Readonly<Record<Probe["resource"], string>> = {
  domain: "access.domain",
  // OP-151 m.19 (a): the environment's `idp` resources, as every `idp.*` change names them
  environment: "idp",
  audit: "access.audit",
};

export function probeIntent(environment: string, probe: Probe): Wanted {
  return {
    action: { namespace: probe.namespace, name: probe.name, major: probe.major },
    resources: [{ namespace: RESOURCE[probe.resource], path: [environment] }],
  };
}

async function asks(subject: string, set: unknown): Promise<boolean> {
  const r = await call("/proxy/adp/eligibility:check", {
    method: "POST",
    body: { subject, set },
  });
  if (!r.ok) return false;
  const a = v.safeParse(Eligibility, await r.json());
  return a.success && a.output.eligible === true;
}

async function eligible(
  instance: Instance,
  environment: string,
  probe: Probe,
  holdings: () => Promise<readonly Holding[]>,
): Promise<boolean> {
  // OP-149 m.10: the subject is the Party the device Instance acts for; without it, nothing
  const subject = instance.party;
  if (subject === undefined) return false;
  try {
    const d = await draft(instance, probeIntent(environment, probe), "check");
    // OP-151 m.20 (d): the set is the drafted probe, its domain, root basis and capacity
    if (d.probe === undefined) return false;
    // OP-152 m.7 (b), OP-159 m.43 (c), §13.7.4
    for (const h of await holdings()) {
      if (!h.actions.some((a) => a.namespace === probe.namespace && a.name === probe.name)) {
        continue;
      }
      const basis = { holding: { grant: h.grant, holder: h.holder, since: h.since } };
      if (await asks(subject, { ...d.probe, basis, intent: d.intent })) return true;
    }
    return await asks(subject, { ...d.probe, intent: d.intent });
  } catch {
    return false;
  }
}

// OP-159 m.46 (d), §13.7.4, m.43 (d)
/**
 * One round of probes per session, device Instance and environment: the check limit counts every
 * eligibility check of a console session, so the answer is kept for the session and a page that
 * shows the same Instance again asks nothing again. Signing out drops it.
 */
export function screensQuery(instance: Instance | undefined, environment: string, account: string) {
  return queryOptions({
    queryKey: ["screens", environment, account, instance?.id] as const,
    queryFn: instance === undefined ? skipToken : () => probeScreens(instance, environment),
    staleTime: Number.POSITIVE_INFINITY,
    gcTime: Number.POSITIVE_INFINITY,
  });
}

async function probeScreens(instance: Instance, environment: string): Promise<ReadonlySet<Screen>> {
  const all = Object.keys(PROBES) as Screen[];
  const probes = new Map<string, Promise<boolean>>();
  let held: Promise<readonly Holding[]> | undefined;
  const holdings = (): Promise<readonly Holding[]> => {
    held ??= readHoldings(instance).catch(() => []);
    return held;
  };
  const ask = (p: Probe) => {
    const key = `${p.namespace}/${p.name}/${String(p.major)}/${p.resource}`;
    let answer = probes.get(key);
    if (answer === undefined) {
      answer = eligible(instance, environment, p, holdings);
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

// OP-159 m.47 (e), (f), (h), TN-140
/** The tenant's own actions, which only its primary environment publishes. */
export const TENANT_ACTIONS = [
  "environment_create",
  "admin_invite",
  "admin_remove",
  "owner_add",
] as const;

export type TenantAction = (typeof TENANT_ACTIONS)[number];

/**
 * The tenant actions the viewer can exercise in primary environment `environment`, asked once
 * per session and Instance like the screens; no answer is no action (fail closed).
 */
export function tenantActionsQuery(instance: Instance, environment: string, account: string) {
  return queryOptions({
    queryKey: ["tenant-actions", environment, account, instance.id] as const,
    queryFn: async (): Promise<ReadonlySet<TenantAction>> => {
      let held: Promise<readonly Holding[]> | undefined;
      const holdings = (): Promise<readonly Holding[]> => {
        held ??= readHoldings(instance).catch(() => []);
        return held;
      };
      const out = new Set<TenantAction>();
      await Promise.all(
        TENANT_ACTIONS.map(async (a) => {
          if (await eligible(instance, environment, idp("tenant", a), holdings)) out.add(a);
        }),
      );
      return out;
    },
    staleTime: Number.POSITIVE_INFINITY,
    gcTime: Number.POSITIVE_INFINITY,
  });
}
