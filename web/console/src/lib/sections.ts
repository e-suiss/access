// IA-5, XI-11: Admin, Developer and Audit, and each screen inside them, are shown only when the
// viewer can exercise at least one action of it, as the eligibility check answers through the
// BFF's ADP read path for a drafted intent. No answer, an error or a refusal shows nothing
// (fail closed); there are no disabled stubs.
import { call } from "./api.js";
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
    "sign-in",
  ],
  developer: ["schemas", "integrations", "lab", "logs"],
  audit: ["records", "replay", "revocation", "unknown", "export"],
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
// OP-151 m.8 (h)
const AUDIT: Probe = { namespace: "access", name: "read", major: 1, resource: "audit" };

/** The actions behind each screen; a screen appears when any one of them is eligible. */
export const PROBES: Readonly<Record<Screen, readonly Probe[]>> = {
  roles: [meta("authority_set_define"), meta("grant_amend")],
  people: [meta("instance_terminate"), idp("account", "suspend")],
  sources: [meta("acceptance_establish"), meta("acceptance_amend")],
  restrictions: [meta("policy_set")],
  protected: [meta("grant_issue")],
  offboarding: [meta("party_depart")],
  domain: [meta("anchor_amend")],
  changes: [meta("grant_issue"), meta("policy_set"), meta("acceptance_amend")],
  "sign-in": [
    idp("realm", "signin_policy"),
    idp("realm", "branding"),
    idp("client", "register"),
    idp("upstream", "register"),
  ],
  schemas: [{ namespace: "access.schema", name: "publish", major: 1, resource: "domain" }],
  integrations: [idp("client", "register"), idp("client", "update")],
  lab: [{ namespace: "access.schema", name: "publish", major: 1, resource: "domain" }, AUDIT],
  logs: [AUDIT],
  records: [AUDIT],
  replay: [AUDIT],
  revocation: [AUDIT],
  unknown: [AUDIT],
  export: [AUDIT],
};

/** The intent `probe` asks about in `realm`. */
const RESOURCE: Readonly<Record<Probe["resource"], string>> = {
  domain: "access.domain",
  realm: "idp.realm",
  audit: "access.audit",
};

export function probeIntent(realm: string, probe: Probe): Wanted {
  return {
    action: { namespace: probe.namespace, name: probe.name, major: probe.major },
    resources: [{ namespace: RESOURCE[probe.resource], path: [realm] }],
  };
}

async function eligible(subject: string, realm: string, probe: Probe): Promise<boolean> {
  try {
    const d = await draft(probeIntent(realm, probe), "check");
    const r = await call("/proxy/adp/eligibility:check", {
      method: "POST",
      body: { subject, set: { intent: d.intent } },
    });
    if (!r.ok) return false;
    const v = (await r.json()) as { eligible?: unknown };
    return v.eligible === true;
  } catch {
    return false;
  }
}

/** The screens the viewer may see: any probe of the screen answered eligible. */
export async function visibleScreens(subject: string, realm: string): Promise<ReadonlySet<Screen>> {
  const all = Object.keys(PROBES) as Screen[];
  const probes = new Map<string, Promise<boolean>>();
  const ask = (p: Probe) => {
    const key = `${p.namespace}/${p.name}/${String(p.major)}/${p.resource}`;
    let answer = probes.get(key);
    if (answer === undefined) {
      answer = eligible(subject, realm, p);
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
