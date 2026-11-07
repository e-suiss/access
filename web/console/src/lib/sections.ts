// IA-5, XI-11: Admin, Developer and Audit are shown only when the viewer can exercise at least
// one action of the section, as the eligibility check answers through the BFF's ADP read path.
// No answer, an error or a refusal shows nothing (fail closed); there are no disabled stubs.
import { call } from "./api.js";

export type Section = "admin" | "developer" | "audit";

/** One action a section offers: what the eligibility check asks about. */
export interface Probe {
  readonly namespace: string;
  readonly name: string;
  readonly major: number;
  readonly resource: { readonly namespace: string; readonly path: readonly string[] };
}

/** The actions behind each section (§8.17.4.1); the screens of each section extend the list. */
export const PROBES: Readonly<Record<Section, readonly Probe[]>> = {
  admin: [
    {
      namespace: "idp.realm",
      name: "signin_policy",
      major: 1,
      resource: { namespace: "idp.realm", path: [] },
    },
    {
      namespace: "idp.group",
      name: "create",
      major: 1,
      resource: { namespace: "idp.realm", path: [] },
    },
  ],
  developer: [
    {
      namespace: "access.schema",
      name: "publish",
      major: 1,
      resource: { namespace: "access.domain", path: [] },
    },
  ],
  audit: [
    {
      namespace: "access.audit",
      name: "read",
      major: 1,
      resource: { namespace: "access.domain", path: [] },
    },
  ],
};

/** The eligibility check body for `probe` of `subject` in `realm` (OP-149 m.10). */
export function eligibilityBody(subject: string, realm: string, probe: Probe): unknown {
  return {
    subject,
    set: {
      intent: {
        action: { namespace: probe.namespace, name: probe.name, major: probe.major },
        resources: [{ namespace: probe.resource.namespace, path: [realm, ...probe.resource.path] }],
      },
    },
  };
}

async function eligible(subject: string, realm: string, probe: Probe): Promise<boolean> {
  try {
    const r = await call("/proxy/adp/eligibility:check", {
      method: "POST",
      body: eligibilityBody(subject, realm, probe),
    });
    if (!r.ok) return false;
    const v = (await r.json()) as { eligible?: unknown };
    return v.eligible === true;
  } catch {
    return false;
  }
}

/** The sections the viewer may see: any probe of the section answered eligible. */
export async function visibleSections(
  subject: string,
  realm: string,
): Promise<ReadonlySet<Section>> {
  const out = new Set<Section>();
  await Promise.all(
    (Object.keys(PROBES) as Section[]).map(async (s) => {
      const answers = await Promise.all(PROBES[s].map((p) => eligible(subject, realm, p)));
      if (answers.some(Boolean)) out.add(s);
    }),
  );
  return out;
}
