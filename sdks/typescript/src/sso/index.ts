// TN-134, OP-155 m.3 (i): the organization SSO setup portal's client. One API serves the hosted
// setup page and `<OrganizationSSO />`: `GET /v1/sso-setup/{link}` reads what a one-use link
// opens and spends nothing; `POST` submits one step. The first step binds the link to this
// browser by its own cookie, so the calls go to the realm's own origin with credentials.

/** A protocol a wizard drafts. */
export type Protocol = "saml" | "oidc";

/** One of Access's values the administrator copies into the provider. */
export type Value = "entity_id" | "acs_url" | "metadata_url" | "redirect_uri" | "scim_base_url";

/** One of the provider's values the administrator pastes. */
export type Input = "entity_id" | "metadata_url" | "issuer" | "client_id";

/** One data step of a wizard. */
export interface WizardStep {
  readonly protocol?: Protocol;
  readonly action: "open" | "copy" | "paste";
  readonly place?: string;
  readonly value?: Value;
  readonly input?: Input;
  readonly field?: string;
}

/** An identity provider wizard. */
export interface Wizard {
  readonly v: number;
  readonly provider: string;
  readonly name: string;
  readonly protocols: readonly Protocol[];
  readonly scim: boolean;
  readonly steps: readonly WizardStep[];
}

/** What a setup link opens. */
export interface SetupView {
  readonly organization: { readonly id: string; readonly display_name: string };
  readonly expires_at: string;
  readonly opened: boolean;
  readonly connection: string;
  readonly values: Readonly<Record<Value, string>>;
  readonly wizards: readonly Wizard[];
  readonly domains: readonly {
    readonly domain: string;
    readonly method: string;
    readonly verified: boolean;
    readonly txt_name: string;
  }[];
  readonly scim: { readonly bound: boolean };
  readonly drafts: readonly {
    readonly protocol: Protocol;
    readonly provider: string | null;
    readonly issuer: string | null;
    readonly client_id: string | null;
    readonly entity_id: string | null;
    readonly metadata_url: string | null;
  }[];
  readonly test: "ready" | "after_enactment";
  readonly texts: Readonly<Record<string, string>>;
}

/** One submitted step. */
export type SetupStep =
  | {
      readonly step: "connection";
      readonly provider: string;
      readonly protocol: "saml";
      readonly entity_id: string;
      readonly metadata_url: string;
    }
  | {
      readonly step: "connection";
      readonly provider: string;
      readonly protocol: "oidc";
      readonly issuer: string;
      readonly client_id: string;
    }
  | { readonly step: "test" }
  | { readonly step: "finish" };

/** An answer: the body, or the problem code of a refusal. */
export type Answer<T> =
  | { readonly ok: true; readonly status: number; readonly body: T }
  | { readonly ok: false; readonly status: number; readonly code: string };

/** Whether `link` can be a setup link token: 256 bits as base64url. */
export function isLink(link: string): boolean {
  return /^[A-Za-z0-9_-]{43}$/.test(link);
}

/** The path of link `link` under the realm's base path `base` (`""` or `/realms/<slug>`). */
export function setupPath(base: string, link: string): string {
  return `${base}/v1/sso-setup/${encodeURIComponent(link)}`;
}

/** The setup link token of a hosted setup page's path, `…/login/sso-setup/<token>`. */
export function linkOf(path: string): string | null {
  const m = /\/login\/sso-setup\/([A-Za-z0-9_-]+)\/?$/.exec(path);
  const link = m?.[1];
  return link !== undefined && isLink(link) ? link : null;
}

/** The steps of `wizard` that apply to `protocol`. */
export function stepsFor(wizard: Wizard, protocol: Protocol): readonly WizardStep[] {
  return wizard.steps.filter((s) => s.protocol === undefined || s.protocol === protocol);
}

function codeOf(body: unknown): string {
  if (typeof body === "object" && body !== null) {
    const b = body as Record<string, unknown>;
    if (typeof b["code"] === "string") return b["code"];
    if (typeof b["type"] === "string") return b["type"].split(":").pop() ?? "unknown";
  }
  return "unknown";
}

async function call<T>(fetcher: typeof fetch, path: string, init: RequestInit): Promise<Answer<T>> {
  try {
    const r = await fetcher(path, {
      ...init,
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
    });
    const body: unknown = (r.headers.get("content-type") ?? "").includes("json")
      ? await r.json()
      : {};
    return r.ok
      ? { ok: true, status: r.status, body: body as T }
      : { ok: false, status: r.status, code: codeOf(body) };
  } catch {
    return { ok: false, status: 0, code: "unavailable" };
  }
}

/** Reads what the link opens; reading spends nothing. */
export function readSetup(
  base: string,
  link: string,
  fetcher: typeof fetch = fetch,
): Promise<Answer<SetupView>> {
  return call<SetupView>(fetcher, setupPath(base, link), {
    method: "GET",
    headers: { Accept: "application/json" },
  });
}

/** Submits one step with a fresh `Idempotency-Key` (OP-65). */
export function submitSetup(
  base: string,
  link: string,
  step: SetupStep,
  fetcher: typeof fetch = fetch,
): Promise<Answer<Record<string, unknown>>> {
  return call<Record<string, unknown>>(fetcher, setupPath(base, link), {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "Idempotency-Key": crypto.randomUUID(),
    },
    body: JSON.stringify(step),
  });
}
