// The account BFF and the Frontend API mocked in the browser, with the rules
// `crates/http/src/account` enforces (tested there against the real server): no session, no
// data; a hub read or a draft needs the browser's statement; the write is a commit. These tests
// exercise the page; the rules themselves are the server's.
import type { BrowserContext, Route } from "@playwright/test";

import { type Cbor, encode } from "./cbor.js";

export const SESSION = "__Host-access-session";
export const CSRF = "__Host-access-account-csrf";

const DOMAIN = Buffer.alloc(32, 3).toString("base64url");
const BASIS = Buffer.alloc(16, 1).toString("base64url");
export const PARTY = Buffer.alloc(16, 2).toString("base64url");
const SCHEMA = Buffer.alloc(32, 7);

interface Wanted {
  readonly action: { readonly namespace: string; readonly name: string; readonly major: number };
  readonly resources: readonly { readonly namespace: string; readonly path: readonly string[] }[];
}

/** A canonical envelope and its ADP wire JSON (test side only), valid around now. */
export function envelopeOf(w: Wanted): { envelope: Uint8Array; intent: unknown } {
  const from = Date.now() - 60_000;
  const until = Date.now() + 600_000;
  const body: Record<string, Cbor> = {
    action: {
      name: w.action.name,
      major: w.action.major,
      schema: [-16, Uint8Array.from(SCHEMA)],
      namespace: w.action.namespace,
    },
    validity: [from, until],
    resources: w.resources.map((r) => ({
      path: [...r.path],
      namespace: r.namespace,
      incarnation: 0,
    })),
  };
  const intent = {
    action: { ...w.action, schema: SCHEMA.toString("base64url") },
    resources: w.resources.map((r) => ({ ...r, incarnation: 0 })),
    params: {},
    validity: { from, until },
  };
  return { envelope: encode(body), intent };
}

export interface Seen {
  readonly path: string;
  readonly body: Record<string, unknown>;
  readonly headers: Record<string, string>;
}

/** The mock: its state and what it saw. */
export class AccountMock {
  signedIn = false;
  /** The challenge refuses: the session must step up first. */
  stepUp = false;
  readonly seen: Seen[] = [];
  /** ADP search results by kind. */
  readonly searches = new Map<string, unknown[]>();
  /** How each successive evaluation is answered. */
  readonly evaluations: ("abort" | "allow")[] = [];
  /** The nonces of the commits received, in order. */
  readonly nonces: string[] = [];
  preferences: Record<string, boolean> = { "email:newsletter": false, "sms:campaign": false };
  /** S11: the sign-in methods `GET /v1/account/methods` lists. */
  methods: S11Methods = {
    password: { set: true },
    passkeys: [{ id: "crd_pk1", name: "Laptop", created_at: "2026-10-01T10:00:00Z", synced: true }],
    totp: [],
    recovery_codes: { set: false, acknowledged: false },
  };
  /** S11: writes that need a fresh confirmation first. */
  freshNeeded = false;
  /** S11: the server refuses removing the last way to sign in. */
  lastMethod = false;
  /** S11: linked sign-ins. */
  linked: { link: string; provider: string; linked_at_ms: number; verified_at_ms: number }[] = [
    { link: "bGluazE", provider: "google", linked_at_ms: 1_790_000_000_000, verified_at_ms: 0 },
  ];
  /** S11: connected apps. */
  apps: { client_id: string; app: string; claims: string[]; since_ms: number }[] = [
    { client_id: "cli_shop", app: "Shop", claims: ["email", "name"], since_ms: 1_790_000_000_000 },
  ];
  /** S10: sign-ins `GET /v1/sessions` lists. */
  signIns: Record<string, unknown>[] = [
    {
      id: "ses_here",
      authenticated_at: "2026-11-09T08:00:00Z",
      expires_at: "2026-11-23T08:00:00Z",
      keep_signed_in: true,
      assurance: {},
      current: true,
      device: null,
      instance: null,
      bound: true,
    },
    {
      id: "ses_phone",
      authenticated_at: "2026-11-08T08:00:00Z",
      expires_at: "2026-11-22T08:00:00Z",
      keep_signed_in: false,
      assurance: {},
      current: false,
      device: "Phone",
      instance: "aW5zdGFuY2Vfb3RoZXI",
      bound: false,
    },
  ];
  /** S10: why `GET /v1/sessions/current` says the sign-in ended, when signed out. */
  signedOutReason: string | null = null;
  /** The device Instance key id the BFF's session names, once this browser set one up. */
  instanceKid: string | null = null;
  /** S2/S11: the connected accounts for agents `GET /v1/account/vault/connections` lists. */
  vault: Record<string, unknown>[] = [];

  async signIn(context: BrowserContext, baseURL: string): Promise<void> {
    this.signedIn = true;
    await context.addCookies([
      {
        name: CSRF,
        value: "csrf-token",
        domain: new URL(baseURL).hostname,
        path: "/",
        secure: true,
        sameSite: "Strict",
      },
    ]);
  }

  async install(context: BrowserContext): Promise<void> {
    await context.route("**/account/api/**", (r) => this.bff(r));
    await context.route("**/v1/account/**", (r) => this.frontend(r));
    await context.route(
      /\/v1\/account\/(methods|password|passkeys|totp|recovery-codes|linked|connected-apps)/,
      (r) => this.s11(r),
    );
    await context.route(/\/v1\/(sessions|me)(\/|$)/, (r) => this.s10(r));
    await context.route(/\/v1\/account\/vault\/connections/, (r) => this.vaultRoute(r));
  }

  private async vaultRoute(r: Route): Promise<void> {
    const s = this.record(r);
    const method = r.request().method();
    const reply = (status: number, body: unknown) =>
      r.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
    if (!this.signedIn) return reply(401, { code: "session-required" });
    const one = /\/vault\/connections\/([^/?]+)$/.exec(s.path)?.[1];
    if (one === undefined) return reply(200, { connections: this.vault });
    if (method === "DELETE") {
      if (s.headers["idempotency-key"] === undefined) {
        return reply(400, { code: "idempotency-key-required" });
      }
      this.vault = this.vault.map((c) =>
        c["connection"] === one ? { ...c, status: "disconnected" } : c,
      );
      return reply(200, { connection: one, status: "disconnected" });
    }
    return reply(404, { code: "not-found" });
  }

  private record(r: Route): Seen {
    const req = r.request();
    const raw = req.postData();
    const seen: Seen = {
      path: new URL(req.url()).pathname,
      body: raw === null || raw === "" ? {} : (JSON.parse(raw) as Record<string, unknown>),
      headers: req.headers(),
    };
    this.seen.push(seen);
    return seen;
  }

  private async bff(r: Route): Promise<void> {
    const s = this.record(r);
    const path = s.path.replace(/^.*\/account\/api/, "");
    const reply = (status: number, body: unknown) =>
      r.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
    if (!this.signedIn) return reply(401, { code: "session-required" });
    if (r.request().method() !== "GET" && s.headers["x-csrf-token"] !== "csrf-token") {
      return reply(403, { code: "csrf-token-invalid" });
    }
    if (path === "/session") {
      return reply(200, {
        realm: "acme",
        domain: DOMAIN,
        account: "usr_ada",
        expires_at: "2099-01-01T00:00:00Z",
        party: PARTY,
        instance: this.instanceKid,
        instance_id: null,
        pep: "access-account",
        api: "/account/api",
        frontend: "",
      });
    }
    if (path === "/instances/challenge") {
      if (this.stepUp) return reply(403, { code: "step-up-required" });
      const create = envelopeOf({
        action: { namespace: "access", name: "instance_create", major: 1 },
        resources: [{ namespace: "access.party", path: ["p"] }],
      });
      return reply(201, {
        challenge: Buffer.alloc(32, 9).toString("base64url"),
        domain: DOMAIN,
        basis: BASIS,
        pep: "access-identity",
        party: PARTY,
        valid_from: new Date(Date.now() - 1000).toISOString(),
        valid_until: new Date(Date.now() + 600_000).toISOString(),
        create: Buffer.from(create.envelope).toString("base64url"),
      });
    }
    if (path === "/instances") {
      return typeof s.body["ais"] === "string" && s.body["ais"] !== ""
        ? reply(201, { instance: "i", party: PARTY })
        : reply(400, { code: "key-pop-invalid" });
    }
    if (path === "/intents") {
      if (s.headers["x-access-ais"] === undefined) return reply(401, { code: "ais-required" });
      const meta = s.body["payload"] !== undefined;
      const w = (meta
        ? { ...s.body, resources: [{ namespace: "access.grant", path: ["g"] }] }
        : s.body) as unknown as Wanted;
      const d = envelopeOf(w);
      return reply(200, {
        intent: d.intent,
        envelope: Buffer.from(d.envelope).toString("base64url"),
        ...(meta
          ? {
              payload: Buffer.from(JSON.stringify(s.body["payload"])).toString("base64url"),
              basis: { anchor: "AAAAAAAAAAAAAAAAAAAAAA" },
            }
          : {}),
      });
    }
    const context = s.body["context"] as Record<string, unknown> | undefined;
    if (typeof context?.["ais"] !== "string") return reply(403, { code: "read-not-own" });
    const kind = /^\/proxy\/adp\/search\/(.+)$/.exec(path)?.[1];
    if (kind !== undefined) return reply(200, { results: this.searches.get(kind) ?? [], page: {} });
    if (path === "/proxy/adp/evaluation") {
      this.nonces.push(String(context["nonce"]));
      const how = this.evaluations.shift() ?? "allow";
      if (how === "abort") return r.abort("connectionreset");
      return reply(200, { decision: true, context: { exercise: "ex_1", position: 42 } });
    }
    return reply(404, { code: "not-found" });
  }

  private async frontend(r: Route): Promise<void> {
    const s = this.record(r);
    const reply = (status: number, body: unknown) =>
      r.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
    if (!this.signedIn) return reply(401, { code: "session-required" });
    const path = s.path.replace(/^.*\/v1\/account/, "");
    if (path === "/preferences" && r.request().method() === "PUT") {
      for (const c of s.body["changes"] as { channel: string; topic: string; granted: boolean }[]) {
        this.preferences[`${c.channel}:${c.topic}`] = c.granted;
      }
    }
    switch (path) {
      case "/preferences":
        return reply(200, { current: this.preferences, history: [] });
      case "/documents":
        return reply(200, { acceptances: [] });
      case "/security-history":
        return reply(200, { days: 90, entries: [], last_sign_in: null });
      case "/deletion":
        return reply(200, { scheduled: false });
      case "/data-requests":
        return reply(200, { requests: [] });
      default:
        return reply(404, { code: "not-found" });
    }
  }

  private async s11(r: Route): Promise<void> {
    const s = this.record(r);
    const method = r.request().method();
    const reply = (status: number, body?: unknown) =>
      r.fulfill({
        status,
        contentType: "application/json",
        body: body === undefined ? "" : JSON.stringify(body),
      });
    if (!this.signedIn) return reply(401, { code: "session-required" });
    const path = s.path.replace(/^.*\/v1\/account/, "");
    const write = method !== "GET";
    if (write && s.headers["idempotency-key"] === undefined) {
      return reply(400, { code: "idempotency-key-required" });
    }
    if (write && this.freshNeeded) return reply(401, { code: "step-up-required" });
    if (path === "/methods") return reply(200, this.methods);
    const removed = /^\/methods\/(.+)$/.exec(path)?.[1];
    if (removed !== undefined && method === "DELETE") {
      if (this.lastMethod) return reply(409, { code: "last-sign-in-method" });
      this.methods = {
        ...this.methods,
        passkeys: this.methods.passkeys.filter((p) => p.id !== removed),
        totp: this.methods.totp.filter((p) => p.id !== removed),
      };
      return reply(204);
    }
    if (path === "/password" && method === "PUT") {
      if (s.body["new_password"] === "password") return reply(400, { code: "password-rejected" });
      this.methods = { ...this.methods, password: { set: true } };
      return reply(204);
    }
    if (path === "/passkeys") {
      return reply(200, {
        registration: "reg_1",
        options: {
          challenge: "Y2hhbGxlbmdl",
          rp: { id: "localhost", name: "acme" },
          user: { id: "dXNlcg", name: "ada", displayName: "Ada" },
          pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        },
      });
    }
    if (path === "/passkeys/reg_1") {
      this.methods = {
        ...this.methods,
        passkeys: [
          ...this.methods.passkeys,
          {
            id: "crd_pk2",
            name: String(this.seen.find((x) => x.path.endsWith("/passkeys"))?.body["name"]),
            created_at: "2026-11-09T09:00:00Z",
            synced: false,
          },
        ],
      };
      return reply(201, {});
    }
    if (path === "/totp") {
      return reply(200, {
        enrollment: "enr_1",
        secret: "JBSWY3DPEHPK3PXP",
        uri: "otpauth://totp/acme:ada?secret=JBSWY3DPEHPK3PXP&issuer=acme",
      });
    }
    if (path === "/totp/enr_1") {
      if (s.body["code"] !== "123456") return reply(400, { code: "invalid-code" });
      this.methods = {
        ...this.methods,
        totp: [{ id: "crd_totp", created_at: "2026-11-09T09:00:00Z" }],
        recovery_codes: { set: true, acknowledged: false },
      };
      return reply(200, {
        recovery_codes: ["AAAA-BBBB-CCCC-DDDD", "EEEE-FFFF-GGGG-HHHH"],
        acknowledgement_required: true,
      });
    }
    if (path === "/recovery-codes") {
      this.methods = { ...this.methods, recovery_codes: { set: true, acknowledged: false } };
      return reply(200, {
        recovery_codes: ["JJJJ-KKKK-LLLL-MMMM"],
        acknowledgement_required: true,
      });
    }
    if (path === "/recovery-codes/acknowledgement") {
      this.methods = { ...this.methods, recovery_codes: { set: true, acknowledged: true } };
      return reply(200, { acknowledged: true });
    }
    if (path === "/linked") return reply(200, { linked: this.linked });
    const link = /^\/linked\/(.+)$/.exec(path)?.[1];
    if (link !== undefined && method === "DELETE") {
      if (this.lastMethod) return reply(409, { code: "last-sign-in-method" });
      this.linked = this.linked.filter((l) => l.link !== link);
      return reply(204);
    }
    if (path === "/connected-apps") return reply(200, { apps: this.apps });
    const client = /^\/connected-apps\/(.+)$/.exec(path)?.[1];
    if (client !== undefined && method === "DELETE") {
      this.apps = this.apps.filter((a) => a.client_id !== client);
      return reply(204);
    }
    return reply(404, { code: "not-found" });
  }

  private async s10(r: Route): Promise<void> {
    const s = this.record(r);
    const method = r.request().method();
    const reply = (status: number, body?: unknown) =>
      r.fulfill({
        status,
        contentType: "application/json",
        body: body === undefined ? "" : JSON.stringify(body),
      });
    const path = s.path.replace(/^.*\/v1/, "");
    if (!this.signedIn) {
      return reply(
        401,
        this.signedOutReason === null
          ? { code: "session-required" }
          : { code: "session-required", reason: this.signedOutReason },
      );
    }
    if (path === "/sessions") return reply(200, { sessions: this.signIns });
    if (path === "/sessions/current") return reply(200, this.signIns[0]);
    if (path === "/sessions/sign-out-everywhere" && method === "POST") {
      this.signIns = [];
      return reply(204);
    }
    if (path === "/sessions/current/sign-out" && method === "POST") {
      this.signedIn = false;
      return reply(204);
    }
    const terminated = /^\/me\/instances\/([^/]+)$/.exec(path)?.[1];
    if (terminated !== undefined && method === "DELETE") {
      return typeof s.body["ais"] === "string" && typeof s.body["nonce"] === "string"
        ? reply(200, { exercise: "ex_term" })
        : reply(400, { code: "invalid-request" });
    }
    const ended = /^\/sessions\/([^/]+)\/end$/.exec(path)?.[1];
    if (ended !== undefined && method === "POST") {
      const row = this.signIns.find((x) => x["id"] === ended);
      if (row === undefined) return reply(404, { code: "not-found" });
      this.signIns = this.signIns.filter((x) => x["id"] !== ended);
      return reply(200, { instance: row["instance"] ?? null });
    }
    return reply(404, { code: "not-found" });
  }
}

/** The S11 method list. */
export interface S11Methods {
  password: { set: boolean };
  passkeys: { id: string; name: string | null; created_at: string; synced: boolean }[];
  totp: { id: string; created_at: string }[];
  recovery_codes: { set: boolean; acknowledged: boolean };
}

/** A holding row as ADP's inventory answers it. */
export function holding(
  grant: string,
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    type: "holding",
    grant,
    groups: ["shared_from_you"],
    holder: { party: "someone" },
    source: { anchor: "root-anchor" },
    capacities: ["own"],
    actions: [{ namespace: "work", name: "approve" }],
    validity: { from: 0, until: 4_102_444_800_000 },
    since: 7,
    ...extra,
  };
}
