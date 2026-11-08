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
        instance: null,
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
