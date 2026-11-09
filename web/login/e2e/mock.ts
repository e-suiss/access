import { readFileSync } from "node:fs";
import { join } from "node:path";

import type { Page, Route } from "@playwright/test";

import type { FieldName, LoginUi, Method, UiNode } from "../src/contract.js";

const examples = join(import.meta.dirname, "../../../sdks/openapi/examples/login");

export const password = "correct horse battery staple";
export const totp = "123456";
export const signupCode = "12345678";

/** One of the committed examples generated from `crates/identity-ui` (OP-65). */
export function example(name: string): LoginUi {
  return JSON.parse(readFileSync(join(examples, `${name}.json`), "utf8")) as LoginUi;
}

function echo(ui: LoginUi, identifier: string): LoginUi {
  return {
    ...ui,
    nodes: ui.nodes.map((n): UiNode =>
      n.type === "input" && n.read_only === true ? { ...n, value: identifier } : n,
    ),
  };
}

function withoutNodes(ui: LoginUi): LoginUi {
  return { ...ui, nodes: [] };
}

/** The sign-up flow handle: `r` and 43 base64url characters (OP-153 m.11 (d)). */
export const signupFlow = `r${"A".repeat(43)}`;

const label = (id: string, text: string) => ({ id, text });

/** The sign-up steps as `crates/identity-ui/src/app/signup.rs` draws them. */
export function signupAddress(): LoginUi {
  return {
    version: 1,
    flow: signupFlow,
    kind: "registration",
    step: "identifier",
    action: `/v1/login/flows/${signupFlow}`,
    requirements: [
      { requirement: "identifier", state: "missing" },
      { requirement: "first_factor", state: "missing" },
    ],
    nodes: [
      {
        type: "input",
        name: "email",
        method: "register",
        kind: "text",
        autocomplete: "email",
        required: true,
        max_length: 320,
        label: label("label.email", "Email"),
      },
      {
        type: "input",
        name: "bot_token",
        method: "register",
        kind: "hidden",
        autocomplete: "off",
        required: false,
        max_length: 4096,
        label: label("registration.title", "Create your account"),
      },
      {
        type: "submit",
        method: "register",
        label: label("action.create_account", "Create account"),
      },
    ],
    messages: [],
  };
}

export function signupCodeStep(): LoginUi {
  return {
    ...signupAddress(),
    step: "authenticate",
    requirements: [
      { requirement: "identifier", state: "satisfied" },
      { requirement: "first_factor", state: "missing" },
    ],
    nodes: [
      {
        type: "input",
        name: "email_code",
        method: "email_code",
        kind: "code",
        autocomplete: "one-time-code",
        required: true,
        max_length: 16,
        label: label("label.email_code", "Code from your email"),
      },
      {
        type: "input",
        name: "display_name",
        method: "email_code",
        kind: "text",
        autocomplete: "name",
        required: false,
        max_length: 200,
        label: label("label.display_name", "Your name"),
      },
      { type: "submit", method: "email_code", label: label("action.verify", "Verify") },
    ],
    messages: [
      {
        id: "registration.code_sent",
        text: "If this address can be used, we've sent a code to it.",
        severity: "info",
      },
    ],
  };
}

/** The link wait of `Ui::email_sent(EmailWait::Link)` (TN-102). */
export function linkWait(): LoginUi {
  const ui = example("authenticate");
  return {
    ...ui,
    nodes: [
      {
        type: "submit",
        method: "restart",
        label: label("action.restart", "Use a different account"),
      },
    ],
    messages: [
      {
        id: "email.sent",
        text: "If these details match an account, we've sent an email.",
        severity: "info",
      },
    ],
  };
}

export interface Recorded {
  readonly path: string;
  readonly method: Method;
  readonly fields: Partial<Record<FieldName, string>>;
  readonly idempotencyKey: string | undefined;
}

interface Reply {
  readonly status: number;
  readonly ui?: LoginUi;
}

/** A JSON route's canned answer. */
export interface Canned {
  readonly status: number;
  readonly body?: unknown;
}

/** The login node endpoints of the Frontend API, mocked in the browser (real ones: OP-146 I5, I7). */
export class LoginMock {
  readonly submissions: Recorded[] = [];
  readonly requests: string[] = [];
  readonly registered = new Set<string>();
  readonly flows = new Map<string, LoginUi>();
  /** Nodes added to the identifier step (the option and provider nodes of N5). */
  identifierExtras: UiNode[] = [];
  /** Nodes added to the authenticate step. */
  authenticateExtras: UiNode[] = [];
  /** How many polls of a link wait still answer "waiting". */
  linkPolls = 2;
  /** JSON answers by `METHOD /path`; the bodies posted to them. */
  readonly json = new Map<string, Canned | ((body: unknown) => Canned)>();
  readonly posted: { key: string; body: unknown }[] = [];
  branding: Canned = { status: 200, body: { display_name: null, logo_uri: null } };
  /** `GET /v1/login/messages`: the realm's text overrides (OP-153 m.22 (k)). */
  messages: Canned = { status: 200, body: { overrides: {} } };
  theme = "";
  private identifier = "";

  async install(page: Page): Promise<void> {
    await page.route(/\/v1\/login\/flows(\/|$)/, (route) => this.handle(route));
    await page.route(/\/v1\/login\/step-up$/, (route) => this.stepUp(route));
    await page.route(/\/v1\/login\/branding$/, (route) =>
      route.fulfill({
        status: this.branding.status,
        contentType: "application/json",
        body: JSON.stringify(this.branding.body ?? {}),
      }),
    );
    await page.route(/\/v1\/login\/messages$/, (route) =>
      route.fulfill({
        status: this.messages.status,
        contentType: "application/json",
        body: JSON.stringify(this.messages.body ?? {}),
      }),
    );
    await page.route(/\/login\/theme\.css$/, (route) =>
      route.fulfill({ status: 200, contentType: "text/css", body: this.theme }),
    );
    await page.route(
      /\/v1\/(recovery|invitations|account|login\/link|login\/approval)(\/|$)/,
      (route) => this.jsonRoute(route),
    );
    await page.route(/\/callback(\?|$)/, (route) =>
      route.fulfill({
        status: 200,
        contentType: "text/html",
        body: "<!doctype html><html lang=en><title>Signed in</title><h1>Signed in</h1></html>",
      }),
    );
  }

  /** Whether the browser holds a live session the step-up route can restamp. */
  session = false;
  readonly stepUps: unknown[] = [];

  private async jsonRoute(route: Route): Promise<void> {
    const request = route.request();
    const key = `${request.method()} ${new URL(request.url()).pathname}`;
    this.requests.push(key);
    const body = request.method() === "GET" ? undefined : (request.postDataJSON() as unknown);
    this.posted.push({ key, body });
    const entry = this.json.get(key);
    const canned =
      entry === undefined
        ? { status: 404, body: { type: "urn:suiss:access:problem:not-found", status: 404 } }
        : typeof entry === "function"
          ? entry(body)
          : entry;
    return route.fulfill({
      status: canned.status,
      contentType: canned.status >= 400 ? "application/problem+json" : "application/json",
      body: JSON.stringify(canned.body ?? {}),
    });
  }

  private async stepUp(route: Route): Promise<void> {
    const request = route.request();
    this.requests.push(`${request.method()} ${new URL(request.url()).pathname}`);
    this.stepUps.push(request.postDataJSON());
    if (!this.session)
      return route.fulfill({
        status: 401,
        contentType: "application/problem+json",
        body: JSON.stringify({ type: "about:blank", title: "Sign in first", status: 401 }),
      });
    return this.reply(route, { status: 201, ui: example("identifier") });
  }

  private identifierStep(): LoginUi {
    const ui = example("identifier");
    return { ...ui, nodes: [...ui.nodes, ...this.identifierExtras] };
  }

  private async handle(route: Route): Promise<void> {
    const request = route.request();
    const url = new URL(request.url());
    this.requests.push(`${request.method()} ${url.pathname}`);
    if (request.method() === "POST" && url.pathname.endsWith("/v1/login/flows")) {
      const created = request.postData();
      const kind = created === null ? undefined : (JSON.parse(created) as { kind?: string }).kind;
      return this.reply(route, {
        status: 201,
        ui: kind === "registration" ? signupAddress() : this.identifierStep(),
      });
    }
    const flow = url.pathname.split("/").at(-1) ?? "";
    if (request.method() === "GET") {
      let ui = this.flows.get(flow);
      if (ui?.messages.some((m) => m.id === "email.sent") === true) {
        if (this.linkPolls > 0) this.linkPolls -= 1;
        else ui = withoutNodes(example("complete"));
      }
      return ui === undefined
        ? route.fulfill({
            status: 410,
            contentType: "application/problem+json",
            body: JSON.stringify({ type: "about:blank", title: "Gone", status: 410 }),
          })
        : this.reply(route, { status: 200, ui });
    }
    const body = request.postDataJSON() as {
      method: Method;
      fields?: Partial<Record<FieldName, string>>;
    };
    const fields = body.fields ?? {};
    this.submissions.push({
      path: url.pathname,
      method: body.method,
      fields,
      idempotencyKey: await request.headerValue("idempotency-key").then((v) => v ?? undefined),
    });
    return this.reply(route, this.answer(body.method, fields, flow));
  }

  private answer(method: Method, fields: Partial<Record<FieldName, string>>, flow: string): Reply {
    if (flow === signupFlow) {
      if (method === "register") return { status: 200, ui: signupCodeStep() };
      return fields.email_code === signupCode
        ? { status: 200, ui: withoutNodes(example("complete")) }
        : {
            status: 401,
            ui: {
              ...signupCodeStep(),
              messages: [
                {
                  id: "registration.failed",
                  text: "We couldn't create an account with these details.",
                  severity: "error",
                },
              ],
            },
          };
    }
    switch (method) {
      case "identifier": {
        this.identifier = fields.identifier ?? "";
        const ui = echo(example("authenticate"), this.identifier);
        return { status: 200, ui: { ...ui, nodes: [...ui.nodes, ...this.authenticateExtras] } };
      }
      case "restart":
        return { status: 200, ui: this.identifierStep() };
      case "password":
        return fields.password === password
          ? { status: 200, ui: example("second-factor") }
          : { status: 401, ui: echo(example("authenticate-failed"), this.identifier) };
      case "totp":
        return fields.totp_code === totp
          ? { status: 200, ui: withoutNodes(example("complete")) }
          : { status: 200, ui: example("second-factor-failed") };
      case "passkey": {
        const credential = JSON.parse(fields.passkey_credential ?? "{}") as { id?: string };
        const id = credential.id ?? "";
        if (this.registered.has(id)) return { status: 200, ui: withoutNodes(example("complete")) };
        const failed = example("identifier-passkey-failed");
        return {
          status: 401,
          ui: {
            ...failed,
            nodes: failed.nodes.map((n): UiNode =>
              n.type === "passkey_signal" && n.signal.kind === "unknown_credential"
                ? { ...n, signal: { ...n.signal, credential_id: id } }
                : n,
            ),
          },
        };
      }
      case "passkey_register": {
        const credential = JSON.parse(fields.passkey_credential ?? "{}") as { id?: string };
        if (credential.id !== undefined) this.registered.add(credential.id);
        return { status: 200, ui: withoutNodes(example("complete")) };
      }
      case "skip":
        return { status: 200, ui: withoutNodes(example("complete")) };
      case "recovery_code":
        return { status: 200, ui: example("second-factor-failed") };
      case "magic_link": {
        const ui = linkWait();
        this.flows.set(ui.flow, ui);
        return { status: 200, ui };
      }
      default:
        return { status: 400, ui: this.identifierStep() };
    }
  }

  private reply(route: Route, reply: Reply): Promise<void> {
    return route.fulfill({
      status: reply.status,
      contentType: "application/json",
      body: JSON.stringify(reply.ui),
    });
  }
}
