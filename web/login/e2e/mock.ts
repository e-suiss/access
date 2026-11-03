import { readFileSync } from "node:fs";
import { join } from "node:path";

import type { Page, Route } from "@playwright/test";

import type { FieldName, LoginUi, Method, UiNode } from "../src/contract.js";

const examples = join(import.meta.dirname, "../../../sdks/openapi/examples/login");

export const password = "correct horse battery staple";
export const totp = "123456";

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

/** The login node endpoints of the Frontend API, mocked in the browser (real ones: OP-146 I5, I7). */
export class LoginMock {
  readonly submissions: Recorded[] = [];
  readonly requests: string[] = [];
  readonly registered = new Set<string>();
  readonly flows = new Map<string, LoginUi>();
  private identifier = "";

  async install(page: Page): Promise<void> {
    await page.route(/\/v1\/login\/flows(\/|$)/, (route) => this.handle(route));
    await page.route(/\/callback(\?|$)/, (route) =>
      route.fulfill({
        status: 200,
        contentType: "text/html",
        body: "<!doctype html><html lang=en><title>Signed in</title><h1>Signed in</h1></html>",
      }),
    );
  }

  private async handle(route: Route): Promise<void> {
    const request = route.request();
    const url = new URL(request.url());
    this.requests.push(`${request.method()} ${url.pathname}`);
    if (request.method() === "POST" && url.pathname === "/v1/login/flows") {
      return this.reply(route, { status: 201, ui: example("identifier") });
    }
    const flow = url.pathname.split("/").at(-1) ?? "";
    if (request.method() === "GET") {
      const ui = this.flows.get(flow);
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
    return this.reply(route, this.answer(body.method, fields));
  }

  private answer(method: Method, fields: Partial<Record<FieldName, string>>): Reply {
    switch (method) {
      case "identifier":
        this.identifier = fields.identifier ?? "";
        return { status: 200, ui: echo(example("authenticate"), this.identifier) };
      case "restart":
        return { status: 200, ui: example("identifier") };
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
