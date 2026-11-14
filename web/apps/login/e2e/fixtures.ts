import { test as base, expect, type CDPSession, type Page } from "@playwright/test";

import { LoginMock } from "./mock.js";

/** How the page called the WebAuthn entry points, across navigations. */
export interface WebAuthnLog {
  readonly gets: { mediation: string | null; aborted: boolean }[];
  readonly creates: { mediation: string | null }[];
  readonly signals: { name: string; args: unknown }[];
}

export interface VirtualAuthenticator {
  readonly cdp: CDPSession;
  readonly id: string;
  credentials(): Promise<
    { credentialId: string; isResidentCredential: boolean; userHandle?: string }[]
  >;
}

/** Runs in the page before its scripts: wraps the WebAuthn entry points and reports each call. */
function spy() {
  const report = (kind: string, data: unknown) =>
    (window as unknown as { __report: (k: string, d: unknown) => Promise<number> }).__report(
      kind,
      data,
    );
  const container = navigator.credentials;
  const get = container.get.bind(container);
  const create = container.create.bind(container);
  container.get = (options?: CredentialRequestOptions) => {
    const signal = options?.signal;
    void report("get", { mediation: options?.mediation ?? null }).then((index) => {
      if (signal?.aborted === true) void report("abort", index);
      signal?.addEventListener("abort", () => void report("abort", index));
    });
    return get(options);
  };
  container.create = (options?: CredentialCreationOptions) => {
    void report("create", {
      mediation: (options as { mediation?: string } | undefined)?.mediation ?? null,
    });
    return create(options);
  };
  const pkc = PublicKeyCredential as unknown as Record<string, unknown>;
  for (const name of [
    "signalUnknownCredential",
    "signalAllAcceptedCredentials",
    "signalCurrentUserDetails",
  ]) {
    pkc[name] = (args: unknown) => report("signal", { name, args }).then(() => undefined);
  }
}

export async function addVirtualAuthenticator(page: Page): Promise<VirtualAuthenticator> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable", { enableUI: false });
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      ctap2Version: "ctap2_1",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  return {
    cdp,
    id: authenticatorId,
    async credentials() {
      const { credentials } = await cdp.send("WebAuthn.getCredentials", { authenticatorId });
      return credentials;
    },
  };
}

export const test = base.extend<{ pageErrors: string[]; mock: LoginMock; webauthn: WebAuthnLog }>({
  pageErrors: [
    async ({ page }, use) => {
      const errors: string[] = [];
      page.on("console", (message) => {
        const text = message.text();
        const refusal =
          /^Failed to load resource: the server responded with a status of (4[0-9][0-9]|503) /;
        if (message.type() === "error" && !refusal.test(text)) errors.push(text);
      });
      page.on("pageerror", (error) => {
        errors.push(error.message);
      });
      await use(errors);
      expect(errors).toEqual([]);
    },
    { auto: true },
  ],
  webauthn: [
    async ({ page }, use) => {
      const log: WebAuthnLog = { gets: [], creates: [], signals: [] };
      await page.exposeFunction("__report", (kind: string, data: unknown) => {
        const d = data as { mediation: string | null; name: string; args: unknown };
        switch (kind) {
          case "get":
            return log.gets.push({ mediation: d.mediation, aborted: false }) - 1;
          case "abort": {
            const entry = log.gets[data as number];
            if (entry !== undefined) entry.aborted = true;
            return 0;
          }
          case "create":
            return log.creates.push({ mediation: d.mediation });
          default:
            return log.signals.push({ name: d.name, args: d.args });
        }
      });
      await page.addInitScript(spy);
      await use(log);
    },
    { auto: true },
  ],
  mock: [
    async ({ page }, use) => {
      const mock = new LoginMock();
      await mock.install(page);
      await use(mock);
    },
    { auto: true },
  ],
});

export { expect };
