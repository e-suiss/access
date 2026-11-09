// OP-153 m.3 (gg), TN-128, TN-131, IA-5, §8.5 S7: the console against the running local
// deployment (deploy/compose/access.yaml), through its real BFF on the management listener. The
// realm's bootstrap test user signs in at the realm's own hosted login, with its password and a
// code of its authenticator app (OP-149 m.26 (b)); the cookie alone then shows no section and
// reads no organization: every authority read needs this browser's device key, which this
// sign-in has not registered.
import { expect, type Page, test } from "@playwright/test";

import { nextStep, totp } from "./totp.js";

const REALM_ORIGIN = process.env["ACCESS_LIVE_ORIGIN"] ?? "https://access-server:8443";
const IDENTIFIER = process.env["ACCESS_LIVE_IDENTIFIER"] ?? "test@acme.example";
const PASSWORD = process.env["ACCESS_LOCAL_TEST_PASSWORD"] ?? "";
const SEED = process.env["ACCESS_LIVE_TEST_TOTP_SEED"] ?? "";

async function step(page: Page, path: string, body?: unknown): Promise<Record<string, unknown>> {
  const r = await page.context().request.post(`${REALM_ORIGIN}${path}`, {
    headers: {
      origin: REALM_ORIGIN,
      "sec-fetch-site": "same-origin",
      "content-type": "application/json",
      "idempotency-key": crypto.randomUUID(),
    },
    ...(body === undefined ? {} : { data: body }),
  });
  expect(r.status(), `${path}: ${await r.text()}`).toBeLessThan(300);
  return (await r.json()) as Record<string, unknown>;
}

/** The console's sign-in: the realm's authorize, its hosted login's JSON steps, then back. */
async function signIn(page: Page): Promise<void> {
  const totpStep = SEED === "" ? 0 : await nextStep();
  const start = await page.request.get("/console/api/sign-in?realm=acme", { maxRedirects: 0 });
  expect(start.status()).toBe(303);
  const authorize = start.headers()["location"] ?? "";
  expect(authorize).toContain("/realms/acme/authorize?");
  const started = await step(page, "/realms/acme/v1/login/flows");
  const identified = await step(page, `/realms/acme${String(started["action"])}`, {
    method: "identifier",
    fields: { identifier: IDENTIFIER },
  });
  let done = await step(page, `/realms/acme${String(identified["action"])}`, {
    method: "password",
    fields: { password: PASSWORD },
  });
  if (done["step"] === "second_factor") {
    expect(
      SEED,
      "ACCESS_LIVE_TEST_TOTP_SEED names the test user's authenticator app seed",
    ).not.toBe("");
    done = await step(page, `/realms/acme${String(done["action"])}`, {
      method: "totp",
      fields: { totp_code: totp(SEED, totpStep) },
    });
  }
  expect(done["step"]).toBe("complete");
  await page.goto(authorize);
  await page.waitForURL(/\/console\//);
}

test.describe("@live console", () => {
  test("@live the shell is served with its headers and the BFF answers nothing without a session", async ({
    page,
  }) => {
    const r = await page.goto("/console/");
    expect(r?.status()).toBe(200);
    const csp = r?.headers()["content-security-policy"] ?? "";
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("'wasm-unsafe-eval'");
    expect((await page.request.get("/console/api/session")).status()).toBe(401);
    const orgs = await page.request.get("/console/api/proxy/admin/realms/acme/organizations");
    expect([401, 403]).toContain(orgs.status());
  });

  test("@live a signed-in cookie without the device key sees no section and reads no organization", async ({
    page,
  }) => {
    test.skip(
      PASSWORD === "",
      "ACCESS_LOCAL_TEST_PASSWORD names the bootstrap test user's password",
    );
    // TN-59: up to one TOTP step of waiting
    test.setTimeout(90_000);
    await signIn(page);
    await expect(page.getByRole("button", { name: "Register this browser" })).toBeVisible();
    const nav = page.getByRole("navigation", { name: "Console sections" });
    await expect(nav.getByRole("link", { name: "Admin" })).toHaveCount(0);
    await expect(nav.getByRole("link", { name: "Audit" })).toHaveCount(0);
    const orgs = await page.request.get("/console/api/proxy/admin/realms/acme/organizations");
    expect([401, 403]).toContain(orgs.status());
  });
});
