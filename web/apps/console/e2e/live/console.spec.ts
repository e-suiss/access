// OP-153 m.3 (gg), TN-128, TN-131, IA-5, §8.5 S7, OP-159 m.47: the console against the running
// local deployment (deploy/compose/access.yaml), through its real BFF on the management listener.
// The environment's bootstrap test user signs in at the environment's own hosted login, with its
// password and a code of its authenticator app (OP-149 m.26 (b)); the cookie alone then shows no
// section and reads no organization: every authority read needs this browser's device key, which
// this sign-in has not registered. The Acme tenant's administrator signs in once at `acme-admin`
// and administers `acme`; the platform administrator lists tenants and opens no environment.
import { expect, type Page, test } from "@playwright/test";

import { MANAGEMENT, NOT_READY, READY, registerAndOpen, signIn as signInAdmin } from "./signin.js";
import { nextStep, totp } from "./totp.js";

const IDENTIFIER = process.env["ACCESS_LIVE_IDENTIFIER"] ?? "test@acme.example";
const PASSWORD = process.env["ACCESS_LOCAL_TEST_PASSWORD"] ?? "";
const SEED = process.env["ACCESS_LIVE_TEST_TOTP_SEED"] ?? "";
const PLATFORM_SEED = process.env["ACCESS_LIVE_PLATFORM_TOTP_SEED"] ?? "";

/** The console's sign-in at its environment's address (OP-159 m.42 (a)): the environment's authorize (`prompt=login` sends it to the hosted login),
 * then the hosted login's own page: identifier, password and the authenticator app's code. */
async function signIn(page: Page): Promise<void> {
  await page.goto("/console/acme");
  await page.waitForURL(/\/env\/acme\/login\?/);
  await page.getByLabel("Email or username").fill(IDENTIFIER);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  const code = page.getByLabel("Code from your authenticator app");
  await code.waitFor();
  expect(SEED, "ACCESS_LIVE_TEST_TOTP_SEED names the test user's authenticator app seed").not.toBe(
    "",
  );
  await code.fill(totp(SEED, await nextStep()));
  await code.press("Enter");
  await page.waitForURL(/\/console\/acme(?:[/?#]|$)/);
}

test.describe("@live console", () => {
  test("@live the shell is served with its headers and the BFF answers nothing without a session", async ({
    page,
  }) => {
    const r = await page.goto("/console");
    expect(r?.status()).toBe(200);
    const csp = r?.headers()["content-security-policy"] ?? "";
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("'wasm-unsafe-eval'");
    expect((await page.request.get("/console/api/session")).status()).toBe(401);
    const orgs = await page.request.get("/console/api/proxy/admin/envs/acme/organizations");
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
    const orgs = await page.request.get("/console/api/proxy/admin/envs/acme/organizations");
    expect([401, 403]).toContain(orgs.status());
  });
});

// OP-159 m.47 (a), (i): the local plan's tenant: its management environment and its environment
test.describe("@live console tenant", () => {
  test("@live the tenant's home and environment addresses are served", async ({ page }) => {
    for (const path of [`/console/${MANAGEMENT}`, "/console/acme", "/console/platform"]) {
      const r = await page.goto(path);
      expect(r?.status()).toBe(200);
    }
    const tenant = await page.request.get(
      `/console/api/proxy/admin/envs/${MANAGEMENT}/tenant/environments`,
    );
    expect([401, 403]).toContain(tenant.status());
  });

  test("@live the Acme administrator signs in once and administers acme", async ({ page }) => {
    test.skip(!READY, NOT_READY);
    // TN-59: up to one TOTP step of waiting
    test.setTimeout(120_000);
    await signInAdmin(page);
    await registerAndOpen(page, "/console/acme/admin");
    await expect(page.getByRole("heading", { level: 1, name: "Admin" })).toBeVisible();
    await page.getByRole("button", { name: "Environment acme: switch environment" }).click();
    await expect(
      page.getByRole("menu").getByRole("menuitemradio", { name: `${MANAGEMENT} (tenant home)` }),
    ).toBeVisible();
  });

  test("@live the platform lists the Acme tenant and opens no environment", async ({ page }) => {
    test.skip(
      PASSWORD === "" || PLATFORM_SEED === "",
      "ACCESS_LIVE_PLATFORM_TOTP_SEED names the platform administrator's authenticator app seed",
    );
    test.setTimeout(120_000);
    await page.goto("/console/platform");
    await page.waitForURL(/\/env\/platform\/login\?/);
    await page.getByLabel("Email or username").fill("admin@platform.local");
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    await page.getByLabel("Password").fill(PASSWORD);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    const code = page.getByLabel("Code from your authenticator app");
    await code.waitFor();
    await code.fill(totp(PLATFORM_SEED, await nextStep()));
    await code.press("Enter");
    await page.waitForURL(/\/console\/platform(?:[/?#]|$)/);
    await page.getByRole("button", { name: "Register this browser" }).click();
    await page
      .getByRole("dialog", { name: "Review and sign" })
      .getByRole("button", { name: "Sign" })
      .click();
    await page
      .getByRole("navigation", { name: "Console sections" })
      .getByRole("link", { name: "Platform" })
      .click();
    await page.getByRole("link", { name: "Tenants" }).click();
    const acme = page.getByTestId("tenant-list").getByRole("row", { name: /Acme/ });
    await expect(acme).toContainText(MANAGEMENT);
    await expect(acme.getByTestId("environment-console-link")).toHaveAttribute(
      "href",
      `/console/${MANAGEMENT}`,
    );
    await expect(page.getByRole("region", { name: "New environment" })).toHaveCount(0);
  });
});
