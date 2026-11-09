// OP-153 m.3 (gg), OP-154 m.3 (e), m.15 (i), IA-5, XI-17: the console's agent registry against
// the running local deployment, through its real BFF on the management listener. The realm has
// the bootstrap's sample agent: the registry route is served, and like every authority read it
// answers nothing without a session or this browser's device key, so even a signed-in cookie
// reads no agent and the page never names it; the Agents screen is not offered to a viewer who
// cannot exercise it, and nowhere is an agent given a person badge.
import { expect, type Page, test } from "@playwright/test";

import { nextStep, totp } from "./totp.js";

const IDENTIFIER = process.env["ACCESS_LIVE_IDENTIFIER"] ?? "test@acme.example";
const PASSWORD = process.env["ACCESS_LOCAL_TEST_PASSWORD"] ?? "";
const SEED = process.env["ACCESS_LIVE_TEST_TOTP_SEED"] ?? "";
/** The sample agent's name in deploy/compose/access/bootstrap.toml. */
const SAMPLE_AGENT = "Local sample agent";

/** The console's sign-in at the realm's hosted login: identifier, password and a code of the
 * test user's authenticator app (OP-149 m.26 (b)). */
async function signIn(page: Page): Promise<void> {
  const start = await page.request.get("/console/api/sign-in?realm=acme", { maxRedirects: 0 });
  expect(start.status()).toBe(303);
  await page.goto(start.headers()["location"] ?? "");
  await page.waitForURL(/\/realms\/acme\/login\?/);
  await page.getByLabel("Email or username").fill(IDENTIFIER);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  const code = page.getByLabel("Code from your authenticator app");
  await code.waitFor();
  await code.fill(totp(SEED, await nextStep()));
  await code.press("Enter");
  await page.waitForURL(/\/console(?:[?#]|$)/);
}

test.describe("@live console agents", () => {
  test("@live the agent registry reads nothing without a session", async ({ page }) => {
    const list = await page.request.get("/console/api/proxy/admin/realms/acme/agents");
    expect([401, 403]).toContain(list.status());
    const one = await page.request.get(
      "/console/api/proxy/admin/realms/acme/agents/DAwMDAwMDAwMDAwMDAwMDA",
    );
    expect([401, 403]).toContain(one.status());
  });

  test("@live the Agents screen is not offered without the viewer's eligibility", async ({
    page,
  }) => {
    const r = await page.goto("/console/admin/agents");
    expect(r?.status()).toBe(200);
    await expect(page.getByTestId("agent-list")).toHaveCount(0);
    await expect(page.getByText("Human", { exact: true })).toHaveCount(0);
  });

  test("@live a signed-in cookie without the device key reads no agent of the realm", async ({
    page,
  }) => {
    test.skip(
      PASSWORD === "",
      "ACCESS_LOCAL_TEST_PASSWORD names the bootstrap test user's password",
    );
    test.skip(
      SEED === "",
      "ACCESS_LIVE_TEST_TOTP_SEED names the test user's authenticator app seed",
    );
    // TN-59: up to one TOTP step of waiting
    test.setTimeout(90_000);
    await signIn(page);
    const list = await page.request.get("/console/api/proxy/admin/realms/acme/agents");
    expect([401, 403]).toContain(list.status());
    expect(await list.text()).not.toContain(SAMPLE_AGENT);
    await page.goto("/console/admin/agents");
    await expect(page.getByTestId("agent-list")).toHaveCount(0);
    await expect(page.getByText(SAMPLE_AGENT)).toHaveCount(0);
    // XI-17
    await expect(page.getByText("Human", { exact: true })).toHaveCount(0);
  });
});
