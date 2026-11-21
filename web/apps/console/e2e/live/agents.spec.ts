// OP-153 m.3 (gg), OP-154 m.3 (e), m.15 (i), IA-5, XI-17, TN-183: the console's agent registry
// against the running local deployment, through its real BFF on the management listener. The
// environment has the bootstrap's sample agent: the registry route is served, and like every
// authority read it answers nothing without a session or this browser's device key, so even the
// Acme administrator's signed-in cookie reads no agent before this browser's key is registered and
// the page never names it; the Agents screen is not offered to a viewer who cannot exercise it, and
// nowhere is an agent given a person badge.
import { expect, test } from "@playwright/test";

import { NOT_READY, READY, signIn } from "./signin.js";

/** The sample agent's name in deploy/compose/access/bootstrap.toml. */
const SAMPLE_AGENT = "Local sample agent";

test.describe("@live console agents", () => {
  test("@live the agent registry reads nothing without a session", async ({ page }) => {
    const list = await page.request.get("/console/api/proxy/admin/envs/acme/agents");
    expect([401, 403]).toContain(list.status());
    const one = await page.request.get(
      "/console/api/proxy/admin/envs/acme/agents/DAwMDAwMDAwMDAwMDAwMDA",
    );
    expect([401, 403]).toContain(one.status());
  });

  test("@live the Agents screen is not offered without the viewer's eligibility", async ({
    page,
  }) => {
    const r = await page.goto("/console/acme/admin/agents");
    expect(r?.status()).toBe(200);
    await expect(page.getByTestId("agent-list")).toHaveCount(0);
    await expect(page.getByText("Human", { exact: true })).toHaveCount(0);
  });

  test("@live a signed-in cookie without the device key reads no agent of the environment", async ({
    page,
  }) => {
    test.skip(!READY, NOT_READY);
    // TN-59: up to one TOTP step of waiting
    test.setTimeout(90_000);
    await signIn(page);
    const list = await page.request.get("/console/api/proxy/admin/envs/acme/agents");
    expect([401, 403]).toContain(list.status());
    expect(await list.text()).not.toContain(SAMPLE_AGENT);
    await page.goto("/console/acme/admin/agents");
    await expect(page.getByTestId("agent-list")).toHaveCount(0);
    await expect(page.getByText(SAMPLE_AGENT)).toHaveCount(0);
    // XI-17
    await expect(page.getByText("Human", { exact: true })).toHaveCount(0);
  });
});
