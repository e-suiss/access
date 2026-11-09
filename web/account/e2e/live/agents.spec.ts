// OP-153 m.3 (gg), §12.4.1, TN-133, XI-17, OP-154 m.3 (t): the connected accounts for agents
// against the running local deployment, signed in once as its bootstrap test user
// (signin.setup.ts): the realm's own vault route answers the cookie with the person's
// connections and never a token, and the page draws them with no person badge for an agent.
import { expect, test } from "@playwright/test";

import { PASSWORD, REALM } from "./signin.js";

test.describe("@live connected accounts for agents", () => {
  test.skip(PASSWORD === "", "ACCESS_LOCAL_TEST_PASSWORD names the bootstrap test user's password");

  test("@live S11 reads the person's connected accounts for agents from the vault route", async ({
    page,
  }) => {
    await page.goto(`${REALM}/account`);
    const box = page.getByTestId("agent-accounts");
    await expect(box.getByRole("heading", { name: "Connected accounts for agents" })).toBeVisible();
    await expect(box.getByText("We can't read your connected accounts right now.")).toHaveCount(0);
    const r = await page.request.get(`${REALM}/v1/account/vault/connections`);
    expect(r.status()).toBe(200);
    const body = (await r.json()) as { connections: Record<string, unknown>[] };
    expect(Array.isArray(body.connections)).toBe(true);
    const rows = box.locator("[data-connection]");
    await expect(rows).toHaveCount(body.connections.length);
    const raw = JSON.stringify(body);
    expect(raw).not.toContain("access_token");
    expect(raw).not.toContain("refresh_token");
    if (body.connections.length === 0) {
      await expect(box).toContainText("No accounts are connected for agents.");
    }
  });

  test("@live an agent is never given a person badge on the account page", async ({ page }) => {
    // XI-17
    await page.goto(`${REALM}/account`);
    await expect(page.getByTestId("agent-accounts")).toBeVisible();
    await expect(page.getByText(/\bhuman\b/i)).toHaveCount(0);
    for (const badge of await page.locator("[data-party-kind]").all()) {
      await expect(badge).toHaveAttribute("data-party-kind", "agent");
    }
  });
});
