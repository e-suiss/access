// OP-153 m.3 (gg), §12.4.1, TN-133, XI-17, A-12, E64, OP-154 m.3 (e), (t), m.15 (i): the agent
// surfaces against the running local deployment, signed in once as its bootstrap test user
// (signin.setup.ts). The bootstrap's sample agent acts for the test user under the test user's
// own Grant and made one allowed Exercise; no executor runs there, so nothing reported its
// outcome, and no upstream account is connected. The realm's agent-connections route answers
// the cookie with the person's connections and agents and never a token; with this browser's
// device set up, the hub shows the sample agent as an agent acting for the test user, and its
// use with no report.
import { expect, test } from "@playwright/test";

import { PASSWORD, REALM } from "./signin.js";

test.describe("@live connected accounts for agents", () => {
  test.skip(PASSWORD === "", "ACCESS_LOCAL_TEST_PASSWORD names the bootstrap test user's password");

  test("@live S11 reads the person's connected accounts for agents from the agent-connections route", async ({
    page,
  }) => {
    await page.goto(`${REALM}/account`);
    const box = page.getByTestId("agent-accounts");
    await expect(box.getByRole("heading", { name: "Connected accounts for agents" })).toBeVisible();
    await expect(box.getByText("We can't read your connected accounts right now.")).toHaveCount(0);
    const r = await page.request.get(`${REALM}/v1/account/agent-connections`);
    expect(r.status()).toBe(200);
    const body = (await r.json()) as {
      agents: Record<string, unknown>[];
      connections: Record<string, unknown>[];
    };
    expect(Array.isArray(body.connections)).toBe(true);
    expect(Array.isArray(body.agents)).toBe(true);
    const rows = box.locator("[data-connection]");
    await expect(rows).toHaveCount(body.connections.length);
    const raw = JSON.stringify(body);
    expect(raw).not.toContain("access_token");
    expect(raw).not.toContain("refresh_token");
    // OP-154 m.15 (i)
    expect(body.connections).toHaveLength(0);
    await expect(box).toContainText("No accounts are connected for agents.");
  });

  test("@live the sample agent acts for the test user and is shown as an agent, with no report", async ({
    page,
  }) => {
    // XI-17, A-12, E64, X30
    await page.goto(`${REALM}/account/authority`);
    await page.getByRole("button", { name: "Set up this device" }).click();
    await page
      .getByRole("dialog", { name: "Check what you're signing" })
      .getByRole("button", { name: "Sign" })
      .click();
    await expect(page.getByTestId("hub")).toBeVisible();
    const badge = page.getByTestId("acting-for-you").getByTestId("agent-badge").first();
    await expect(badge).toHaveText(
      /^Agent · Acting for you · (operated by \S+|operator not confirmed)$/,
    );
    await expect(badge.locator("[data-party-kind]")).toHaveAttribute("data-party-kind", "agent");
    await page.getByRole("link", { name: "Activity" }).click();
    const use = page
      .getByTestId("activity")
      .getByTestId("use")
      .filter({ has: page.getByTestId("agent-badge") })
      .first();
    await expect(use).toContainText("No report of the outcome yet");
    await expect(use).not.toContainText("reported by");
    await expect(page.getByText(/\bhuman\b/i)).toHaveCount(0);
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
