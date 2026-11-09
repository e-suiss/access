// OP-153 m.3 (gg), OP-154 m.3 (e), IA-5, XI-17: the console's agent registry against the running
// local deployment, through its real BFF on the management listener: the registry route is
// served, and like every authority read it answers nothing without a session or this browser's
// device key; the Agents screen is not offered to a viewer who cannot exercise it.
import { expect, test } from "@playwright/test";

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
});
