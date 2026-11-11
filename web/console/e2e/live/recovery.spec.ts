// §13.6, §8.17.9.7, OP-158 m.3 (m), OP-153 m.3 (gg): the recovery read against the running local
// deployment, through its real BFF on the management listener. Like every management read it
// answers nothing without a session, and nothing in the console starts a recovery.
import { expect, test } from "@playwright/test";

test.describe("@live console recovery", () => {
  test("@live the recovery read answers nothing without a session", async ({ page }) => {
    const read = await page.request.get("/console/api/proxy/admin/realms/acme/recovery");
    expect([401, 403]).toContain(read.status());
  });

  test("@live the recovery screen is not offered without a session", async ({ page }) => {
    const r = await page.goto("/console/audit/recovery");
    expect(r?.status()).toBe(200);
    await expect(page.getByTestId("recovery")).toHaveCount(0);
  });
});
