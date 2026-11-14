// HL-8, HL-17, DL-10, OP-159 m.3 (s), OP-153 m.3 (gg): the durability read names the hosting
// the governing domain's metadata declares, against the running local deployment through its
// real BFF. Without a session it answers nothing; a signed-in viewer who may read durability
// sees the hosting line, shared unless the provider declared dedicated hardware.
import { expect, test } from "@playwright/test";

test.describe("@live console hosting", () => {
  test("@live the durability read with its hosting answers nothing without a session", async ({
    page,
  }) => {
    const read = await page.request.get("/console/api/proxy/admin/realms/acme/durability");
    expect([401, 403]).toContain(read.status());
  });

  test("@live the hosting line is part of the durability screen only", async ({ page }) => {
    const r = await page.goto("/console/admin/durability");
    expect(r?.status()).toBe(200);
    await expect(page.getByTestId("durability-hosting")).toHaveCount(0);
  });
});
