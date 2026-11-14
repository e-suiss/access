// §12.5.4, TN-127, OP-158 m.3 (v), OP-153 m.3 (gg): the rate limits read against the running
// local deployment, through its real BFF on the management listener. Like every management read
// it answers nothing without a session, and the screen is not offered to a viewer who cannot
// exercise idp.realm.rate_limit.
import { expect, test } from "@playwright/test";

test.describe("@live console rate limits", () => {
  test("@live the rate limits read answers nothing without a session", async ({ page }) => {
    const read = await page.request.get("/console/api/proxy/admin/realms/acme/rate-limits");
    expect([401, 403]).toContain(read.status());
    const write = await page.request.put(
      "/console/api/proxy/admin/realms/acme/settings/rate-limit",
      { data: { rps: 1 } },
    );
    expect([401, 403]).toContain(write.status());
  });

  test("@live the rate limits screen is not offered without the viewer's eligibility", async ({
    page,
  }) => {
    const r = await page.goto("/console/admin/ratelimits");
    expect(r?.status()).toBe(200);
    await expect(page.getByTestId("rate-limits")).toHaveCount(0);
  });
});
