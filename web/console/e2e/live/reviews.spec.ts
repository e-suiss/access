// OP-157 m.3 (w), m.6 (a), OP-153 m.3 (gg): the access review routes against the running local
// deployment, through its real BFF on the management listener. Without a session or this
// browser's device key they read nothing, no keep or schedule reaches them unsigned, and the
// screen is not offered to a viewer who cannot exercise it.
import { expect, test } from "@playwright/test";

const ADMIN = "/console/api/proxy/admin/realms/acme/reviews";

test.describe("@live console access reviews", () => {
  test("@live the review routes read and write nothing without a session", async ({ page }) => {
    for (const path of ["", "/q4", "/q4/items"]) {
      const r = await page.request.get(`${ADMIN}${path}`);
      expect([401, 403]).toContain(r.status());
    }
    const schedule = await page.request.post(ADMIN, {
      data: { name: "q4", period_days: 90, scope: "manager_team" },
    });
    expect([401, 403]).toContain(schedule.status());
    const keep = await page.request.post(`${ADMIN}/q4/items/AAAAAAAAAAAAAAAAAAAAAA/keep`, {
      data: {},
    });
    expect([401, 403]).toContain(keep.status());
  });

  test("@live the review screen is not offered without the viewer's eligibility", async ({
    page,
  }) => {
    const r = await page.goto("/console/admin/reviews");
    expect(r?.status()).toBe(200);
    await expect(page.getByTestId("review-items")).toHaveCount(0);
  });
});
