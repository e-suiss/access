// OP-157 m.3 (h), OP-153 m.3 (gg): the break-glass routes against the running local
// deployment, through its real BFF on the management listener. Without a session or this
// browser's device key they read nothing, no mark or review reaches them unsigned, and the
// screen is not offered to a viewer who cannot exercise it.
import { expect, test } from "@playwright/test";

const ADMIN = "/console/api/proxy/admin/realms/acme/breakglass";

test.describe("@live console break-glass", () => {
  test("@live the break-glass routes read and write nothing without a session", async ({
    page,
  }) => {
    for (const path of ["accounts", "reviews", "drills"]) {
      const r = await page.request.get(`${ADMIN}/${path}`);
      expect([401, 403]).toContain(r.status());
    }
    const mark = await page.request.post(`${ADMIN}/accounts`, {
      data: { organization: "AAAAAAAAAAAAAAAAAAAAAA", member: "AAAAAAAAAAAAAAAAAAAAAA" },
    });
    expect([401, 403]).toContain(mark.status());
    const review = await page.request.post(
      `${ADMIN}/reviews/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`,
      { data: { classification: "drill" } },
    );
    expect([401, 403]).toContain(review.status());
  });

  test("@live the break-glass screen is not offered without the viewer's eligibility", async ({
    page,
  }) => {
    const r = await page.goto("/console/admin/breakglass");
    expect(r?.status()).toBe(200);
    await expect(page.getByRole("region", { name: "Break-glass accounts" })).toHaveCount(0);
  });
});
