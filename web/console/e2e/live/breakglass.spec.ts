// OP-157 m.3 (h), m.6 (i), m.10, OP-153 m.3 (gg): the break-glass routes against the running
// local deployment, through its real BFF on the management listener. Without a session or this
// browser's device key they read nothing, no mark or review reaches them unsigned, and the
// screen is not offered to a viewer who cannot exercise it. The bootstrap marked a break-glass
// account in its own organization and let the test user review break-glass uses; signed in with
// this browser's key, the test user's screen lists the marked account.
import { expect, test } from "@playwright/test";

import { PASSWORD, registerAndOpen, signIn } from "./signin.js";

const ADMIN = "/console/api/proxy/admin/realms/acme/breakglass";
const ORGANIZATION = process.env["ACCESS_LIVE_BREAKGLASS_ORGANIZATION"];

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

  // INV-28, §12.3.8, OP-157 m.3 (h), Ek B 5536, 5537
  test("@live the break-glass screen lists the marked account", async ({ page }) => {
    test.skip(
      PASSWORD === "" || ORGANIZATION === undefined,
      "ACCESS_LIVE_BREAKGLASS_ORGANIZATION names the bootstrap's break-glass organization",
    );
    // TN-59: up to one TOTP step of waiting
    test.setTimeout(120_000);
    await signIn(page);
    await registerAndOpen(page, "/console/admin/breakglass");
    await expect(page.getByRole("heading", { level: 2, name: "Break-glass" })).toBeVisible();
    const accounts = page.getByRole("region", { name: "Break-glass accounts" });
    await expect(accounts).toBeVisible();
    await expect(page.getByTestId("breakglass-accounts")).toContainText(ORGANIZATION ?? "");
  });
});
