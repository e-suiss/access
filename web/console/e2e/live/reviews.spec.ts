// OP-157 m.3 (w), m.6 (a), (i), OP-153 m.3 (gg): the access review routes against the running
// local deployment, through its real BFF on the management listener. Without a session or this
// browser's device key they read nothing, no keep or schedule reaches them unsigned, and the
// screen is not offered to a viewer who cannot exercise it. The bootstrap scheduled a review
// whose manager is the test user, with its Grant to the sample agent as its one team item; signed
// in with this browser's key, the test user sees that item and keeps it.
import { expect, test } from "@playwright/test";

import { PASSWORD, registerAndOpen, signIn } from "./signin.js";

const ADMIN = "/console/api/proxy/admin/realms/acme/reviews";
const REVIEW = process.env["ACCESS_LIVE_REVIEW"];

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

  // IDP-39 (3), LFP-18, OP-157 m.3 (w), m.6 (a), Ek B 5565
  test("@live the manager sees the team's Grant and keeps it with a signature", async ({
    page,
  }) => {
    test.skip(
      PASSWORD === "" || REVIEW === undefined,
      "ACCESS_LIVE_REVIEW names the bootstrap's review; ACCESS_LOCAL_TEST_PASSWORD its manager's password",
    );
    // TN-59: up to one TOTP step of waiting
    test.setTimeout(120_000);
    await signIn(page);
    await registerAndOpen(page, "/console/admin/reviews");
    await expect(page.getByRole("heading", { level: 2, name: "Access reviews" })).toBeVisible();
    const campaign = page
      .getByTestId("reviews")
      .getByRole("listitem")
      .filter({ hasText: REVIEW ?? "" });
    await expect(campaign).toContainText("Next review");
    await campaign.getByRole("button", { name: "To check" }).click();
    const items = page.getByTestId("review-items").getByRole("listitem");
    await expect(items.first()).toBeVisible();
    await expect(page.getByRole("button", { name: /remove all/i })).toHaveCount(0);
    await items.first().getByRole("button", { name: "Keep" }).click();
    await page
      .getByRole("dialog", { name: "Review and sign" })
      .getByRole("button", { name: "Sign" })
      .click();
    await expect(items.first()).toContainText("Checked: kept");
  });
});
