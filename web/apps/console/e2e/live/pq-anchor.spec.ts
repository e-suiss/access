// RR-35, OP-159 m.3 (g), (j), OP-158 m.3 (n), OP-153 m.3 (gg): the durability read with its
// post-quantum anchor line against the running local deployment. The bootstrap test user cannot
// exercise idp.realm.dr_profile, so even signed in the screen is not offered (IA-5); the anchor
// text itself is covered by the mocked placement spec.
import { expect, test } from "@playwright/test";

import { PASSWORD, registerAndOpen, signIn } from "./signin.js";

test.describe("@live console post-quantum anchor", () => {
  test("@live the durability read answers nothing without a session", async ({ page }) => {
    const read = await page.request.get("/console/api/proxy/admin/realms/acme/durability");
    expect([401, 403]).toContain(read.status());
  });

  test("@live the signed-in test user is not offered the durability screen or its anchor line", async ({
    page,
  }) => {
    test.skip(PASSWORD === "", "ACCESS_LOCAL_TEST_PASSWORD names the bootstrap test user");
    // TN-59: up to one TOTP step of waiting
    test.setTimeout(120_000);
    await signIn(page);
    await registerAndOpen(page, "/console/admin/durability");
    await expect(page.getByTestId("durability")).toHaveCount(0);
    await expect(page.getByTestId("durability-pq-anchor")).toHaveCount(0);
  });
});
