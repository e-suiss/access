// RR-35, OP-159 m.3 (g), (j), OP-153 m.3 (gg): the durability screen against the running local
// deployment. Its governing domain has never been re-anchored, so the screen says there is no
// post-quantum anchor yet, and it marks no witness the provider alone declared as counted.
import { expect, test } from "@playwright/test";

import { PASSWORD, registerAndOpen, signIn } from "./signin.js";

test.describe("@live console post-quantum anchor", () => {
  test("@live the durability read answers nothing without a session", async ({ page }) => {
    const read = await page.request.get("/console/api/proxy/admin/realms/acme/durability");
    expect([401, 403]).toContain(read.status());
  });

  test("@live the durability screen says there is no post-quantum anchor yet", async ({ page }) => {
    test.skip(PASSWORD === "", "ACCESS_LOCAL_TEST_PASSWORD names the bootstrap test user");
    // TN-59: up to one TOTP step of waiting
    test.setTimeout(120_000);
    await signIn(page);
    await registerAndOpen(page, "/console/admin/durability");
    await expect(page.getByTestId("durability-pq-anchor")).toHaveText("No post-quantum anchor yet");
  });
});
