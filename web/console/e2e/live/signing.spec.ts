// CR-41, CR-44, HL-27, OP-159 m.3 (o), (r), m.4 (a), OP-153 m.3 (gg)
import { expect, test } from "@playwright/test";

import { PASSWORD, registerAndOpen, signIn } from "./signin.js";

test.describe("@live console signing", () => {
  test("@live the signing read and writes answer nothing without a session", async ({ page }) => {
    const read = await page.request.get("/console/api/proxy/admin/realms/acme/signing");
    expect([401, 403]).toContain(read.status());
    const write = await page.request.put(
      "/console/api/proxy/admin/realms/acme/settings/signing-profile",
      { data: {} },
    );
    expect([401, 403]).toContain(write.status());
  });

  test("@live the signing screen shows the bootstrap's post-quantum profile", async ({ page }) => {
    test.skip(PASSWORD === "", "ACCESS_LOCAL_TEST_PASSWORD names the bootstrap test user");
    test.setTimeout(120_000);
    await signIn(page);
    await registerAndOpen(page, "/console/admin/signing");
    await expect(page.locator("#signing-profile-title")).toHaveText(
      "Post-quantum signatures on (ML-DSA-65)",
    );
    await expect(page.getByTestId("signing-algorithms")).toContainText("ML-DSA-65");
    await expect(page.getByTestId("signing-fips-module")).toHaveText(
      "FIPS 140-3 module: not in use",
    );
    await expect(page.locator("main")).not.toContainText("validated");
  });
});
