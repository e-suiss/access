// CR-41, CR-44, HL-27, OP-159 m.3 (o), (r), m.4 (a), OP-153 m.3 (gg): the signing read against the
// running local deployment. The bootstrap test user cannot exercise idp.realm.signing_profile, so
// even signed in the screen is not offered (IA-5); its content is covered by the mocked spec.
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

  test("@live the signed-in test user is not offered the signing screen", async ({ page }) => {
    test.skip(PASSWORD === "", "ACCESS_LOCAL_TEST_PASSWORD names the bootstrap test user");
    test.setTimeout(120_000);
    await signIn(page);
    await registerAndOpen(page, "/console/admin/signing");
    await expect(page.getByTestId("signing")).toHaveCount(0);
  });
});
