// TN-114, OP-157 m.3 (t), OP-153 m.3 (gg): the delegated-admin setting against the running local
// deployment, through its real BFF on the management listener: no write without a session.
import { expect, test } from "@playwright/test";

test.describe("@live console delegated administration", () => {
  test("@live the setting changes nothing without a session", async ({ page }) => {
    const put = await page.request.put(
      "/console/api/proxy/admin/realms/acme/settings/delegated-admin",
      { data: { enabled: true } },
    );
    expect([401, 403]).toContain(put.status());
  });
});
