// TI-17, HL-40, OP-158 m.3 (o), (p), OP-153 m.3 (gg): the placement and durability reads against
// the running local deployment, through its real BFF on the management listener. Like every
// management read they answer nothing without a session, and the screens are not offered to a
// viewer who cannot exercise idp.realm.residency or idp.realm.dr_profile.
import { expect, test } from "@playwright/test";

test.describe("@live console placement and durability", () => {
  test("@live the placement and durability reads answer nothing without a session", async ({
    page,
  }) => {
    for (const path of ["placement", "durability"]) {
      const read = await page.request.get(`/console/api/proxy/admin/realms/acme/${path}`);
      expect([401, 403]).toContain(read.status());
    }
    const rehome = await page.request.post("/console/api/proxy/admin/realms/acme/rehome", {
      data: { domain: "AAAA" },
    });
    expect([401, 403]).toContain(rehome.status());
  });

  test("@live the screens are not offered without the viewer's eligibility", async ({ page }) => {
    for (const screen of ["placement", "durability"]) {
      const r = await page.goto(`/console/admin/${screen}`);
      expect(r?.status()).toBe(200);
      await expect(page.getByTestId(screen)).toHaveCount(0);
    }
  });
});
