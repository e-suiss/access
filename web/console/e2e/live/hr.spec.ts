// OP-156 m.3 (q), OP-153 m.3 (gg): the HR routes against the running local deployment, through
// its real BFF on the management listener. Like every authority read they answer nothing
// without a session or this browser's device key, no import reaches them unsigned, and the
// screen is not offered to a viewer who cannot exercise it.
import { expect, test } from "@playwright/test";

test.describe("@live console HR", () => {
  test("@live the HR routes read and write nothing without a session", async ({ page }) => {
    const sources = await page.request.get("/console/api/proxy/admin/realms/acme/hr-sources");
    expect([401, 403]).toContain(sources.status());
    const connectors = await page.request.get("/console/api/proxy/admin/realms/acme/hr-connectors");
    expect([401, 403]).toContain(connectors.status());
    const content = "employee_id,email\nE1,ada@acme.example\n";
    const write = await page.request.post(
      "/console/api/proxy/admin/realms/acme/hr-sources/workday/records:csv",
      { data: { file: "x", records: 1, content } },
    );
    expect([401, 403]).toContain(write.status());
  });

  test("@live the HR screen is not offered without the viewer's eligibility", async ({ page }) => {
    const r = await page.goto("/console/admin/hr");
    expect(r?.status()).toBe(200);
    await expect(page.getByRole("region", { name: "HR sources" })).toHaveCount(0);
  });
});
