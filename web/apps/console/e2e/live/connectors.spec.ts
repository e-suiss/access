// §18.3, OP-156 m.3 (x), OP-153 m.3 (gg), Ek B 5238: the connectors catalogue against the running
// local deployment. It lives under Developer ▸ Integrations, which is offered only to a viewer
// who can exercise it, and it calls no route of its own.
import { expect, test } from "@playwright/test";

test.describe("@live console enterprise connectors", () => {
  test("@live the catalogue is not offered without the viewer's eligibility", async ({ page }) => {
    const asked: string[] = [];
    page.on("request", (r) => asked.push(new URL(r.url()).pathname));
    const r = await page.goto("/console/developer/integrations");
    expect(r?.status()).toBe(200);
    await expect(page.getByRole("region", { name: "Enterprise connectors" })).toHaveCount(0);
    expect(asked.filter((p) => p.includes("connector"))).toEqual([]);
  });
});
