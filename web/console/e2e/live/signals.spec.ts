// OP-156 m.3 (r), OP-153 m.3 (gg): the signal sources route against the running local
// deployment, through its real BFF on the management listener. It answers nothing without a
// session, no write reaches it unsigned, and the panel is not shown without eligibility.
import { expect, test } from "@playwright/test";

test.describe("@live console signal sources", () => {
  test("@live the signal sources route reads and writes nothing without a session", async ({
    page,
  }) => {
    const list = await page.request.get("/console/api/proxy/admin/realms/acme/signal-sources");
    expect([401, 403]).toContain(list.status());
    const write = await page.request.post("/console/api/proxy/admin/realms/acme/signal-sources", {
      data: { name: "acme-mdm", kind: "mdm", provider: "Acme MDM", issuer: "x" },
    });
    expect([401, 403]).toContain(write.status());
  });

  test("@live the signal sources panel is not offered without the viewer's eligibility", async ({
    page,
  }) => {
    const r = await page.goto("/console/admin/sign-in");
    expect(r?.status()).toBe(200);
    await expect(page.getByRole("region", { name: "Signal sources" })).toHaveCount(0);
  });
});
