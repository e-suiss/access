// OP-156 m.3 (i), OP-153 m.3 (gg): the custom domains route against the running local
// deployment, through its real BFF on the management listener. Like every authority read it
// answers nothing without a session or this browser's device key, no write reaches it unsigned,
// and the panel is not shown on a screen the viewer cannot exercise.
import { expect, test } from "@playwright/test";

test.describe("@live console custom domains", () => {
  test("@live the custom domains route reads and writes nothing without a session", async ({
    page,
  }) => {
    const list = await page.request.get("/console/api/proxy/admin/realms/acme/domains");
    expect([401, 403]).toContain(list.status());
    const one = await page.request.get(
      "/console/api/proxy/admin/realms/acme/domains/login.acme.example",
    );
    expect([401, 403]).toContain(one.status());
    const write = await page.request.post("/console/api/proxy/admin/realms/acme/domains", {
      data: { host: "login.acme.example" },
    });
    expect([401, 403]).toContain(write.status());
  });

  test("@live the custom domains panel is not offered without the viewer's eligibility", async ({
    page,
  }) => {
    const r = await page.goto("/console/admin/sign-in");
    expect(r?.status()).toBe(200);
    await expect(page.getByRole("region", { name: "Custom domains" })).toHaveCount(0);
  });
});
