// OP-156 m.3 (s), OP-153 m.3 (gg): the export sinks route against the running local deployment,
// through its real BFF on the management listener. It answers nothing without a session or this
// browser's device key, no write reaches it unsigned, and the screen is not offered to a viewer
// who cannot exercise it.
import { expect, test } from "@playwright/test";

test.describe("@live console SIEM export", () => {
  test("@live the export sinks route reads and writes nothing without a session", async ({
    page,
  }) => {
    const list = await page.request.get("/console/api/proxy/admin/realms/acme/export-sinks");
    expect([401, 403]).toContain(list.status());
    const write = await page.request.post("/console/api/proxy/admin/realms/acme/export-sinks", {
      data: { name: "splunk", adapter: "otlp", endpoint: "https://otel.example/v1/logs" },
    });
    expect([401, 403]).toContain(write.status());
    const retire = await page.request.post(
      "/console/api/proxy/admin/realms/acme/export-sinks/splunk/retire",
      { data: {} },
    );
    expect([401, 403]).toContain(retire.status());
  });

  test("@live the SIEM export screen is not offered without the viewer's eligibility", async ({
    page,
  }) => {
    const r = await page.goto("/console/admin/siem");
    expect(r?.status()).toBe(200);
    await expect(page.getByRole("region", { name: "Export sinks" })).toHaveCount(0);
  });
});
