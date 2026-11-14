// OP-156 m.3 (s), X22: the console's SIEM export screen over mocked management answers; the
// projection's rules are the server's (bins/access-server bootstrap export walkthrough).
import AxeBuilder from "@axe-core/playwright";

import { BASE, open } from "./data.js";
import { expect, test } from "./fixtures.js";

test.beforeEach(async ({ context, bff }) => {
  await bff.signIn(context, BASE);
  bff.admin.set("realms/acme/export-sinks", {
    items: [
      {
        name: "splunk",
        adapter: "collector",
        preset: "splunk",
        format: null,
        endpoint: "https://hec.example/services/collector/event",
        has_secret: true,
        status: "live",
        record: "copy",
        delivery: {
          sent: "120",
          failures: 0,
          failing_since: null,
          last_error: null,
          last_sent_at: null,
        },
      },
      {
        name: "qradar",
        adapter: "syslog",
        preset: null,
        format: "leef",
        endpoint: "siem.example:6514",
        has_secret: false,
        status: "live",
        record: "copy",
        delivery: {
          sent: "80",
          failures: 4,
          failing_since: "2026-11-10T10:00:00Z",
          last_error: "unreachable",
          last_sent_at: null,
        },
      },
      {
        name: "old-lake",
        adapter: "s3_parquet",
        preset: null,
        format: null,
        endpoint: "https://s3.eu-central-1.amazonaws.com",
        has_secret: false,
        status: "retired",
        record: "copy",
        delivery: null,
      },
    ],
  });
});

// OP-156 m.3 (s), X22, OP-64
test("sinks are registered and retired only through signed changes", async ({ page, bff }) => {
  await open(page, bff, "/console/admin/siem");
  await expect(page.getByRole("heading", { level: 2, name: "SIEM export" })).toBeVisible();
  await expect(page.getByTestId("export-copy-note")).toContainText("a copy, not the record");
  const sinks = page.getByTestId("export-sinks");
  await expect(sinks).toContainText("120 events delivered");
  await expect(sinks).toContainText("Not accepting (unreachable); nothing is lost");
  await expect(sinks.getByRole("button", { name: "Retire old-lake" })).toHaveCount(0);
  expect(bff.writes).toEqual([]);

  await page.getByLabel("Name", { exact: true }).fill("datadog");
  await page.getByLabel("Destination").selectOption("collector:datadog");
  await page.getByLabel("Endpoint").fill("https://http-intake.logs.datadoghq.eu/api/v2/logs");
  await page.getByLabel("Secret", { exact: true }).fill("dd-key-from-the-vendor");
  await page.getByRole("button", { name: "Register", exact: true }).click();
  await page
    .getByRole("dialog", { name: "Review and sign" })
    .getByRole("button", { name: "Sign" })
    .click();
  await expect(page.getByRole("status")).toContainText("Recorded as change");
  await expect(page.getByLabel("Secret", { exact: true })).toHaveValue("");

  await sinks.getByRole("button", { name: "Retire qradar" }).click();
  await page
    .getByRole("dialog", { name: "Review and sign" })
    .getByRole("button", { name: "Sign" })
    .click();
  await expect(page.getByRole("status")).toContainText("Recorded as change");

  expect(bff.writes.map((w) => [w.method, w.path])).toEqual([
    ["POST", "realms/acme/export-sinks"],
    ["POST", "realms/acme/export-sinks/qradar/retire"],
  ]);
  expect(bff.writes[0]?.body).toMatchObject({
    name: "datadog",
    adapter: "collector",
    preset: "datadog",
    endpoint: "https://http-intake.logs.datadoghq.eu/api/v2/logs",
    settings: {},
  });

  const result = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(result.violations.map((v) => `${v.id}: ${v.help}`)).toEqual([]);
});
