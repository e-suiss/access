// §12.5.4, TN-127, OP-158 m.3 (v): Observability ▸ Rate limits over a mocked management answer;
// the counters are the server's (bins/access-server management limits tests).
import AxeBuilder from "@axe-core/playwright";

import { BASE, open } from "./data.js";
import { expect, test } from "./fixtures.js";

test.beforeEach(async ({ context, bff }) => {
  await bff.signIn(context, BASE);
  bff.admin.set("realms/acme/rate-limits", {
    realm: "acme",
    rate_limit_rps: 200,
    default: true,
    tenant_rps: 1000,
    burst_s: 2,
    usage: {
      buckets: [
        {
          name: "realm-request",
          now_percent: 92,
          average_1h_percent: 40,
          average_24h_percent: 12,
          above_threshold: true,
        },
        {
          name: "realm-write",
          now_percent: 4,
          average_1h_percent: 1,
          average_24h_percent: 0,
          above_threshold: false,
        },
      ],
      top_consumers: [{ consumer: "0123456789abcdef", requests: 1234 }],
      events: [{ kind: "quota-exceeded", last_hour: 3, last_day: 17 }],
      threshold_percent: 80,
    },
  });
});

// §12.5.4, TN-127
test("the rate limits screen shows each bucket, the heaviest consumers and the refusals", async ({
  page,
  bff,
}) => {
  await open(page, bff, "/console/admin/ratelimits");
  await expect(page.getByRole("heading", { level: 2, name: "Rate limits" })).toBeVisible();
  const realm = page.locator('[data-testid="rate-limits-bucket"][data-name="realm-request"]');
  await expect(realm).toContainText("92%");
  await expect(realm).toContainText("40%");
  await expect(realm).toContainText("12%");
  await expect(page.getByTestId("rate-limits-warning")).toContainText("Above 80% of the limit");
  await expect(page.getByTestId("rate-limits-consumers")).toContainText("1234 requests");
  await expect(page.getByTestId("rate-limits-events")).toContainText("quota-exceeded");
  await expect(page.getByTestId("rate-limits-events")).toContainText("Last 24 h: 17");
  expect(bff.writes).toEqual([]);
  const a11y = await new AxeBuilder({ page }).include("main").analyze();
  expect(a11y.violations).toEqual([]);
});
