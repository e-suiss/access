// IDP-39 (3), LFP-18, OP-157 m.3 (w), m.6 (a): the console's access review screen over mocked
// management answers; the rules are the server's (bins/access-server idp review tests).
import AxeBuilder from "@axe-core/playwright";

import { BASE, open } from "./data.js";
import { expect, test } from "./fixtures.js";

const KEEP = "S2VlcEtlZXBLZWVwS2VlcA";
const DROP = "RHJvcERyb3BEcm9wRHJvcA";
const MANAGER = "TWFuYWdlck1hbmFnZXJNYQ";

const item = (grant: string, holder: string) => ({
  review: "q4",
  grant,
  holder: { party: holder },
  actions: [{ namespace: "payroll", name: "read", major: 1 }],
  resource: { namespace: "payroll.record" },
  valid_until: null,
  since: "7",
  issued_by: MANAGER,
  delegable: false,
  derived: 0,
  remove: {
    operation: "revokeGrant",
    basis: { holding: { grant: "VGVhbVRlYW1UZWFtVGVhbQ", holder: MANAGER, since: 5 } },
  },
});

test.beforeEach(async ({ context, bff }) => {
  await bff.signIn(context, BASE);
  bff.admin.set("realms/acme/reviews", {
    items: [
      {
        name: "q4",
        period_days: 90,
        scope: "manager_team",
        status: "live",
        started_at: "2026-11-01T00:00:00Z",
        next_run: "2027-01-30T00:00:00Z",
        version: 1,
      },
    ],
  });
  bff.admin.set("realms/acme/reviews/q4/items", {
    items: [item(KEEP, "WGF2aVhhdmlYYXZpWGF2aQ"), item(DROP, "WWFyYVlhcmFZYXJhWWFyYQ")],
  });
});

// OP-157 m.3 (w), m.6 (a), §8.17.9.8
test("keep records a check and remove is the reviewer's own revoke of one Grant", async ({
  page,
  bff,
}) => {
  await open(page, bff, "/console/admin/reviews");
  await expect(page.getByRole("heading", { level: 2, name: "Access reviews" })).toBeVisible();
  await expect(page.getByTestId("reviews")).toContainText("Next review");
  expect(bff.writes).toEqual([]);
  await page.getByRole("button", { name: "To check" }).click();
  const items = page.getByTestId("review-items").getByRole("listitem");
  await expect(items).toHaveCount(2);
  await expect(page.getByText("Each Grant is removed on its own")).toBeVisible();
  await expect(page.getByRole("button", { name: /remove all/i })).toHaveCount(0);

  await items.first().getByRole("button", { name: "Keep" }).click();
  await page
    .getByRole("dialog", { name: "Review and sign" })
    .getByRole("button", { name: "Sign" })
    .click();
  await expect(items.first()).toContainText("Checked: kept");
  expect(bff.writes.map((w) => [w.method, w.path])).toEqual([
    ["POST", `realms/acme/reviews/q4/items/${KEEP}/keep`],
  ]);
  expect(bff.metaCommits).toEqual([]);

  await items.nth(1).getByRole("button", { name: "Remove" }).click();
  await page
    .getByRole("dialog", { name: "Review and sign" })
    .getByRole("button", { name: "Sign" })
    .click();
  await expect(page.getByRole("status").last()).toContainText("Recorded as change");
  expect(bff.metaCommits).toEqual([
    { action: "grant_revoke", payload: { grant_revoke: { grant: DROP } } },
  ]);

  const result = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(result.violations.map((v) => `${v.id}: ${v.help}`)).toEqual([]);
});

// OP-157 m.6 (f)
test("scheduling names a period and the manager's team", async ({ page, bff }) => {
  await open(page, bff, "/console/admin/reviews");
  await page.getByLabel("Name").fill("q1");
  await page.getByLabel("Every (days)").fill("30");
  await page.getByRole("button", { name: "Schedule a review" }).click();
  await page
    .getByRole("dialog", { name: "Review and sign" })
    .getByRole("button", { name: "Sign" })
    .click();
  await expect(page.getByRole("status")).toContainText("Recorded as change");
  expect(bff.writes[0]).toMatchObject({
    method: "POST",
    path: "realms/acme/reviews",
    body: { name: "q1", period_days: 30, scope: "manager_team" },
  });
});
