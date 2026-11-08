// S2, S4, S5, S6, Changes (OP-153 m.3 (w), m.8 (e)): XI-3, XI-5, XI-10, XI-11, XI-15, XI-16,
// XI-19, G39, HL-5, TI-8, IA-2
import type { Page } from "@playwright/test";

import { expect, test } from "./fixtures.js";
import { type AccountMock, holding, PARTY } from "./mock.js";

async function setUp(page: Page, bff: AccountMock): Promise<void> {
  await page.goto("/account/authority");
  await page.getByRole("button", { name: "Set up this device" }).click();
  const dialog = page.getByRole("dialog", { name: "Check what you're signing" });
  await expect(dialog).toContainText("access.instance_create");
  await dialog.getByRole("button", { name: "Sign" }).click();
  await expect(page.getByTestId("hub")).toBeVisible();
  expect(bff.seen.some((s) => s.path.endsWith("/instances"))).toBe(true);
}

test.beforeEach(async ({ bff, context, baseURL }) => {
  await bff.signIn(context, baseURL ?? "");
  bff.searches.set("inventory", [
    holding("g-given"),
    holding("g-lapsed", { member: false }),
    holding("g-not-mine", { source: { holder: "someone-else", grant: "parent" } }),
    holding("g-held", { groups: ["your_authority"], holder: { party: PARTY } }),
    { type: "root", anchor: "root-anchor", sole: true },
  ]);
  bff.searches.set("activity", [
    {
      type: "use",
      pos: 3,
      at: 1_700_000_000_000,
      by_viewer: true,
      capacity: {},
      basis: { grant: "g-held" },
    },
    { type: "use", pos: 4, by_viewer: false, capacity: { for: "someone-else" } },
  ]);
  bff.searches.set("changes", [
    { type: "change", kind: "grant", id: "g-old", position: "5", ended: true, own: true },
    { type: "change", kind: "not_a_kind", id: "x", position: "6" },
  ]);
});

test("the device step-up is said plainly, with no way around it", async ({ page, bff }) => {
  bff.stepUp = true;
  await page.goto("/account/authority");
  await page.getByRole("button", { name: "Set up this device" }).click();
  await expect(page.getByTestId("device-message")).toHaveText(
    "Confirm it's you again, then set up this device.",
  );
  await expect(page.getByText(/remember/i)).toHaveCount(0);
});

test("every row says whose record it is, when it was read, and in whose name", async ({
  page,
  bff,
}) => {
  await setUp(page, bff);
  const shared = page.getByTestId("shared-from-you");
  await expect(shared.locator("li.row")).toHaveCount(3);
  for (const row of await shared.locator("li.row").all()) {
    await expect(row).toContainText("Recorded by Access");
    await expect(row).toContainText("As of");
    await expect(row).toContainText("for their own use");
  }
  await expect(page.getByTestId("your-authority")).toContainText("as yourself");
  await expect(shared.locator('[data-grant="g-lapsed"]')).toContainText(
    "Needs refresh — not removed",
  );
  await expect(shared.locator('[data-grant="g-not-mine"]')).toContainText(
    "Who can: the person who gave it",
  );
  await expect(page.getByText("Not shown: places you haven't connected")).toBeVisible();
  const reads = bff.seen.filter((s) => s.path.includes("/proxy/adp/search/"));
  expect(reads.length).toBeGreaterThanOrEqual(3);
  expect(reads.every((s) => typeof (s.body["context"] as { ais?: unknown }).ais === "string")).toBe(
    true,
  );
});

test("Why? says where a holding comes from, as recorded, with details on request", async ({
  page,
  bff,
}) => {
  await setUp(page, bff);
  const row = page.getByTestId("shared-from-you").locator('[data-grant="g-given"]');
  await row.getByRole("button", { name: "Why?" }).click();
  const why = row.getByTestId("why");
  await expect(why).toContainText("From the decision record");
  await expect(why).toContainText("Given from an authority root you hold");
  await why.getByRole("button", { name: "Details" }).click();
  await expect(why).toContainText("grant g-given");
});

test("revoke takes two steps and is done only once Access recorded it", async ({ page, bff }) => {
  await setUp(page, bff);
  bff.searches.set("revocation-impact", [
    { type: "revocation_impact", subtree: ["g-given", "child"] },
  ]);
  const row = page.getByTestId("shared-from-you").locator('[data-grant="g-given"]');
  await row.getByRole("button", { name: "Revoke" }).click();
  const panel = row.getByTestId("revoke");
  await expect(panel.getByTestId("impact")).toHaveText("Delegations given from it that end too: 1");
  await expect(panel).toContainText("access.grant_revoke");
  await panel.getByRole("button", { name: "Revoke" }).click();
  const after = row.getByTestId("aftermath");
  await expect(after.getByTestId("outcome")).toHaveText("Done");
  await expect(after).toContainText("Recorded at position 42");
  await expect(after).toContainText("Uses made before stay in the record.");
});

test("a lost answer is not confirmed; the retry sends the same signed request", async ({
  page,
  bff,
}) => {
  await setUp(page, bff);
  bff.evaluations.push("abort", "allow");
  const row = page.getByTestId("shared-from-you").locator('[data-grant="g-given"]');
  await row.getByRole("button", { name: "Revoke" }).click();
  await row.getByTestId("revoke").getByRole("button", { name: "Revoke" }).click();
  const after = row.getByTestId("aftermath");
  await expect(after.getByTestId("outcome")).toHaveText("Not confirmed — checking");
  await expect(after).not.toContainText("Done");
  await expect(after).not.toContainText("Not recorded");
  await after.getByRole("button", { name: "Read again" }).click();
  await expect(after.getByTestId("outcome")).toHaveText("Done");
  expect(bff.nonces).toHaveLength(2);
  expect(bff.nonces[0]).toBe(bff.nonces[1]);
});

test("Activity is a record of uses and Changes are information only", async ({ page, bff }) => {
  await setUp(page, bff);
  await page.getByRole("link", { name: "Activity" }).click();
  const activity = page.getByTestId("activity");
  await expect(activity).toContainText("A refused request is not a use.");
  await expect(activity.locator("li.row")).toHaveCount(1);
  await expect(activity).toContainText("You used this");
  await page.getByRole("link", { name: "Changes" }).click();
  const changes = page.getByTestId("changes");
  await expect(changes).toContainText("Nothing here asks you to act.");
  await expect(changes.locator("li.row")).toHaveCount(1);
  await expect(changes).toContainText("A delegation ended");
  await expect(changes.getByRole("button")).toHaveCount(0);
});
