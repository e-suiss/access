import AxeBuilder from "@axe-core/playwright";
import type { Page } from "@playwright/test";

import { open } from "./data.js";
import { expect, test } from "./fixtures.js";

const BASE = "http://127.0.0.1:4173";

// OP-83
const wcag22aa = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];

async function clean(page: Page) {
  expect((await new AxeBuilder({ page }).withTags(wcag22aa).analyze()).violations).toEqual([]);
}

test("sign-in has no WCAG 2.2 AA violations", async ({ page }) => {
  await page.goto("/console/");
  await expect(page.getByLabel("Realm")).toBeVisible();
  await clean(page);
});

test("every signed-in screen and the signature screen have no WCAG 2.2 AA violations", async ({
  page,
  context,
  bff,
}) => {
  await bff.signIn(context, BASE);
  await page.goto("/console/");
  await expect(page.getByTestId("device-state")).toBeVisible();
  await clean(page);
  await page.getByRole("button", { name: "Register this browser" }).click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await clean(page);
  await page.getByRole("dialog").getByRole("button", { name: "Cancel" }).click();
  for (const [path, heading] of [
    ["/console/profile", "Your profile"],
    ["/console/sessions", "Your sign-ins"],
    ["/console/about", "About"],
  ] as const) {
    await page.goto(path);
    await expect(page.getByRole("heading", { level: 1, name: heading })).toBeVisible();
    await expect(page.locator("[aria-busy=true]")).toHaveCount(0);
    await clean(page);
  }
});

const SCREENS = [
  ["admin/roles", "Roles & templates"],
  ["admin/people", "People & agents"],
  ["admin/sources", "Sources"],
  ["admin/restrictions", "Restrictions & requirements"],
  ["admin/protected", "Protected actions & break-glass"],
  ["admin/offboarding", "Offboarding"],
  ["admin/domain", "Domain"],
  ["admin/changes", "Changes"],
  ["admin/sign-in", "Sign-in settings"],
  ["developer/schemas", "Namespaces & schemas"],
  ["developer/integrations", "Integrations"],
  ["developer/lab", "Decision lab"],
  ["developer/logs", "Logs"],
  ["audit/records", "Records"],
  ["audit/replay", "Replay"],
  ["audit/revocation", "Revocation impact"],
  ["audit/unknown", "Unknown outcomes"],
  ["audit/export", "Export"],
] as const;

// OP-83: every Admin, Developer and Audit screen, with its answers shown
test("every section screen has no WCAG 2.2 AA violations", async ({ page, context, bff }) => {
  await bff.signIn(context, BASE);
  await open(page, bff, "/console/admin/roles");
  for (const [path, heading] of SCREENS) {
    await page.evaluate((p) => {
      history.pushState(null, "", p);
      dispatchEvent(new PopStateEvent("popstate"));
    }, `/console/${path}`);
    await expect(page.getByRole("heading", { level: 2, name: heading })).toBeVisible();
    await expect(page.locator("[aria-busy=true]")).toHaveCount(0);
    await clean(page);
    const show = page.locator("main form").getByRole("button", { name: "Show" }).first();
    if ((await show.count()) > 0) {
      await show.click();
      await expect(page.locator("[aria-busy=true]")).toHaveCount(0);
      await clean(page);
    }
  }
});
