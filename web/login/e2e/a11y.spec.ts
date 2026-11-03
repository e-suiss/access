import AxeBuilder from "@axe-core/playwright";

import { expect, test } from "./fixtures.js";

// OP-83
const wcag22aa = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];

test("every login step has no WCAG 2.2 AA violations", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByLabel("Email or username")).toBeVisible();
  expect((await new AxeBuilder({ page }).withTags(wcag22aa).analyze()).violations).toEqual([]);

  await page.getByLabel("Email or username").fill("ada@example.org");
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByLabel("Password").fill("not it");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.getByRole("alert")).not.toBeEmpty();
  expect((await new AxeBuilder({ page }).withTags(wcag22aa).analyze()).violations).toEqual([]);
});
