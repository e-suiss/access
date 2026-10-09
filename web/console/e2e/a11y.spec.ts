import AxeBuilder from "@axe-core/playwright";

import { expect, test } from "./fixtures.js";

// OP-83
const wcag22aa = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];

test("console home has no WCAG 2.2 AA violations", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByTestId("kernel-api-version")).toHaveText("0.0");
  const results = await new AxeBuilder({ page }).withTags(wcag22aa).analyze();
  expect(results.violations).toEqual([]);
});
