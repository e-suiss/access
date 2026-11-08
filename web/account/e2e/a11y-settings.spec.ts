// TN-107, WCAG 2.2 AA (§12.4.3, SA-55, TN-108): axe on every S10/S11 view, also right to left.
import AxeBuilder from "@axe-core/playwright";
import type { Page } from "@playwright/test";

import { expect, test } from "./fixtures.js";

// @axe-core/playwright pins a newer playwright-core than @playwright/test; the page is the same
type AxePage = ConstructorParameters<typeof AxeBuilder>[0]["page"];

const TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];

async function axe(page: Page): Promise<void> {
  const result = await new AxeBuilder({ page: page as unknown as AxePage })
    .withTags(TAGS)
    .analyze();
  expect(result.violations.map((v) => `${v.id}: ${v.help}`)).toEqual([]);
}

test.beforeEach(async ({ bff, context, baseURL }) => {
  await bff.signIn(context, baseURL ?? "");
});

for (const dir of ["ltr", "rtl"] as const) {
  test(`S10 and S11 pass axe (${dir})`, async ({ page }) => {
    await page.goto("/account/");
    await expect(page.getByTestId("passkey-row")).toHaveCount(1);
    await expect(page.getByTestId("sign-in-row")).toHaveCount(2);
    await page.evaluate((d) => {
      document.documentElement.dir = d;
    }, dir);
    await axe(page);
  });

  test(`the open forms pass axe (${dir})`, async ({ page }) => {
    await page.goto("/account/");
    await page.evaluate((d) => {
      document.documentElement.dir = d;
    }, dir);
    await page.getByRole("button", { name: "Change password" }).click();
    await page.getByRole("button", { name: "Set up an authenticator app" }).click();
    await expect(page.getByTestId("totp-secret")).toBeVisible();
    await page.getByRole("button", { name: "Get new recovery codes" }).click();
    await expect(page.getByTestId("code-list")).toBeVisible();
    await page.getByLabel("Show details").check();
    await axe(page);
  });
}

test("the signed-out-everywhere text passes axe", async ({ page }) => {
  await page.goto("/account/");
  await page.getByRole("button", { name: "Sign out everywhere" }).click();
  await expect(page.getByTestId("signed-out-everywhere")).toBeVisible();
  await axe(page);
});
