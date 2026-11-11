// OP-157 m.3 (cc), (f), OP-153 m.3 (gg), §8.16, TN-137: the support access page against the running
// local deployment. The local bootstrap seeds no support operator, so the page is checked as a
// person with no request reads it; a request's own path is the server's real-path test.
import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { PASSWORD, REALM, signIn } from "./signin.js";

type AxePage = ConstructorParameters<typeof AxeBuilder>[0]["page"];

async function axe(page: Page): Promise<void> {
  const result = await new AxeBuilder({ page: page as unknown as AxePage })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(result.violations.map((v) => `${v.id}: ${v.help}`)).toEqual([]);
}

test.describe("@live support access", () => {
  test.skip(PASSWORD === "", "ACCESS_LOCAL_TEST_PASSWORD names the bootstrap test user's password");
  test.use({ storageState: { cookies: [], origins: [] } });

  test("@live the person's support page answers, blocks and is accessible", async ({
    page,
    baseURL,
  }) => {
    // TN-59: up to one TOTP step of waiting
    test.setTimeout(120_000);
    await signIn(page.request, baseURL ?? "");
    await page.goto(`${REALM}/account/authority`);
    await page.getByRole("button", { name: "Set up this device" }).click();
    await page
      .getByRole("dialog", { name: "Check what you're signing" })
      .getByRole("button", { name: "Sign" })
      .click();
    await expect(page.getByTestId("hub")).toBeVisible();
    await page.goto(`${REALM}/account/support`);
    await expect(page.getByTestId("support-access")).toBeVisible();
    await axe(page);
    await page.getByTestId("support-block").click();
    await expect(page.getByText("Support teams can't ask for access")).toBeVisible();
    await page.getByTestId("support-block").click();
    await expect(page.getByText("Support teams can't ask for access")).toHaveCount(0);
  });
});
