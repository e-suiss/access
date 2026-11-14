// OP-153 m.3 (gg), (y), (z); S10, S11 (§8.5, X32, X36), TN-107, G50: the sign-in methods and the
// sign-ins list against the running local deployment, signed in once as its bootstrap test user
// through the hosted login's own API (signin.setup.ts).
import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

import { PASSWORD, REALM } from "./signin.js";

// @axe-core/playwright pins a newer playwright-core than @playwright/test; the page is the same

test.describe("@live sign-in methods and sign-ins", () => {
  test.skip(PASSWORD === "", "ACCESS_LOCAL_TEST_PASSWORD names the bootstrap test user's password");

  test("@live S11 lists the account's sign-in methods from the realm's own routes", async ({
    page,
  }) => {
    await page.goto(`${REALM}/account`);
    const methods = page.getByTestId("sign-in-methods");
    await expect(methods.getByTestId("password")).toContainText("A password is set.");
    await expect(methods.getByTestId("passkeys")).toBeVisible();
    // HL-19, OP-159 m.3 (ll)
    await expect(methods.getByTestId("passkey-no-pqc")).toHaveText(
      "Passkeys don't use post-quantum cryptography yet.",
    );
    await expect(methods.getByTestId("authenticator")).toBeVisible();
    await expect(page.getByTestId("linked-sign-ins")).toBeVisible();
    await expect(page.getByTestId("connected-apps")).toBeVisible();
  });

  test("@live a password change is refused and the sign-in kept while no breach corpus can check it", async ({
    page,
  }) => {
    await page.goto(`${REALM}/account`);
    const password = page.getByTestId("password");
    await password.getByRole("button", { name: "Change password" }).click();
    await password.getByLabel("New password").fill(PASSWORD);
    await password.getByRole("button", { name: "Save" }).click();
    await expect(page.getByTestId("sign-in-methods").getByTestId("said-alert")).toHaveText(
      "That didn't work. Try again.",
    );
    expect(page.url()).not.toContain("/login");
    expect((await page.request.get(`${REALM}/account/api/session`)).status()).toBe(200);
  });

  test("@live S10 shows this device's sign-in with its end time and no End button", async ({
    page,
  }) => {
    await page.goto(`${REALM}/account`);
    const here = page.locator('[data-testid="sign-in-row"][data-current="true"]');
    await expect(here.locator("strong")).toHaveText("Sign-in on this device");
    await expect(here).toContainText("Signed in until");
    await expect(here.getByRole("button", { name: /End this sign-in/ })).toHaveCount(0);
    await expect(page.getByText(/trusted/i)).toHaveCount(0);
  });

  test("@live the account page passes axe with S10 and S11 drawn", async ({ page }) => {
    await page.goto(`${REALM}/account`);
    await expect(page.getByTestId("sign-in-row").first()).toBeVisible();
    const result = await new AxeBuilder({ page: page })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
      .analyze();
    expect(result.violations.map((v) => v.id)).toEqual([]);
  });
});
