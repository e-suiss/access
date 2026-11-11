// OP-157 m.3 (w), m.6 (i), XI-19, §8.17.12, OP-153 m.3 (gg): inventory hygiene against the running
// local deployment, signed in once as its bootstrap test user (signin.setup.ts). The test user
// gave the bootstrap's sample agent a Grant over the sample's whole namespace, a broad delegation,
// so the person's Changes count it as a suggestion that offers no action and changes nothing.
import { expect, test } from "@playwright/test";

import { PASSWORD, REALM } from "./signin.js";

test.describe("@live inventory hygiene", () => {
  test.skip(PASSWORD === "", "ACCESS_LOCAL_TEST_PASSWORD names the bootstrap test user's password");

  // XI-19, Ek B 5566
  test("@live the person's Changes count the broad delegation as a suggestion only", async ({
    page,
  }) => {
    await page.goto(`${REALM}/account/authority`);
    await page.getByRole("button", { name: "Set up this device" }).click();
    await page
      .getByRole("dialog", { name: "Check what you're signing" })
      .getByRole("button", { name: "Sign" })
      .click();
    await expect(page.getByTestId("hub")).toBeVisible();
    await page.getByRole("link", { name: "Changes" }).click();
    const hygiene = page.getByTestId("hygiene");
    await expect(hygiene).toContainText(
      /\d+ broad delegations: any resource, or they can be passed on/,
    );
    await expect(hygiene).not.toContainText("not used for 90 days");
    await expect(hygiene).toContainText("A suggestion only. Nothing changes until you act.");
    await expect(hygiene.getByRole("button")).toHaveCount(0);
  });
});
