// S10 (§8.5, §8.10, §12.2.1; X36, X33, MD-13, OP-153 m.3 (y))
import type { Page } from "@playwright/test";

import { expect, test } from "./fixtures.js";
import type { AccountMock } from "./mock.js";

test.beforeEach(async ({ bff, context, baseURL }) => {
  await bff.signIn(context, baseURL ?? "");
});

function rows(page: Page) {
  return page.getByTestId("sign-ins").getByTestId("sign-in-row");
}

/** Sets this browser up as a device through the hub; the BFF's session then names its key. */
async function setUpDevice(page: Page, bff: AccountMock): Promise<void> {
  await page.goto("/account/authority");
  await page.getByRole("button", { name: "Set up this device" }).click();
  await page
    .getByRole("dialog", { name: "Check what you're signing" })
    .getByRole("button", { name: "Sign" })
    .click();
  await expect(page.getByTestId("hub")).toBeVisible();
  bff.instanceKid = await page.evaluate(
    () =>
      new Promise<string>((resolve, reject) => {
        const open = indexedDB.open("access-account", 1);
        open.onsuccess = () => {
          const keys = open.result.transaction("instances").objectStore("instances").getAllKeys();
          keys.onsuccess = () => {
            resolve((keys.result[0] as string).split("/").pop() ?? "");
          };
          keys.onerror = () => {
            reject(new Error("keys"));
          };
        };
      }),
  );
}

test("one row per sign-in on a device; identity and authority shown apart", async ({ page }) => {
  await page.goto("/account/");
  await expect(rows(page)).toHaveCount(2);
  const here = rows(page).nth(0);
  await expect(here.locator("strong")).toHaveText("Sign-in on this device");
  await expect(here).toContainText("Signed in until");
  await expect(here).toContainText("Stays signed in");
  await expect(here.getByTestId("bound")).toContainText("This sign-in is tied to this device");
  await expect(here.getByTestId("authority")).toHaveText(
    "This device holds no key for your authority.",
  );
  const phone = rows(page).nth(1);
  await expect(phone.locator("strong")).toHaveText("Sign-in on Phone");
  await expect(phone.getByTestId("authority")).toHaveText(
    "This device holds a key that can act for you.",
  );
  await expect(page.getByText(/trusted/i)).toHaveCount(0);
});

test("the expert view says device-bound or not bound", async ({ page }) => {
  await page.goto("/account/");
  await expect(page.getByTestId("binding")).toHaveCount(0);
  await page.getByLabel("Show details").check();
  await expect(rows(page).nth(0).getByTestId("binding")).toHaveText("device-bound");
  await expect(rows(page).nth(1).getByTestId("binding")).toHaveText("not bound");
});

test("End this sign-in is only on other devices and never one button with Sign out", async ({
  page,
}) => {
  await page.goto("/account/");
  const here = rows(page).nth(0);
  await expect(here.getByRole("button", { name: "Sign out", exact: true })).toBeVisible();
  await expect(here.getByRole("button", { name: /End this sign-in/ })).toHaveCount(0);
  const phone = rows(page).nth(1);
  await expect(phone.getByRole("button", { name: "Sign out", exact: true })).toHaveCount(0);
  await expect(phone.getByRole("button", { name: "End this sign-in: Phone" })).toBeVisible();
});

test("ending a sign-in without this device's key says the key stays", async ({ page, bff }) => {
  await page.goto("/account/");
  await page.getByRole("button", { name: "End this sign-in: Phone" }).click();
  await expect(page.getByTestId("sign-ins").getByTestId("said")).toContainText(
    "That device's key still acts for you",
  );
  await expect(rows(page)).toHaveCount(1);
  expect(bff.seen.some((s) => s.path.endsWith("/v1/sessions/ses_phone/end"))).toBe(true);
  expect(bff.seen.some((s) => s.path.includes("/v1/me/instances/"))).toBe(false);
});

test("ending a sign-in with this device's key ends that device's key after signing", async ({
  page,
  bff,
}) => {
  await setUpDevice(page, bff);
  await page.goto("/account/");
  await page.getByRole("button", { name: "End this sign-in: Phone" }).click();
  const dialog = page.getByRole("dialog", { name: "Check what you're signing" });
  await expect(dialog).toContainText("access.instance_terminate");
  await dialog.getByRole("button", { name: "Sign" }).click();
  await expect(page.getByTestId("sign-ins").getByTestId("said")).toHaveText(
    "Sign-in ended. That device's key no longer acts for you.",
  );
  const del = bff.seen.find((s) => s.path.endsWith("/v1/me/instances/aW5zdGFuY2Vfb3RoZXI"));
  expect(typeof del?.body["ais"]).toBe("string");
  expect(typeof del?.body["valid_until"]).toBe("string");
});

test("signing out everywhere says what stays connected (§8.10)", async ({ page }) => {
  await page.goto("/account/");
  await page.getByRole("button", { name: "Sign out everywhere" }).click();
  const done = page.getByTestId("signed-out-everywhere");
  await expect(done).toContainText("Signed out on all devices.");
  await expect(done).toContainText(
    "Apps and agents you connected keep their access until you revoke it.",
  );
});

test("this device's own Sign out ends only this sign-in", async ({ page, bff }) => {
  await page.goto("/account/");
  await rows(page).nth(0).getByRole("button", { name: "Sign out", exact: true }).click();
  await expect(page.getByTestId("signed-out")).toBeVisible();
  expect(bff.seen.some((s) => s.path.endsWith("/v1/sessions/current/sign-out"))).toBe(true);
  expect(bff.seen.some((s) => s.path.endsWith("/sign-out-everywhere"))).toBe(false);
});
