// OP-153 m.3 (gg), OP-149 m.26 (b), TN-128: the console's sign-in at the realm's own hosted login
// as the bootstrap test user (identifier, password and a code of its authenticator app), and the
// registration of this browser's device key, which every authority read and write needs.
import { expect, type Page } from "@playwright/test";

import { nextStep, totp } from "./totp.js";

export const IDENTIFIER = process.env["ACCESS_LIVE_IDENTIFIER"] ?? "test@acme.example";
export const PASSWORD = process.env["ACCESS_LOCAL_TEST_PASSWORD"] ?? "";
const SEED = process.env["ACCESS_LIVE_TEST_TOTP_SEED"] ?? "";

/** The console's sign-in from its own button: the realm's authorize, then the hosted login. */
export async function signIn(page: Page): Promise<void> {
  await page.goto("/console");
  await page.getByLabel("Realm").fill("acme");
  await page.getByRole("button", { name: "Continue to sign-in" }).click();
  await page.waitForURL(/\/realms\/acme\/login\?/);
  await page.getByLabel("Email or username").fill(IDENTIFIER);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  const code = page.getByLabel("Code from your authenticator app");
  await code.waitFor();
  expect(SEED, "ACCESS_LIVE_TEST_TOTP_SEED names the test user's authenticator app seed").not.toBe(
    "",
  );
  await code.fill(totp(SEED, await nextStep()));
  await code.press("Enter");
  await page.waitForURL(/\/console(?:[?#]|$)/);
}

/** Registers this browser's device key, signed on the console's signature screen, and opens
 * `path` in the same page. */
export async function registerAndOpen(page: Page, path: string): Promise<void> {
  await page.getByRole("button", { name: "Register this browser" }).click();
  await page
    .getByRole("dialog", { name: "Review and sign" })
    .getByRole("button", { name: "Sign" })
    .click();
  await expect(page.getByTestId("device-state")).toContainText("Device key registered");
  await expect(
    page.getByRole("navigation", { name: "Console sections" }).getByRole("link", { name: "Admin" }),
  ).toBeVisible();
  await page.evaluate((p) => {
    history.pushState(null, "", p);
    dispatchEvent(new PopStateEvent("popstate"));
  }, path);
}
