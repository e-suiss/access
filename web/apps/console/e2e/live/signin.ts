// OP-153 m.3 (gg), OP-149 m.26 (b), OP-159 m.47 (a), (g), (i), TN-128, TN-142: the console's sign-in as
// the Acme tenant's administrator at its management environment's own hosted login (identifier,
// password and a code of its authenticator app), the registration of this browser's device key
// there, and the first visit to the tenant's `acme` environment, which registers this browser's key
// in `acme` with one signature and no new sign-in. Every authority read and write needs those keys.
import { expect, type Page } from "@playwright/test";

import { nextStep, totp } from "./totp.js";

/** The tenant's management environment (deploy/compose/access/bootstrap.toml `[[tenant]]`). */
export const MANAGEMENT = "acme-admin";
export const IDENTIFIER = process.env["ACCESS_LIVE_ADMIN_IDENTIFIER"] ?? "admin@acme.example";
export const PASSWORD = process.env["ACCESS_LOCAL_TEST_PASSWORD"] ?? "";
const SEED = process.env["ACCESS_LIVE_ADMIN_TOTP_SEED"] ?? "";

/** Whether the administrator's password and authenticator app seed are given. */
export const READY = PASSWORD !== "" && SEED !== "";

/** Why a spec that signs in is skipped without them. */
export const NOT_READY =
  "ACCESS_LOCAL_TEST_PASSWORD and ACCESS_LIVE_ADMIN_TOTP_SEED name the Acme administrator's password and authenticator app seed";

/** The console's sign-in at the management environment's address (OP-159 m.42 (a), m.47 (a)). */
export async function signIn(page: Page): Promise<void> {
  await page.goto(`/console/${MANAGEMENT}`);
  await page.waitForURL(new RegExp(`/env/${MANAGEMENT}/login\\?`));
  await page.getByLabel("Email or username").fill(IDENTIFIER);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  const code = page.getByLabel("Code from your authenticator app");
  await code.waitFor();
  expect(SEED, NOT_READY).not.toBe("");
  await code.fill(totp(SEED, await nextStep()));
  await code.press("Enter");
  await page.waitForURL(new RegExp(`/console/${MANAGEMENT}(?:[/?#]|$)`));
}

async function sign(page: Page): Promise<void> {
  await page
    .getByRole("dialog", { name: "Review and sign" })
    .getByRole("button", { name: "Sign" })
    .click();
}

/**
 * Registers this browser's device key in the management environment, opens the tenant's `acme`
 * environment, registers the key there with one signature, and opens `path` in the same page.
 */
export async function registerAndOpen(page: Page, path: string): Promise<void> {
  await page.getByRole("button", { name: "Register this browser" }).click();
  await sign(page);
  await expect(page.getByRole("heading", { level: 1, name: "Your tenant" })).toBeVisible();
  await page
    .getByTestId("tenant-environments")
    .getByRole("link", { name: "acme", exact: true })
    .click();
  await page.getByRole("button", { name: "Register and open acme" }).click();
  await sign(page);
  await expect(page.getByTestId("device-state")).toContainText("Device key registered");
  await expect(
    page.getByRole("navigation", { name: "Console sections" }).getByRole("link", { name: "Admin" }),
  ).toBeVisible();
  await page.evaluate((p) => {
    history.pushState(null, "", p);
    dispatchEvent(new PopStateEvent("popstate"));
  }, path);
}
