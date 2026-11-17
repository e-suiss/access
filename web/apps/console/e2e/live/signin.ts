// OP-153 m.3 (gg), OP-149 m.26 (b), OP-159 m.47 (a), (g), (i), m.49, TN-128, TN-142: the console's
// sign-in as the Acme tenant's administrator at its primary environment `acme`'s own hosted login
// (identifier, password and a code of its authenticator app) and the registration of this browser's
// device key there with one signature. Every authority read and write needs that key.
import { expect, type Page } from "@playwright/test";

import { nextStep, totp } from "./totp.js";

/** The tenant's primary environment (deploy/compose/access/bootstrap.toml `[[tenant]]`). */
export const PRIMARY = "acme";
export const IDENTIFIER = process.env["ACCESS_LIVE_ADMIN_IDENTIFIER"] ?? "admin@acme.example";
export const PASSWORD = process.env["ACCESS_LOCAL_TEST_PASSWORD"] ?? "";
const SEED = process.env["ACCESS_LIVE_ADMIN_TOTP_SEED"] ?? "";

/** Whether the administrator's password and authenticator app seed are given. */
export const READY = PASSWORD !== "" && SEED !== "";

/** Why a spec that signs in is skipped without them. */
export const NOT_READY =
  "ACCESS_LOCAL_TEST_PASSWORD and ACCESS_LIVE_ADMIN_TOTP_SEED name the Acme administrator's password and authenticator app seed";

/** The console's sign-in at the primary environment's address (OP-159 m.42 (a), m.47 (a)). */
export async function signIn(page: Page): Promise<void> {
  await page.goto(`/console/${PRIMARY}`);
  await page.waitForURL(new RegExp(`/env/${PRIMARY}/login\\?`));
  await page.getByLabel("Email or username").fill(IDENTIFIER);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  const code = page.getByLabel("Code from your authenticator app");
  await code.waitFor();
  expect(SEED, NOT_READY).not.toBe("");
  await code.fill(totp(SEED, await nextStep()));
  await code.press("Enter");
  await page.waitForURL(new RegExp(`/console/${PRIMARY}(?:[/?#]|$)`));
}

async function sign(page: Page): Promise<void> {
  await page
    .getByRole("dialog", { name: "Review and sign" })
    .getByRole("button", { name: "Sign" })
    .click();
}

/**
 * Registers this browser's device key in the primary environment `acme` with one signature and
 * opens `path` in the same page.
 */
export async function registerAndOpen(page: Page, path: string): Promise<void> {
  await page.getByRole("button", { name: "Register this browser" }).click();
  await sign(page);
  await expect(page.getByRole("heading", { level: 1, name: "Your tenant" })).toBeVisible();
  await expect(
    page.getByRole("navigation", { name: "Console sections" }).getByRole("link", { name: "Admin" }),
  ).toBeVisible();
  await page.evaluate((p) => {
    history.pushState(null, "", p);
    dispatchEvent(new PopStateEvent("popstate"));
  }, path);
}
