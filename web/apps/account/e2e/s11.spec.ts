// S11 (§8.5, X32; TN-99, TN-64, TN-68, TN-107, X29, §8.13, OP-153 m.3 (m), (z))
import type { Page } from "@playwright/test";

import { expect, test } from "./fixtures.js";

test.beforeEach(async ({ bff, context, baseURL }) => {
  await bff.signIn(context, baseURL ?? "");
});

async function stubPasskeys(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const fake = { toJSON: () => ({ id: "bmV3", type: "public-key", response: {} }) };
    Object.defineProperty(PublicKeyCredential, "parseCreationOptionsFromJSON", {
      value: (o: unknown) => o,
    });
    Object.defineProperty(navigator.credentials, "create", {
      value: () => Promise.resolve(fake),
    });
  });
}

function said(page: Page) {
  return page.getByTestId("sign-in-methods").getByTestId("said");
}

function alerted(page: Page) {
  return page.getByTestId("sign-in-methods").getByTestId("said-alert");
}

test("passkeys are created, seen and removed here (TN-99)", async ({ page, bff }) => {
  await stubPasskeys(page);
  await page.goto("/account/");
  const passkeys = page.getByTestId("passkeys");
  await expect(passkeys.getByTestId("passkey-row")).toHaveCount(1);
  await expect(passkeys).toContainText("Laptop");
  await expect(passkeys).toContainText("Available on your synced devices");
  await passkeys.getByLabel("Name for a new passkey").fill("Work key");
  await passkeys.getByRole("button", { name: "Create a passkey" }).click();
  await expect(said(page)).toHaveText("Added.");
  await expect(passkeys.getByTestId("passkey-row")).toHaveCount(2);
  const finish = bff.seen.find((s) => s.path.endsWith("/passkeys/reg_1"));
  expect(finish?.body["credential"]).toEqual({ id: "bmV3", type: "public-key", response: {} });
  expect(finish?.headers["idempotency-key"]).toMatch(/^[0-9a-f-]{36}$/);
  await passkeys.getByRole("button", { name: "Remove: Laptop" }).click();
  await expect(said(page)).toHaveText("Removed.");
  await expect(passkeys.getByTestId("passkey-row")).toHaveCount(1);
});

// HL-19, OP-159 m.3 (ll)
test("the passkeys block says passkeys have no post-quantum cryptography", async ({ page }) => {
  await page.goto("/account/");
  await expect(page.getByTestId("passkeys").getByTestId("passkey-no-pqc")).toHaveText(
    "Passkeys don't use post-quantum cryptography yet.",
  );
});

test("the last way to sign in is kept and said plainly (TN-68)", async ({ page, bff }) => {
  bff.lastMethod = true;
  await page.goto("/account/");
  await page.getByRole("button", { name: "Remove: Laptop" }).click();
  await expect(alerted(page)).toHaveText("Add another way to sign in first.");
  await expect(page.getByTestId("passkey-row")).toHaveCount(1);
});

test("a write that needs a fresh confirmation goes to the hosted login and back (X29)", async ({
  page,
  bff,
}) => {
  bff.freshNeeded = true;
  await page.route("**/login?**", (r) =>
    r.fulfill({ status: 200, contentType: "text/html", body: "<title>login</title>" }),
  );
  await page.goto("/account/");
  await page.getByRole("button", { name: "Remove: Laptop" }).click();
  await page.waitForURL(/\/login\?reason=reauthenticate&return_to=%2Faccount/);
});

test("a password is changed; a weak one is refused with a reason", async ({ page, bff }) => {
  await page.goto("/account/");
  const password = page.getByTestId("password");
  await expect(password).toContainText("A password is set.");
  await password.getByRole("button", { name: "Change password" }).click();
  const field = password.getByLabel("New password");
  await expect(field).toBeFocused();
  await expect(field).toHaveAttribute("autocomplete", "new-password");
  await field.fill("password");
  await password.getByRole("button", { name: "Save" }).click();
  await expect(alerted(page)).toContainText("Choose a different password.");
  await field.fill("a long and unusual sentence");
  await password.getByRole("button", { name: "Save" }).click();
  await expect(said(page)).toHaveText("Your password was saved.");
  expect(bff.seen.filter((s) => s.path.endsWith("/v1/account/password"))).toHaveLength(2);
});

test("the authenticator key is text with a copy button; one pasteable code field (TN-107)", async ({
  page,
  bff,
}) => {
  await page.goto("/account/");
  const app = page.getByTestId("authenticator");
  await expect(app).toContainText("No authenticator app is set up.");
  await app.getByRole("button", { name: "Set up an authenticator app" }).click();
  await expect(app.getByTestId("totp-secret")).toHaveText("JBSWY3DPEHPK3PXP");
  await expect(app.getByRole("button", { name: "Copy the key" })).toBeVisible();
  const code = app.getByLabel("Code from your authenticator app");
  await expect(code).toBeFocused();
  await expect(code).toHaveAttribute("autocomplete", "one-time-code");
  await expect(app.locator("input")).toHaveCount(1);
  await code.fill("000000");
  await app.getByRole("button", { name: "Verify" }).click();
  await expect(alerted(page)).toHaveText("That code didn't work. Check it and try again.");
  await code.fill("123 456");
  await app.getByRole("button", { name: "Verify" }).click();
  await expect(app.getByTestId("totp-row")).toHaveCount(1);
  expect(bff.seen.findLast((s) => s.path.endsWith("/totp/enr_1"))?.body["code"]).toBe("123456");
  const codes = page.getByTestId("recovery-codes");
  await expect(codes.getByTestId("code-list").locator("li")).toHaveCount(2);
  await codes.getByRole("button", { name: "I saved them" }).click();
  await expect(codes).toContainText("You have recovery codes.");
});

test("new recovery codes are shown once and need the saved acknowledgement", async ({ page }) => {
  await page.goto("/account/");
  const codes = page.getByTestId("recovery-codes");
  await expect(codes).toContainText("You have no recovery codes yet.");
  await codes.getByRole("button", { name: "Get new recovery codes" }).click();
  await expect(codes.getByTestId("code-list")).toHaveText("JJJJ-KKKK-LLLL-MMMM");
  await codes.getByRole("button", { name: "I saved them" }).click();
  await expect(codes.getByTestId("code-list")).toHaveCount(0);
  await expect(codes).toContainText("You have recovery codes.");
});

test("linked sign-ins are listed and unlinked, never called merged", async ({ page }) => {
  await page.goto("/account/");
  const linked = page.getByTestId("linked-sign-ins");
  await expect(linked.getByTestId("linked-row")).toContainText("google");
  await expect(linked.getByText(/merged/i)).toHaveCount(0);
  await linked.getByRole("button", { name: "Remove: google" }).click();
  await expect(linked).toContainText("No other sign-ins are linked.");
});

test("connected apps say what they receive; stopping keeps the record", async ({ page, bff }) => {
  await page.goto("/account/");
  const apps = page.getByTestId("connected-apps");
  await expect(apps.getByTestId("app-row")).toContainText("Receives: email, name");
  await apps.getByRole("button", { name: "Stop sharing: Shop" }).click();
  await expect(apps.getByTestId("said")).toContainText("Sharing stopped.");
  await expect(apps).toContainText("You don't share details with any app.");
  expect(bff.seen.some((s) => s.path.endsWith("/connected-apps/cli_shop"))).toBe(true);
});

test("a lost sign-in says only to sign in again (§8.13)", async ({ page, bff }) => {
  await page.goto("/account/");
  await expect(page.getByTestId("passkey-row")).toHaveCount(1);
  bff.signedIn = false;
  await page.getByRole("button", { name: "Remove: Laptop" }).click();
  await expect(alerted(page)).toHaveText("Please sign in again to continue.");
});

// OP-156 m.3 (d): approvers register themselves from their app; here they are seen and removed
test("approvers are listed and removed", async ({ page }) => {
  await page.goto("/account/");
  const approvers = page.getByTestId("approvers");
  await expect(approvers).toContainText("Apps on your phone that can approve your sign-ins");
  await expect(approvers.getByTestId("approver-row")).toHaveCount(1);
  await expect(approvers).toContainText("Ada's phone");
  await approvers.getByRole("button", { name: "Remove: Ada's phone" }).click();
  await expect(approvers.getByTestId("said")).toHaveText("Removed.");
  await expect(approvers).toContainText("No approvers yet.");
});

// OP-156 m.3 (w), E59: a live cloud key permission is seen and stopped with one tap
test("a cloud key permission is seen and stopped", async ({ page }) => {
  await page.goto("/account/");
  const keys = page.getByTestId("cloud-keys");
  await expect(keys).toContainText("Cloud use of your data by One");
  await expect(keys.getByTestId("cloud-key-row")).toHaveCount(1);
  await expect(keys).toContainText("one_memory, one_model");
  await keys.getByRole("button", { name: "Stop cloud use" }).click();
  await expect(page.getByTestId("cloud-keys")).toHaveCount(0);
});

// E56, OP-156 m.4 (Q20): a name shows only once its site points back; it can be checked again
test("a pending name is checked again and then shown", async ({ page }) => {
  await page.goto("/account/");
  const names = page.getByTestId("handles");
  await expect(names).toContainText("Your names");
  await expect(names).toContainText("Waiting for ada.example.org to point back to you");
  await names.getByRole("button", { name: "Check again" }).click();
  await expect(names).not.toContainText("Waiting for");
  await names.getByRole("button", { name: "Remove: ada.example.org" }).click();
  await expect(names.getByTestId("handle-row")).toHaveCount(0);
});
