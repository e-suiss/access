// OP-153 m.3 (w), (t), (ee), TN-131, G57, X40
import { expect, test } from "./fixtures.js";

test("without a session the shell offers sign-in and shows no data", async ({ page, bff }) => {
  await page.goto("/account/");
  await expect(page.getByTestId("signed-out")).toBeVisible();
  expect(bff.seen.filter((s) => s.path.includes("/v1/account/"))).toEqual([]);
});

test("the environment's name is the brand; the Account section runs on the cookie alone", async ({
  page,
  bff,
  context,
  baseURL,
}) => {
  await bff.signIn(context, baseURL ?? "");
  await page.goto("/account/");
  await expect(page.getByTestId("brand")).toHaveText("acme");
  await expect(page.getByTestId("preferences")).toBeVisible();
  await expect(page.getByTestId("deletion")).toContainText("No deletion is scheduled.");
  expect(bff.seen.some((s) => s.path.includes("/proxy/adp/"))).toBe(false);
});

test("a preference change is a cookie write with the CSRF token and an Idempotency-Key", async ({
  page,
  bff,
  context,
  baseURL,
}) => {
  await bff.signIn(context, baseURL ?? "");
  await page.goto("/account/");
  await page.getByRole("checkbox", { name: "Newsletter · Email" }).check();
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("status")).toHaveText("Saved.");
  const put = bff.seen.find(
    (s) => s.path.endsWith("/v1/account/preferences") && s.body["changes"] !== undefined,
  );
  expect(put?.headers["x-csrf-token"]).toBe("csrf-token");
  expect(put?.headers["idempotency-key"]).toMatch(/^[0-9a-f-]{36}$/);
  expect(bff.preferences["email:newsletter"]).toBe(true);
});

test("the page carries the account's security headers", async ({ page }) => {
  const r = await page.goto("/account/");
  const csp = r?.headers()["content-security-policy"] ?? "";
  expect(csp).toContain("frame-ancestors 'none'");
  expect(csp).toContain("script-src 'self' 'wasm-unsafe-eval'");
  expect(r?.headers()["x-frame-options"]).toBe("DENY");
});

// OP-153 m.3 (y), X36
test("the signed-out screen says why, from the closed list", async ({ page, bff }) => {
  bff.signedOutReason = "device_mismatch";
  await page.goto("/account/");
  await expect(page.getByTestId("signed-out")).toBeVisible();
  await expect(page.getByTestId("signed-out-reason")).toHaveText(
    "Signed out because this device didn't match the sign-in.",
  );
});

// TN-108, OP-153 m.3 (s)
test("the ar-XB pseudo-locale draws the shell right to left", async ({ page }) => {
  await page.goto("/account/?ui_locales=ar-XB");
  await expect(page.getByTestId("signed-out")).toBeVisible();
  await expect(page.locator("html")).toHaveAttribute("dir", "rtl");
  await expect(page.locator("html")).toHaveAttribute("lang", "ar-XB");
});

// OP-156 m.3 (c), IDP-37 (4), B23
test("the İYS state of each commercial channel is shown as Relay reported it", async ({
  page,
  bff,
  context,
  baseURL,
}) => {
  await bff.signIn(context, baseURL ?? "");
  await page.goto("/account/");
  await expect(page.getByTestId("preferences")).toBeVisible();
  await expect(page.getByTestId("iys")).toHaveCount(0);
  bff.iys = {
    sms: { consent: "approved", status: "recorded", at: "2026-11-10T09:00:00.000Z" },
    email: { consent: "rejected", status: "failed", at: "2026-11-10T09:01:00.000Z" },
    call: { consent: "approved", status: "pending", at: null },
  };
  await page.reload();
  await expect(page.getByTestId("iys")).toContainText("İYS");
  await expect(page.getByTestId("iys-sms")).toContainText("2026-11-10T09:00:00.000Z");
  await expect(page.getByTestId("iys-email")).toContainText("Access will try again.");
  await expect(page.getByTestId("iys-call")).toContainText("Being recorded with İYS");
});

// OP-159 m.50, TN-145: what deleting the account does is said before anything is signed
test("deleting the account says its date, that it can be cancelled and what stays", async ({
  page,
  context,
  baseURL,
  bff,
}) => {
  await bff.signIn(context, baseURL ?? "");
  await page.goto("/account/");
  const deletion = page.getByTestId("deletion");
  await deletion.getByRole("button", { name: "Delete my account" }).click();
  const asked = deletion.getByRole("group", { name: "Before you delete your account" });
  await expect(asked).toContainText("2026-11-18T12:00:00Z");
  await expect(asked).toContainText("You can cancel here until then.");
  await expect(asked).toContainText("every device is signed out");
  await expect(asked).not.toContainText(/instantly|immediately/i);
  await asked.getByRole("button", { name: "Keep my account" }).click();
  await expect(asked).toHaveCount(0);
  expect(bff.seen.filter((x) => x.path.endsWith("/deletion") && "ais" in x.body)).toEqual([]);
});

test("an environment that turned self-deletion off says so in its own words", async ({
  page,
  context,
  baseURL,
  bff,
}) => {
  bff.deletionDraft = "closed";
  await bff.signIn(context, baseURL ?? "");
  await page.goto("/account/");
  const deletion = page.getByTestId("deletion");
  await deletion.getByRole("button", { name: "Delete my account" }).click();
  await expect(deletion.getByRole("alert")).toContainText(
    "This app doesn't let you delete your account here.",
  );
});

test("deleting the account after a stale sign-in confirms it's you first", async ({
  page,
  context,
  baseURL,
  bff,
}) => {
  bff.deletionDraft = "step-up";
  await bff.signIn(context, baseURL ?? "");
  await page.route("**/login?**", (r) =>
    r.fulfill({ status: 200, contentType: "text/html", body: "<title>login</title>" }),
  );
  await page.goto("/account/");
  await page.getByTestId("deletion").getByRole("button", { name: "Delete my account" }).click();
  await page.waitForURL(/\/login\?reason=reauthenticate&return_to=%2Faccount/);
});
