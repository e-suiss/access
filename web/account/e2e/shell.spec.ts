// OP-153 m.3 (w), (t), (ee), TN-131, G57, X40
import { expect, test } from "./fixtures.js";

test("without a session the shell offers sign-in and shows no data", async ({ page, bff }) => {
  await page.goto("/account/");
  await expect(page.getByTestId("signed-out")).toBeVisible();
  expect(bff.seen.filter((s) => s.path.includes("/v1/account/"))).toEqual([]);
});

test("the realm's name is the brand; the Account section runs on the cookie alone", async ({
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
