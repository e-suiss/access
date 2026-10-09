import { expect, test } from "./fixtures.js";

test("shows the Kernel API version computed by the Wasm module", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1, name: "Console" })).toBeVisible();
  await expect(page.getByTestId("kernel-api-version")).toHaveText("0.0");
});

test("is served with a CSP that enforces Trusted Types", async ({ page }) => {
  const response = await page.goto("/");
  const csp = response?.headers()["content-security-policy"] ?? "";
  expect(csp).toContain("require-trusted-types-for 'script'");
  expect(csp).not.toContain("'unsafe-eval'");
  expect(csp).not.toContain("'unsafe-inline'");
});
