import { expect, test } from "./fixtures.js";
import { password, totp } from "./mock.js";

// TN-106, §14.5, K06 "Tarayıcı tarafı sertleştirme"
test("is served with a strict CSP that enforces Trusted Types", async ({ page }) => {
  const response = await page.goto("/");
  const headers = response?.headers() ?? {};
  const csp = headers["content-security-policy"] ?? "";
  for (const directive of [
    "default-src 'none'",
    "script-src 'self'",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "require-trusted-types-for 'script'",
    "trusted-types 'none'",
  ]) {
    expect(csp).toContain(directive);
  }
  expect(csp).not.toContain("unsafe-");
  expect(csp).not.toMatch(/https?:/);
  expect(headers["referrer-policy"]).toBe("no-referrer");
  expect(headers["x-content-type-options"]).toBe("nosniff");
  expect(headers["permissions-policy"]).toContain("publickey-credentials-get=(self)");
});

// §14.5
test("refuses HTML sinks through Trusted Types", async ({ page, pageErrors }) => {
  await page.goto("/");
  await expect(page.getByLabel("Email or username")).toBeVisible();
  const blocked = await page.evaluate(() => {
    try {
      document.body.insertAdjacentHTML("beforeend", "<img src=x>");
      return false;
    } catch (error) {
      return error instanceof TypeError;
    }
  });
  expect(blocked).toBe(true);
  pageErrors.splice(0);
});

// IDP-36, TN-81, TN-106, X27, §8.11
test("loads nothing from a third party and shows no tracking, CAPTCHA or consent screen", async ({
  page,
  baseURL,
}) => {
  const origins = new Set<string>();
  const scripts: string[] = [];
  page.on("request", (request) => origins.add(new URL(request.url()).origin));
  page.on("response", async (response) => {
    if (response.request().resourceType() === "script") scripts.push(await response.text());
  });

  await page.goto("/");
  await page.getByLabel("Email or username").fill("ada@example.org");
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  const mfa = await page.locator("main").innerText();
  await page.getByLabel("Code from your authenticator app").fill(totp);
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByRole("heading", { name: "Signed in" })).toBeVisible();

  expect([...origins]).toEqual([new URL(baseURL ?? "").origin]);
  expect(await page.locator("iframe").count()).toBe(0);
  const bundle = scripts.join("\n");
  for (const marker of [
    "recaptcha",
    "hcaptcha",
    "googletagmanager",
    "google-analytics",
    "gtag(",
    "segment.io",
  ]) {
    expect(bundle).not.toContain(marker);
  }
  for (const banned of [/\bscopes?\b/i, /\bauthorize\b/i, /\bpermissions? requested\b/i]) {
    expect(mfa).not.toMatch(banned);
  }
});
