// OP-153 m.3 (gg), TN-106, TN-107, TN-133, X-L5: the hosted pages against the running local
// deployment, through its real router; nothing here is mocked.
import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

const REALM = process.env["ACCESS_LIVE_REALM"] ?? "/realms/acme";
const wcag22aa = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];

async function clean(page: Page): Promise<void> {
  expect((await new AxeBuilder({ page }).withTags(wcag22aa).analyze()).violations).toEqual([]);
}

test.describe("@live hosted pages", () => {
  test("@live the pages are served with a strict CSP that refuses every frame", async ({
    page,
  }) => {
    for (const path of [
      "/login",
      "/login?reason=create",
      "/login?reason=share",
      "/login/recovery",
    ]) {
      const r = await page.goto(`${REALM}${path}`);
      expect(r?.status(), path).toBe(200);
      const h = r?.headers() ?? {};
      const csp = h["content-security-policy"] ?? "";
      expect(csp, path).toContain("frame-ancestors 'none'");
      expect(csp, path).toContain("script-src 'self'");
      expect(csp, path).toContain("require-trusted-types-for 'script'");
      expect(csp, path).not.toContain("unsafe-inline");
      expect(h["x-content-type-options"]).toBe("nosniff");
    }
  });

  test("@live the sign-up page opens a registration flow and passes axe", async ({ page }) => {
    await page.goto(`${REALM}/login?reason=create`);
    await expect(page.getByRole("heading", { name: "Create your account" })).toBeVisible();
    await expect(page.getByLabel("Email")).toHaveAttribute("autocomplete", "email");
    await clean(page);
  });

  test("@live every hosted page passes axe, left to right and right to left", async ({ page }) => {
    for (const locale of ["en", "ar-XB"]) {
      const pages: [string, string][] = [
        ["/login", "Sign in"],
        ["/login/recovery", "Get back into your account"],
        ["/login/invitation", "You're invited to join an organization"],
        [
          "/login/error?error=invalid_client&owner=app&ref=7F3K-2Q",
          "Sign-in couldn't be completed",
        ],
        ["/login/link", "Confirm sign-in"],
      ];
      for (const [path, heading] of pages) {
        const join = path.includes("?") ? "&" : "?";
        await page.goto(`${REALM}${path}${join}ui_locales=${locale}`);
        await expect(page.getByRole("heading", { name: heading })).toBeVisible();
        await expect(page.locator("html")).toHaveAttribute(
          "dir",
          locale === "ar-XB" ? "rtl" : "ltr",
        );
        await clean(page);
      }
    }
  });

  // X35, OP-153 m.22 (k): the pages read the realm's stored texts; none are protected keys
  test("@live the realm's text overrides are served to the pages", async ({ page }) => {
    const r = await page.request.get(`${REALM}/v1/login/messages`);
    expect(r.status()).toBe(200);
    const body = (await r.json()) as { overrides?: Record<string, Record<string, string>> };
    expect(typeof body.overrides).toBe("object");
    for (const texts of Object.values(body.overrides ?? {})) {
      expect(Object.keys(texts)).not.toContain("login-failed");
    }
  });

  test("@live recovery answers the same for an unknown address", async ({ page }) => {
    await page.goto(`${REALM}/login/recovery`);
    await page.getByLabel("Email or username").fill(`nobody-${String(Date.now())}@example.org`);
    await page.getByRole("button", { name: "Start recovery" }).click();
    await expect(
      page.getByText("If an account exists for these details, we've sent instructions."),
    ).toBeVisible();
  });
});
