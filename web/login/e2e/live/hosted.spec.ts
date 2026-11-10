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

  // §11.6, §11.4.5 #28, EI-18, OP-154 m.3 (k), Ek B 4538, 4541
  test("@live the consent screen is never framed, may compile only the Kernel and needs a sign-in", async ({
    page,
  }) => {
    const back = `${REALM}/authorize?client_id=${encodeURIComponent("https://app.example/c.json")}&request_uri=x`;
    const r = await page.goto(
      `${REALM}/login?reason=approve&return_to=${encodeURIComponent(back)}`,
    );
    expect(r?.status()).toBe(200);
    const csp = r?.headers()["content-security-policy"] ?? "";
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("script-src 'self' 'wasm-unsafe-eval'");
    expect(csp).not.toContain("unsafe-inline");
    expect(r?.headers()["set-cookie"]).toBeUndefined();
    await expect(page.getByRole("link", { name: "Sign in" })).toBeVisible();
    const preview = await page.request.post(`${REALM}/v1/login/approval/preview`, {
      data: { return_to: back },
      headers: { origin: new URL(page.url()).origin },
    });
    expect(preview.status()).toBe(401);
    expect(preview.headers()["x-frame-options"]).toBe("DENY");
    await clean(page);
  });

  // RFC 8628, TN-35, OP-154 m.3 (p), (dd), Ek B 4649, 4651
  test("@live the device page is a framed-never page that needs a sign-in to read a code", async ({
    page,
  }) => {
    const r = await page.goto(`${REALM}/device`);
    expect(r?.status()).toBe(200);
    const csp = r?.headers()["content-security-policy"] ?? "";
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).not.toContain("unsafe-inline");
    await expect(page.getByRole("heading", { name: "Connect a device" })).toBeVisible();
    const preview = await page.request.post(`${REALM}/v1/device/preview`, {
      data: { user_code: "BCDF-GHJZ" },
      headers: { origin: new URL(page.url()).origin },
    });
    expect([401, 404]).toContain(preview.status());
    await clean(page);
  });

  // OP-155 m.3 (l), IDP-14, Ek B 4718
  test("@live the CIBA approval page is never framed, may compile only the Kernel and needs a sign-in", async ({
    page,
  }) => {
    const r = await page.goto(`${REALM}/login?reason=ciba&request=AAAAAAAAAAAAAAAAAAAAAA`);
    expect(r?.status()).toBe(200);
    const csp = r?.headers()["content-security-policy"] ?? "";
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("script-src 'self' 'wasm-unsafe-eval'");
    expect(csp).not.toContain("unsafe-inline");
    await expect(page.getByRole("link", { name: "Sign in" })).toBeVisible();
    const preview = await page.request.post(`${REALM}/v1/ciba/preview`, {
      data: { request: "AAAAAAAAAAAAAAAAAAAAAA" },
      headers: { origin: new URL(page.url()).origin },
    });
    expect([401, 404]).toContain(preview.status());
    const cross = await page.request.post(`${REALM}/v1/ciba/approval`, {
      data: { request: "AAAAAAAAAAAAAAAAAAAAAA", approve: false },
      headers: { origin: "https://elsewhere.example" },
    });
    expect([403, 404]).toContain(cross.status());
    await clean(page);
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

  // TN-95, §8.13, OP-155 m.3 (h), Ek B 4678, 4731
  test("@live an upstream connection the realm does not hold is not served and changes nothing", async ({
    page,
  }) => {
    const start = await page.request.get(`${REALM}/v1/login/upstream/no-such-connection`, {
      maxRedirects: 0,
    });
    expect(start.status()).toBe(404);
    expect((await start.json())["code"]).toBe("no-such-provider");
    const metadata = await page.request.get(
      `${REALM}/v1/login/upstream/no-such-connection/saml/metadata`,
    );
    expect(metadata.status()).toBe(404);
  });
});
