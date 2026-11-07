import { expect, test } from "./fixtures.js";

const BASE = "http://127.0.0.1:4173";

// TN-131, §14.5: strict CSP, no referrer, isolation, minimal permissions
test("is served with a strict CSP and isolation headers", async ({ page }) => {
  const response = await page.goto("/console/");
  const h = response?.headers() ?? {};
  const csp = h["content-security-policy"] ?? "";
  for (const d of [
    "default-src 'none'",
    "script-src 'self' 'wasm-unsafe-eval'",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "require-trusted-types-for 'script'",
    "trusted-types 'none'",
  ]) {
    expect(csp).toContain(d);
  }
  expect(csp).not.toContain("unsafe-inline");
  expect(csp).not.toContain("'unsafe-eval'");
  expect(csp).not.toMatch(/https?:/);
  expect(h["referrer-policy"]).toBe("no-referrer");
  expect(h["cross-origin-opener-policy"]).toBe("same-origin");
  expect(h["cross-origin-embedder-policy"]).toBe("require-corp");
  expect(h["permissions-policy"]).toContain("camera=()");
  expect(h["x-frame-options"]).toBe("DENY");
});

// TN-131: tenant-controlled strings are text, never markup
test("renders tenant-controlled strings as text", async ({ page, context, bff }) => {
  await bff.signIn(context, BASE);
  let dialogs = 0;
  page.on("dialog", (d) => {
    dialogs += 1;
    void d.dismiss();
  });
  await page.goto("/console/profile");
  await expect(page.getByTestId("display-name")).toHaveText("<img src=x onerror=alert(1)>Ada");
  await expect(page.locator("main img")).toHaveCount(0);
  expect(dialogs).toBe(0);
});

// §14.5: Trusted Types refuse every HTML sink
test("refuses HTML sinks through Trusted Types", async ({ page, pageErrors }) => {
  await page.goto("/console/");
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
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

// TN-131: nothing loads from another origin
test("loads nothing from another origin", async ({ page, context, bff }) => {
  await bff.signIn(context, BASE);
  const origins = new Set<string>();
  page.on("request", (r) => origins.add(new URL(r.url()).origin));
  await page.goto("/console/about");
  await expect(page.getByTestId("kernel-api-version")).toHaveText("0.0");
  expect([...origins]).toEqual([BASE]);
});

// TN-131: state changes carry the session's CSRF token
test("state changes carry the CSRF token", async ({ page, context, bff }) => {
  await bff.signIn(context, BASE);
  const signOut = page.waitForRequest((r) => r.url().endsWith("/console/api/sign-out"));
  await page.goto("/console/");
  await page.getByRole("button", { name: "Sign out" }).click();
  const r = await signOut;
  const csrf = (await context.cookies()).find((c) => c.name === "__Host-access-console-csrf");
  expect(r.headers()["x-csrf-token"]).toBe(csrf?.value);
  await expect(page.getByRole("heading", { name: "Sign in to the console" })).toBeVisible();
  expect(bff.seen.find((s) => s.path === "/sign-out")?.status).toBe(204);
});
