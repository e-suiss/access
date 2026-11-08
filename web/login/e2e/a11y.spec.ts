import AxeBuilder from "@axe-core/playwright";
import type { Page } from "@playwright/test";

import { expect, test } from "./fixtures.js";
import type { LoginMock } from "./mock.js";

// OP-83, TN-107, SA-55
const wcag22aa = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];

async function clean(page: Page): Promise<void> {
  expect((await new AxeBuilder({ page }).withTags(wcag22aa).analyze()).violations).toEqual([]);
}

function backends(mock: LoginMock): void {
  mock.identifierExtras = [
    {
      type: "option",
      name: "keep_signed_in",
      label: { id: "option.keep_signed_in", text: "Keep me signed in on this device" },
      checked: false,
    },
    {
      type: "provider",
      provider: "google",
      label: { id: "social.google", text: "Continue with Google" },
      href: "/v1/login/social/google",
    },
  ];
  mock.branding = { status: 200, body: { display_name: "Acme", logo_uri: null } };
  mock.json.set("POST /v1/recovery", {
    status: 201,
    body: {
      attempt: "rca_1",
      state: "cooling_down",
      method: "sent_code",
      text: "recovery.cooling",
      until: "2026-11-10T09:30:00Z",
    },
  });
  mock.json.set("GET /v1/invitations/K7Q2M9XA", {
    status: 200,
    body: {
      organization: { id: "org_1", display_name: "Acme" },
      invitee_domain: "acme.example",
    },
  });
  mock.json.set("POST /v1/account/connected-apps/preview", {
    status: 200,
    body: { client_id: "cli_x", app: "Photo Prints", claims: ["email", "name"] },
  });
  mock.json.set("POST /v1/login/link/preview", {
    status: 200,
    body: { state: "confirm", same_device: false },
  });
}

for (const locale of ["en", "ar-XB"]) {
  test(`every login step has no WCAG 2.2 AA violations (${locale})`, async ({ page, mock }) => {
    backends(mock);
    await page.goto(`/?ui_locales=${locale}`);
    await expect(page.getByLabel("Email or username")).toBeVisible();
    await clean(page);

    await page.getByLabel("Email or username").fill("ada@example.org");
    await page.getByRole("button", { name: "Continue" }).click();
    await page.getByLabel("Password").fill("not it");
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await expect(page.getByRole("alert")).not.toBeEmpty();
    await clean(page);
  });

  // TN-107, Ek B 3676: axe on every hosted page
  test(`every hosted page has no WCAG 2.2 AA violations (${locale})`, async ({ page, mock }) => {
    backends(mock);
    const pages: [string, string][] = [
      ["/login?reason=create", "Create your account"],
      ["/login/recovery", "Get back into your account"],
      ["/login/invitation/K7Q2M9XA", "You're invited to join an organization"],
      ["/login/invitation", "You're invited to join an organization"],
      [
        `/login?reason=share&return_to=${encodeURIComponent("/authorize?client_id=cli_x")}`,
        "Share with Photo Prints",
      ],
      ["/login/link#tok_1", "Confirm sign-in"],
      ["/login/error?error=invalid_client&owner=app&ref=7F3K-2Q", "Sign-in couldn't be completed"],
    ];
    for (const [path, heading] of pages) {
      const join = path.includes("?") ? "&" : "?";
      const at = path.includes("#")
        ? path.replace("#", `${join}ui_locales=${locale}#`)
        : `${path}${join}ui_locales=${locale}`;
      await page.goto(at);
      await expect(page.getByRole("heading", { name: heading })).toBeVisible();
      await clean(page);
    }

    await page.goto(`/login/recovery?ui_locales=${locale}`);
    await page.getByLabel("Email or username").fill("ada@example.org");
    await page.getByRole("button", { name: "Start recovery" }).click();
    await expect(page.getByTestId("until")).toBeVisible();
    await clean(page);
  });
}

// TN-107: paste is never blocked and a code is one field
test("a code can be pasted into its one field", async ({ page, context, browserName }) => {
  test.skip(browserName !== "chromium");
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await page.goto("/login?reason=create");
  await page.getByLabel("Email").fill("new@example.org");
  await page.getByRole("button", { name: "Create account" }).click();
  const code = page.getByLabel("Code from your email");
  await page.evaluate(() => navigator.clipboard.writeText("12345678"));
  await code.focus();
  await page.keyboard.press("ControlOrMeta+V");
  await expect(code).toHaveValue("12345678");
  expect(await page.locator("input[autocomplete='one-time-code']").count()).toBe(1);
});
