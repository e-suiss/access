import { expect, test } from "./fixtures.js";
import { password, signupCode, totp } from "./mock.js";

const keep = {
  type: "option" as const,
  name: "keep_signed_in" as const,
  label: { id: "option.keep_signed_in", text: "Keep me signed in on this device" },
  checked: false,
};

const remember = {
  type: "option" as const,
  name: "remember_device" as const,
  label: {
    id: "option.remember_device",
    text: "Don't ask for a second step on this device for 30 days",
  },
  checked: false,
};

// TN-36, X33, X-L2, Ek B 4095, 4101
test("a checked option goes with every submission of its step, an unchecked one with none", async ({
  page,
  mock,
}) => {
  mock.identifierExtras = [keep];
  mock.authenticateExtras = [remember];
  await page.goto("/");
  await page.getByLabel("Keep me signed in on this device").check();
  await page.getByLabel("Email or username").fill("ada@example.org");
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByLabel("Password")).toBeVisible();
  await expect(
    page.getByLabel("Don't ask for a second step on this device for 30 days"),
  ).not.toBeChecked();
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await page.getByLabel("Code from your authenticator app").fill(totp);
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByRole("heading", { name: "Signed in" })).toBeVisible();

  expect(mock.submissions[0]?.fields).toEqual({
    identifier: "ada@example.org",
    keep_signed_in: "true",
  });
  expect(mock.submissions[1]?.fields).toEqual({ password });
});

// OP-153 m.3 (l)
test("a social sign-in is a full-page link; a link off this site is dropped", async ({
  page,
  mock,
}) => {
  mock.identifierExtras = [
    {
      type: "provider",
      provider: "google",
      label: { id: "social.google", text: "Continue with Google" },
      href: "/v1/login/social/google",
    },
    {
      type: "provider",
      provider: "evil",
      label: { id: "social.evil", text: "Continue with Evil" },
      href: "//evil.example/start",
    },
  ];
  await page.route(/\/v1\/login\/social\/google$/, (route) =>
    route.fulfill({
      status: 200,
      contentType: "text/html",
      body: "<!doctype html><html lang=en><title>Provider</title><h1>Provider</h1></html>",
    }),
  );
  await page.goto("/");
  await expect(page.getByRole("link", { name: "Continue with Evil" })).toHaveCount(0);
  await page.getByRole("link", { name: "Continue with Google" }).click();
  await expect(page).toHaveURL(/\/v1\/login\/social\/google$/);
});

// §10.4.6, OP-153 m.3 (g), Ek B 4098, 4104
test("prompt=create opens the sign-up page: address, then code and name", async ({
  page,
  mock,
}) => {
  await page.goto("/login?reason=create");
  await expect(page.getByRole("heading", { name: "Create your account" })).toBeVisible();
  const email = page.getByLabel("Email");
  await expect(email).toHaveAttribute("autocomplete", "email");
  await email.fill("new@example.org");
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(page.getByRole("status").first()).toContainText(
    "If this address can be used, we've sent a code to it.",
  );
  await expect(page.getByRole("heading", { name: "Create your account" })).toBeFocused();
  const code = page.getByLabel("Code from your email");
  await expect(code).toHaveAttribute("autocomplete", "one-time-code");
  await expect(code).toHaveAttribute("inputmode", "numeric");
  await code.fill(signupCode);
  await page.getByLabel("Your name").fill("New Person");
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByRole("heading", { name: "Signed in" })).toBeVisible();

  expect(mock.requests[0]).toBe("POST /v1/login/flows");
  expect(mock.submissions.map((s) => [s.method, s.fields])).toEqual([
    ["register", { email: "new@example.org" }],
    ["email_code", { email_code: signupCode, display_name: "New Person" }],
  ]);
});

// TN-102, §10.2.2, Ek B 4094
test("a sign-in link: the page waits, polls and continues once the link is confirmed", async ({
  page,
  mock,
}) => {
  mock.authenticateExtras = [
    {
      type: "submit",
      method: "magic_link",
      label: { id: "action.magic_link", text: "Email me a sign-in link" },
    },
  ];
  mock.linkPolls = 1;
  await page.clock.install();
  await page.goto("/");
  await page.getByLabel("Email or username").fill("ada@example.org");
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByRole("button", { name: "Email me a sign-in link" }).click();
  await expect(page.getByTestId("link-wait")).toHaveText(
    "Waiting for you to open the link in your email. This page continues on its own.",
  );
  await page.clock.runFor(2000);
  await expect.poll(() => mock.requests.filter((r) => r.startsWith("GET")).length).toBe(1);
  await page.clock.runFor(3000);
  await expect(page.getByRole("heading", { name: "Signed in" })).toBeVisible();
});

test("the sign-in link's page confirms with a POST, never on opening", async ({ page, mock }) => {
  mock.json.set("POST /v1/login/link/preview", {
    status: 200,
    body: { state: "confirm", same_device: false },
  });
  mock.json.set("POST /v1/login/link/confirm", {
    status: 200,
    body: { state: "confirmed", same_device: false },
  });
  await page.goto("/login/link#tok_123");
  await expect(page.getByText("This link was opened on a different device")).toBeVisible();
  expect(page.url()).not.toContain("tok_123");
  expect(mock.posted.map((p) => p.key)).toEqual(["POST /v1/login/link/preview"]);
  await page.getByRole("button", { name: "Confirm sign-in" }).click();
  await expect(page.getByTestId("link-done")).toHaveText(
    "Confirmed. Continue on the device where you started. You can close this page.",
  );
  expect(mock.posted.at(-1)).toEqual({
    key: "POST /v1/login/link/confirm",
    body: { token: "tok_123", other_device: true },
  });
});

test("a used sign-in link says so", async ({ page, mock }) => {
  mock.json.set("POST /v1/login/link/preview", {
    status: 410,
    body: { type: "urn:suiss:access:problem:flow-gone", status: 410 },
  });
  await page.goto("/login/link#tok_used");
  await expect(page.getByRole("alert")).toHaveText(
    "This link has expired or was already used. Start again from the sign-in page.",
  );
});

// §12.3.2, TN-54, TN-55, OP-153 m.3 (e), Ek B 4104
test("recovery: the same start for everyone, then the waiting period's end date", async ({
  page,
  mock,
}) => {
  mock.json.set("POST /v1/recovery", {
    status: 201,
    body: {
      attempt: "rca_1",
      state: "requested",
      method: "sent_code",
      text: "recovery.requested",
    },
  });
  mock.json.set("POST /v1/recovery/rca_1", (body) =>
    (body as { send?: string }).send !== undefined
      ? {
          status: 200,
          body: {
            attempt: "rca_1",
            state: "requested",
            method: "sent_code",
            text: "recovery.requested",
          },
        }
      : {
          status: 200,
          body: {
            attempt: "rca_1",
            state: "cooling_down",
            method: "sent_code",
            text: "recovery.cooling",
            until: "2026-11-10T09:30:00Z",
          },
        },
  );
  await page.goto("/login/recovery");
  await page.getByLabel("Email or username").fill("ada@example.org");
  await page.getByLabel("With a code sent to my email").check();
  await page.getByRole("button", { name: "Start recovery" }).click();
  await expect(
    page.getByText("If an account exists for these details, we've sent instructions."),
  ).toBeVisible();
  await page.getByRole("button", { name: "Email me a code" }).click();
  const code = page.getByLabel("Code from your email");
  await expect(code).toHaveAttribute("autocomplete", "one-time-code");
  await code.fill("12345678");
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByTestId("until")).toContainText("Recovery can finish after");
  await expect(page.getByTestId("until")).toContainText("2026");
  await expect(page.getByRole("button", { name: "Continue recovery" })).toBeVisible();
  expect(mock.posted.map((p) => p.body)).toEqual([
    { identifier: "ada@example.org", method: "sent_code" },
    { send: "sent_code" },
    { code: "12345678" },
  ]);
});

test("recovery's rebind window takes a new password and shows a replacement code once", async ({
  page,
  mock,
}) => {
  mock.json.set("POST /v1/recovery", {
    status: 201,
    body: {
      attempt: "rca_2",
      state: "rebind_open",
      method: "registered_code",
      text: "recovery.cooling",
    },
  });
  mock.json.set("POST /v1/recovery/rca_2", {
    status: 200,
    body: {
      attempt: "rca_2",
      state: "grace_period",
      text: "recovery.complete",
      replacement_code: "ABCD-EFGH-IJKL-MNOP",
      sensitive_actions_after: "2026-11-11T09:30:00Z",
    },
  });
  await page.goto("/login/recovery");
  await page.getByLabel("Email or username").fill("ada@example.org");
  await page.getByRole("button", { name: "Start recovery" }).click();
  const fresh = page.getByLabel("New password");
  await expect(fresh).toHaveAttribute("autocomplete", "new-password");
  await fresh.fill("a brand new passphrase");
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByTestId("replacement-code")).toHaveText("ABCD-EFGH-IJKL-MNOP");
  await expect(page.getByTestId("sensitive-after")).toContainText("2026");
  // X38
  await expect(page.locator("main")).not.toContainText(/restored/i);
});

// TN-89, OP-153 m.3 (o)
test("an invitation names the organization as text and asks before an unconfirmed domain", async ({
  page,
  mock,
}) => {
  const organization = { id: "org_1", display_name: '<a href="https://evil.example">Acme</a>' };
  mock.json.set("GET /v1/invitations/K7Q2M9XA", {
    status: 200,
    body: { organization, invitee_domain: "acme.example", role: { name: "member", version: 1 } },
  });
  mock.json.set("POST /v1/invitations/K7Q2M9XA", (body) =>
    (body as { confirm?: boolean }).confirm === true
      ? { status: 200, body: { organization, owner: false, role_grant: "pending" } }
      : {
          status: 409,
          body: {
            type: "urn:suiss:access:problem:interstitial-required",
            status: 409,
            organization,
            invitee_domain: "acme.example",
          },
        },
  );
  await page.goto("/login/invitation/K7Q2M9XA");
  await expect(page.getByTestId("organization")).toHaveText(organization.display_name);
  await expect(page.locator("main a[href^='https://evil']")).toHaveCount(0);
  await page.getByRole("button", { name: "Join" }).click();
  await expect(page.getByRole("alert")).toContainText("hasn't shown that it owns acme.example");
  await page.getByRole("button", { name: "Join this organization" }).click();
  await expect(page.getByTestId("joined")).toContainText("You joined");
  expect(mock.posted.filter((p) => p.key.startsWith("POST")).map((p) => p.body)).toEqual([
    {},
    { confirm: true },
  ]);
});

test("a used invitation says so", async ({ page, mock }) => {
  mock.json.set("GET /v1/invitations/USEDCODE", {
    status: 410,
    body: { type: "urn:suiss:access:problem:invitation-gone", status: 410 },
  });
  await page.goto("/login/invitation/USEDCODE");
  await expect(page.getByRole("alert")).toHaveText(
    "This invitation has expired or was already used.",
  );
});

const returnTo =
  "/authorize?client_id=cli_x&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aabc";

function share(mock: import("./mock.js").LoginMock) {
  mock.json.set("POST /v1/account/connected-apps/preview", {
    status: 200,
    body: { client_id: "cli_x", app: "Photo Prints", claims: ["email", "name", "custom_thing"] },
  });
  mock.json.set("POST /v1/account/connected-apps", {
    status: 200,
    body: { redirect_to: "/callback?code=abc" },
  });
  mock.json.set("POST /v1/account/connected-apps/decline", {
    status: 200,
    body: { redirect_to: "/callback?error=access_denied" },
  });
}

// OP-153 m.3 (z), §8.8, X27, Ek B 3943, 4099
test("Share with the app lists the claims and never says Allow or Authorize", async ({
  page,
  mock,
}) => {
  share(mock);
  await page.goto(`/login?reason=share&return_to=${encodeURIComponent(returnTo)}`);
  await expect(page.getByRole("heading", { name: "Share with Photo Prints" })).toBeVisible();
  await expect(page.getByRole("listitem")).toHaveText([
    "Your email address",
    "Your name",
    "custom_thing",
  ]);
  const words = await page.locator("main").innerText();
  expect(words).not.toMatch(/\b(allow|authori[sz]e)\b/i);
  await page.getByRole("button", { name: "Share", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Signed in" })).toBeVisible();
  const origin = new URL(page.url()).origin;
  expect(mock.posted.map((p) => p.body)).toEqual([
    { return_to: `${origin}${returnTo}` },
    { return_to: `${origin}${returnTo}` },
  ]);
});

// X-L8, Ek B 3453
test("Don't share says the person chose not to continue, then answers the app", async ({
  page,
  mock,
}) => {
  share(mock);
  await page.goto(`/login?reason=share&return_to=${encodeURIComponent(returnTo)}`);
  await page.getByRole("button", { name: "Don't share" }).click();
  await expect(page.getByTestId("declined")).toHaveText("You chose not to continue.");
  await expect(page).toHaveURL(/error=access_denied/);
  expect(mock.posted.at(-1)?.key).toBe("POST /v1/account/connected-apps/decline");
});

test("a return address on another site is not followed", async ({ page, mock }) => {
  share(mock);
  await page.goto(`/login?reason=share&return_to=${encodeURIComponent("https://evil.example/x")}`);
  await expect(page.getByRole("alert")).toHaveText(
    "Access couldn't complete this request. Try again shortly.",
  );
  expect(mock.posted).toEqual([]);
});

// X-L8, X41, OP-153 m.3 (jj), Ek B 3452
test("an OAuth error names its owner and a reference, never the raw code", async ({ page }) => {
  await page.goto("/login/error?error=invalid_client&owner=app&ref=7f3k-2q");
  await expect(page.getByRole("alert")).toHaveText(
    "This app isn't set up correctly for sign-in. The app's developer can fix this.",
  );
  await expect(page.getByTestId("reference")).toHaveText("Reference: 7F3K-2Q");
  await expect(page.locator("main")).not.toContainText("invalid_client");

  await page.goto("/login/error?error=temporarily_unavailable&ref=ZZZZ-ZZ");
  await expect(page.getByRole("alert")).toHaveText(
    "Access couldn't complete this request. Try again shortly.",
  );
  await page.goto("/login/error?error=access_denied");
  await expect(page.getByRole("alert")).toHaveText("You chose not to continue.");
  await expect(page.getByTestId("reference")).toHaveCount(0);

  await page.goto("/login/error?error=x&owner=app&ref=<script>");
  await expect(page.getByTestId("reference")).toHaveCount(0);
});

// TN-106, OP-153 m.3 (t), §14.3
test("the realm's name and logo are drawn from data; the logo is an image only", async ({
  page,
  mock,
  pageErrors,
}) => {
  mock.branding = {
    status: 200,
    body: { display_name: "Acme Bank", logo_uri: "https://cdn.acme.example/logo.svg" },
  };
  mock.theme = ":root { --brand-primary: #0f766e; --brand-background: #ecfeff; }";
  await page.route("https://cdn.acme.example/logo.svg", (route) =>
    route.fulfill({
      status: 200,
      contentType: "image/svg+xml",
      body: "<svg xmlns='http://www.w3.org/2000/svg'/>",
    }),
  );
  await page.goto("/");
  await expect(page.getByTestId("brand")).toContainText("Acme Bank");
  const logo = page.locator(".brand-logo");
  await expect(logo).toHaveAttribute("src", "https://cdn.acme.example/logo.svg");
  await expect(logo).toHaveAttribute("alt", "");
  expect(await page.locator("object, embed, iframe").count()).toBe(0);
  const accent = await page
    .getByRole("button", { name: "Continue" })
    .evaluate((b) => getComputedStyle(b).backgroundColor);
  expect(accent).toBe("rgb(15, 118, 110)");
  // TN-106
  expect(pageErrors.every((e) => e.includes("Content Security Policy"))).toBe(true);
  pageErrors.splice(0);
});

test("a logo that is not https is not drawn", async ({ page, mock }) => {
  mock.branding = {
    status: 200,
    body: { display_name: "Acme", logo_uri: "javascript:alert(1)" },
  };
  await page.goto("/");
  await expect(page.getByTestId("brand")).toHaveText("Acme");
  await expect(page.locator(".brand-logo")).toHaveCount(0);
});

// TN-108, X-L15, OP-153 m.3 (s)
test("ar-XB draws right to left; ui_locales picks Turkish", async ({ page }) => {
  await page.goto("/?ui_locales=ar-XB");
  await expect(page.locator("html")).toHaveAttribute("dir", "rtl");
  await expect(page.locator("html")).toHaveAttribute("lang", "ar-XB");
  await expect(page.getByLabel("Email or username")).toBeVisible();

  await page.goto("/?ui_locales=tr");
  await expect(page.locator("html")).toHaveAttribute("dir", "ltr");
  await expect(page.getByRole("button", { name: "Devam" })).toBeVisible();
});

// §17.9.6, TN-133
test("a path realm keeps its prefix on every call and link", async ({ page, mock }) => {
  await page.goto("/realms/acme/login");
  await expect(page.getByLabel("Email or username")).toBeVisible();
  expect(mock.requests).toEqual(["POST /realms/acme/v1/login/flows"]);
  await expect(page.getByRole("link", { name: "Can't sign in?" })).toHaveAttribute(
    "href",
    "/realms/acme/login/recovery",
  );
  await page.getByLabel("Email or username").fill("ada@example.org");
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByLabel("Password")).toBeVisible();
  expect(mock.requests.at(-1)).toBe("POST /realms/acme/v1/login/flows/lgf_example");
});
