// OP-159 m.47 (b), (c), (f), TN-89, TN-138, TN-141: a tenant's founding and an administrator's
// invitation on the hosted pages, and the management environment's sign-in. The magic code rides in
// the fragment and is dropped from the address; the address is proved before the password is
// chosen; the browser sends only its device key's public `COSE_Key`; the tenant's name is text.
import AxeBuilder from "@axe-core/playwright";

import { expect, test } from "./fixtures.js";
import { example } from "./mock.js";

const TOKEN = "fnd_TOKEN";

// the server lets these pages compile the Kernel, as it does the pages that sign (crates/http
// `login::web::signs`); the preview server sends the hosted login's plain policy
test.beforeEach(async ({ page }) => {
  await page.route(/\/login\/(founding|admin-invite)\//, async (route) => {
    if (route.request().resourceType() !== "document") return route.fallback();
    const r = await route.fetch();
    const headers = r.headers();
    headers["content-security-policy"] = (headers["content-security-policy"] ?? "").replace(
      "script-src 'self'",
      "script-src 'self' 'wasm-unsafe-eval'",
    );
    return route.fulfill({ response: r, headers });
  });
});
const NAME = '<img src=x onerror="alert(1)">Acme';

function founding(mock: import("./mock.js").LoginMock, view: Record<string, unknown> = {}) {
  mock.json.set(`GET /env/acme-admin/v1/foundings/${TOKEN}`, {
    status: 200,
    body: {
      display_name: NAME,
      environment: { slug: "acme-admin", kind: "management" },
      expires_at: "2026-11-23T10:00:00Z",
      verified: false,
      completed: false,
      ...view,
    },
  });
  mock.json.set(`POST /env/acme-admin/v1/foundings/${TOKEN}/verify`, (body) =>
    (body as { code?: string }).code === "MAGIC-42"
      ? { status: 204 }
      : {
          status: 400,
          body: {
            type: "urn:suiss:access:problem:invalid-code",
            status: 400,
            code: "invalid-code",
          },
        },
  );
  mock.json.set(`POST /env/acme-admin/v1/foundings/${TOKEN}/complete`, {
    status: 201,
    body: {
      environment: { slug: "acme-admin", kind: "management" },
      issuer: "https://acme.example/env/acme-admin",
      party: "AgICAgICAgICAgICAgICAg",
    },
  });
}

// OP-159 m.47 (c), TN-141
test("a founder proves the address with the code, chooses a password and sends only a public key", async ({
  page,
  mock,
}) => {
  founding(mock);
  await page.goto(`/env/acme-admin/login/founding/${TOKEN}#code=MAGIC-42`);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(`Set up ${NAME}`);
  await expect(page.getByTestId("tenant-name")).toHaveText(NAME);
  await expect(page.locator("main img")).toHaveCount(0);
  // TN-89 (8): the code leaves the address once read
  expect(new URL(page.url()).hash).toBe("");
  await expect(page.getByLabel("Code from the invitation email")).toHaveCount(0);
  await page.getByLabel("Email", { exact: true }).fill("founder@acme.example");
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByText("Choose a password for founder@acme.example.")).toBeVisible();
  await page.getByLabel("New password").fill("a long and fresh passphrase");
  await page.getByRole("button", { name: "Finish setup" }).click();
  await expect(page.getByTestId("onboarding-done")).toHaveText(
    `${NAME} is ready, and you're its first administrator.`,
  );
  await expect(page.getByRole("link", { name: "Sign in" })).toHaveAttribute(
    "href",
    "/env/acme-admin/login",
  );
  const sent = mock.posted.filter((p) => p.key.startsWith("POST"));
  expect(sent.map((p) => p.key)).toEqual([
    `POST /env/acme-admin/v1/foundings/${TOKEN}/verify`,
    `POST /env/acme-admin/v1/foundings/${TOKEN}/complete`,
  ]);
  expect(sent[0]?.body).toEqual({ email: "founder@acme.example", code: "MAGIC-42" });
  const done = sent[1]?.body as Record<string, string>;
  expect(done).toMatchObject({
    email: "founder@acme.example",
    code: "MAGIC-42",
    password: "a long and fresh passphrase",
  });
  // a COSE_Key (EC2, P-256): public coordinates only, no private `d` (-4)
  const cose = Buffer.from(done["device_key"] ?? "", "base64url");
  expect(cose.length).toBeGreaterThan(64);
  expect(cose.includes(Buffer.from([0x23, 0x58, 0x20]))).toBe(false);
});

// TN-89 (5): a wrong code is refused without going on; a typed code works without the fragment
test("a founder without the code in the link types it; a wrong code is refused", async ({
  page,
  mock,
}) => {
  founding(mock);
  await page.goto(`/env/acme-admin/login/founding/${TOKEN}`);
  await page.getByLabel("Email", { exact: true }).fill("founder@acme.example");
  await page.getByLabel("Code from the invitation email").fill("WRONG");
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByRole("alert")).toHaveText(
    "The address or the code doesn't match the invitation.",
  );
  await page.getByLabel("Code from the invitation email").fill("MAGIC-42");
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByLabel("New password")).toBeVisible();
});

// TN-141: a finished or expired founding says so and asks nothing
test("a finished founding and an expired one say so", async ({ page, mock }) => {
  founding(mock, { completed: true });
  await page.goto(`/env/acme-admin/login/founding/${TOKEN}#code=MAGIC-42`);
  await expect(page.getByRole("alert")).toHaveText(
    "This setup is already finished. Sign in instead.",
  );
  await expect(page.getByLabel("Email", { exact: true })).toHaveCount(0);
  mock.json.set(`GET /env/acme-admin/v1/foundings/${TOKEN}`, {
    status: 410,
    body: {
      type: "urn:suiss:access:problem:founding-expired",
      status: 410,
      code: "founding-expired",
    },
  });
  await page.goto(`/env/acme-admin/login/founding/${TOKEN}`);
  await expect(page.getByRole("alert")).toHaveText(
    "This invitation has expired. Ask for a new one.",
  );
});

function invite(mock: import("./mock.js").LoginMock, state = "pending") {
  mock.json.set("GET /env/acme-admin/v1/admin-invites/inv_TOKEN", {
    status: 200,
    body: { tenant: "Acme", environment: "acme-admin", state },
  });
  mock.json.set("POST /env/acme-admin/v1/admin-invites/inv_TOKEN/verify", { status: 204 });
  mock.json.set("POST /env/acme-admin/v1/admin-invites/inv_TOKEN/accept", (body) =>
    (body as { password?: string }).password === "short"
      ? {
          status: 400,
          body: {
            type: "urn:suiss:access:problem:invalid-password",
            status: 400,
            code: "invalid-password",
          },
        }
      : { status: 201, body: { environment: { slug: "acme-admin", kind: "management" } } },
  );
}

// OP-159 m.47 (f)
test("an invited administrator proves the address, chooses a password and joins", async ({
  page,
  mock,
}) => {
  invite(mock);
  await page.goto("/env/acme-admin/login/admin-invite/inv_TOKEN#code=MAGIC-7");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Administer Acme");
  await page.getByLabel("Email", { exact: true }).fill("bob@acme.example");
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByLabel("New password").fill("short");
  await page.getByRole("button", { name: "Accept and create account" }).click();
  await expect(page.getByRole("alert")).toHaveText(
    "This password can't be used. Choose a longer one that you don't use anywhere else.",
  );
  await page.getByLabel("New password").fill("a long and fresh passphrase");
  await page.getByRole("button", { name: "Accept and create account" }).click();
  await expect(page.getByTestId("onboarding-done")).toHaveText(
    "You're now an administrator of Acme.",
  );
  const accepted = mock.posted.filter((p) => p.key.endsWith("/accept")).map((p) => p.body);
  expect(accepted).toHaveLength(2);
  expect(accepted[1]).toMatchObject({ email: "bob@acme.example", code: "MAGIC-7" });
  expect(typeof (accepted[1] as Record<string, unknown>)["device_key"]).toBe("string");
});

test("a used or replaced administrator invitation says so", async ({ page, mock }) => {
  invite(mock, "superseded");
  await page.goto("/env/acme-admin/login/admin-invite/inv_TOKEN#code=MAGIC-7");
  await expect(page.getByRole("alert")).toHaveText(
    "This invitation was already used or replaced by a newer one.",
  );
  await page.goto("/env/acme-admin/login/admin-invite/not a token");
  await expect(page.getByRole("alert")).toHaveText(
    "This invitation link doesn't work. Check that you opened the whole link.",
  );
});

// OP-159 m.47 (b), TN-138: the management environment's sign-in names its tenant and offers no sign-up
test("a management environment's sign-in is titled for its tenant's administrators", async ({
  page,
  mock,
}) => {
  mock.branding = {
    status: 200,
    body: {
      display_name: null,
      logo_uri: null,
      environment: { kind: "management", tenant_name: "Acme" },
    },
  };
  await page.goto("/env/acme-admin/login");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Acme — Administrator sign-in");
  await expect(page.getByRole("link", { name: "Create an account" })).toHaveCount(0);
  await page.goto("/env/acme-admin/login?ui_locales=tr");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Acme — Yönetim girişi");
});

test("a standard environment's sign-in keeps its title and sign-up link", async ({
  page,
  mock,
}) => {
  mock.branding = {
    status: 200,
    body: { display_name: "Acme", logo_uri: null, environment: { kind: "standard" } },
  };
  await page.goto("/env/acme/login");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Sign in");
  await expect(page.getByRole("link", { name: "Create an account" })).toBeVisible();
});

// TN-138: a required second step the account can't give is said plainly, never a blank step
test("a second step the account has none of is explained", async ({ page, mock }) => {
  const ui = example("second-factor");
  mock.secondFactor = {
    ...ui,
    nodes: ui.nodes.filter((n) => n.type === "submit" && n.method === "restart"),
  };
  await page.goto("/");
  await page.getByLabel("Email or username").fill("ada@example.org");
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByLabel("Password").fill("correct horse battery staple");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.getByTestId("second-step-missing")).toContainText(
    "Your account doesn't have one yet",
  );
});

// OP-159 m.48 (a), §10.2.2: the first second step is set up in the sign-in, and its recovery codes
// are read before it continues
test("a required second step is set up during the sign-in", async ({ page, mock }) => {
  mock.secondFactor = example("second-factor-enroll");
  mock.totpDone = example("complete-recovery-codes");
  mock.json.set("POST /v1/account/recovery-codes/acknowledgement", { status: 204 });
  await page.goto("/");
  await page.getByLabel("Email or username").fill("ada@example.org");
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByLabel("Password").fill("correct horse battery staple");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.getByTestId("totp-secret")).toHaveText("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP");
  await expect(page.getByTestId("totp-uri")).toHaveAttribute("href", /^otpauth:\/\/totp\//);
  await expect(page.getByTestId("second-step-missing")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Create a passkey" })).toBeVisible();
  await page.getByLabel("Code from your authenticator app").fill("123456");
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByTestId("recovery-codes").getByRole("listitem")).toHaveCount(10);
  expect(mock.requests).not.toContain("POST /v1/account/recovery-codes/acknowledgement");
  await page.getByRole("button", { name: "I saved them — continue" }).click();
  await expect(page.getByRole("heading", { name: "Signed in" })).toBeVisible();
  expect(mock.requests).toContain("POST /v1/account/recovery-codes/acknowledgement");
});

// OP-83
test("the founding and invitation pages have no WCAG 2.2 AA violations", async ({ page, mock }) => {
  founding(mock);
  invite(mock);
  for (const path of [
    `/env/acme-admin/login/founding/${TOKEN}#code=MAGIC-42`,
    "/env/acme-admin/login/admin-invite/inv_TOKEN",
  ]) {
    await page.goto(path);
    await expect(page.getByLabel("Email", { exact: true })).toBeVisible();
    const a11y = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
      .analyze();
    expect(a11y.violations).toEqual([]);
  }
});
