// OP-153 m.3 (gg), (y), (z); S10, S11 (§8.5, X32, X36), TN-107: the sign-in methods and the
// sign-ins list against the running local deployment, signed in as its bootstrap test user
// through the hosted login's own API.
import AxeBuilder from "@axe-core/playwright";
import { expect, type APIRequestContext, type Page, test } from "@playwright/test";

const REALM = "/realms/acme";
const IDENTIFIER = process.env["ACCESS_LIVE_IDENTIFIER"] ?? "test@acme.example";
const PASSWORD = process.env["ACCESS_LOCAL_TEST_PASSWORD"] ?? "";

// @axe-core/playwright pins a newer playwright-core than @playwright/test; the page is the same
type AxePage = ConstructorParameters<typeof AxeBuilder>[0]["page"];

async function post(
  request: APIRequestContext,
  origin: string,
  path: string,
  body?: unknown,
): Promise<Record<string, unknown>> {
  const r = await request.post(`${origin}${path}`, {
    headers: {
      origin,
      "sec-fetch-site": "same-origin",
      "content-type": "application/json",
      "idempotency-key": crypto.randomUUID(),
    },
    ...(body === undefined ? {} : { data: body }),
  });
  expect(r.status(), `${path}: ${await r.text()}`).toBeLessThan(300);
  return (await r.json()) as Record<string, unknown>;
}

async function signIn(page: Page, origin: string): Promise<void> {
  const request = page.context().request;
  const started = await post(request, origin, `${REALM}/v1/login/flows`);
  const identified = await post(request, origin, `${REALM}${String(started["action"])}`, {
    method: "identifier",
    fields: { identifier: IDENTIFIER },
  });
  const done = await post(request, origin, `${REALM}${String(identified["action"])}`, {
    method: "password",
    fields: { password: PASSWORD },
  });
  expect(done["step"]).toBe("complete");
}

test.describe("@live sign-in methods and sign-ins", () => {
  test.skip(PASSWORD === "", "ACCESS_LOCAL_TEST_PASSWORD names the bootstrap test user's password");

  test("@live S11 lists the account's sign-in methods from the realm's own routes", async ({
    page,
    baseURL,
  }) => {
    await signIn(page, baseURL ?? "");
    await page.goto(`${REALM}/account`);
    const methods = page.getByTestId("sign-in-methods");
    await expect(methods.getByTestId("password")).toContainText("A password is set.");
    await expect(methods.getByTestId("passkeys")).toBeVisible();
    await expect(methods.getByTestId("authenticator")).toBeVisible();
    await expect(page.getByTestId("linked-sign-ins")).toBeVisible();
    await expect(page.getByTestId("connected-apps")).toBeVisible();
  });

  test("@live a write without a fresh confirmation goes to the hosted login", async ({
    page,
    baseURL,
  }) => {
    await signIn(page, baseURL ?? "");
    await page.goto(`${REALM}/account`);
    const password = page.getByTestId("password");
    await password.getByRole("button", { name: "Change password" }).click();
    await password.getByLabel("New password").fill(PASSWORD);
    await password.getByRole("button", { name: "Save" }).click();
    await page.waitForURL(/\/login\?reason=reauthenticate/);
  });

  test("@live S10 shows this device's sign-in with its end time and no End button", async ({
    page,
    baseURL,
  }) => {
    await signIn(page, baseURL ?? "");
    await page.goto(`${REALM}/account`);
    const here = page.locator('[data-testid="sign-in-row"][data-current="true"]');
    await expect(here.locator("strong")).toHaveText("Sign-in on this device");
    await expect(here).toContainText("Signed in until");
    await expect(here.getByRole("button", { name: /End this sign-in/ })).toHaveCount(0);
    await expect(page.getByText(/trusted/i)).toHaveCount(0);
  });

  test("@live the account page passes axe with S10 and S11 drawn", async ({ page, baseURL }) => {
    await signIn(page, baseURL ?? "");
    await page.goto(`${REALM}/account`);
    await expect(page.getByTestId("sign-in-row").first()).toBeVisible();
    const result = await new AxeBuilder({ page: page as unknown as AxePage })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
      .analyze();
    expect(result.violations.map((v) => v.id)).toEqual([]);
  });
});
