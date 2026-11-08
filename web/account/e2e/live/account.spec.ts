// OP-153 m.3 (gg), (w), TN-128, TN-131, G57: the account pages against the running local
// deployment (deploy/compose/access.yaml), signed in as its bootstrap test user through the
// hosted login's own API. The cookie reads the Account section; it reads and changes no
// authority without the browser's device key, and an AAL1 sign-in cannot set one up.
import { expect, type APIRequestContext, type Page, test } from "@playwright/test";

const REALM = "/realms/acme";
const IDENTIFIER = process.env["ACCESS_LIVE_IDENTIFIER"] ?? "test@acme.example";
const PASSWORD = process.env["ACCESS_LOCAL_TEST_PASSWORD"] ?? "";

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

/** The hosted login's JSON steps: start, identifier, password (TN-96, TN-132). */
async function signIn(page: Page, origin: string): Promise<void> {
  const request = page.context().request;
  const started = await post(request, origin, `${REALM}/v1/login/flows`);
  const identified = await post(request, origin, `${REALM}${String(started["action"])}`, {
    method: "identifier",
    fields: { identifier: IDENTIFIER },
  });
  expect(identified["step"]).toBe("authenticate");
  const done = await post(request, origin, `${REALM}${String(identified["action"])}`, {
    method: "password",
    fields: { password: PASSWORD },
  });
  expect(done["step"]).toBe("complete");
}

test.describe("@live account pages", () => {
  test.skip(PASSWORD === "", "ACCESS_LOCAL_TEST_PASSWORD names the bootstrap test user's password");

  test("@live the shell is served with its headers and shows nothing without a session", async ({
    page,
  }) => {
    const r = await page.goto(`${REALM}/account`);
    expect(r?.status()).toBe(200);
    const csp = r?.headers()["content-security-policy"] ?? "";
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("'wasm-unsafe-eval'");
    await expect(page.getByTestId("signed-out")).toBeVisible();
    const session = await page.request.get(`${REALM}/account/api/session`);
    expect(session.status()).toBe(401);
  });

  test("@live the Account section reads the realm's own privacy routes with the cookie", async ({
    page,
    baseURL,
  }) => {
    await signIn(page, baseURL ?? "");
    await page.goto(`${REALM}/account`);
    await expect(page.getByTestId("brand")).toHaveText("acme");
    await expect(page.getByTestId("preferences").getByRole("checkbox")).toHaveCount(12);
    await expect(page.getByTestId("deletion")).toBeVisible();
    await expect(page.getByTestId("security-history")).toBeVisible();
  });

  test("@live the cookie alone reads and changes no authority", async ({ page, baseURL }) => {
    const origin = baseURL ?? "";
    await signIn(page, origin);
    await page.goto(`${REALM}/account`);
    await expect(page.getByTestId("brand")).toBeVisible();
    const answers = await page.evaluate(async (realm) => {
      const csrf =
        document.cookie
          .split(";")
          .map((c) => c.trim().split("="))
          .find(([n]) => n === "__Host-access-account-csrf")?.[1] ?? "";
      const send = async (path: string, body: unknown, token = csrf) => {
        const r = await fetch(`${realm}/account/api${path}`, {
          method: "POST",
          headers: { "content-type": "application/json", "x-csrf-token": token },
          body: JSON.stringify(body),
        });
        const j = (await r.json()) as { code?: string };
        return [r.status, j.code ?? ""] as const;
      };
      return {
        read: await send("/proxy/adp/search/inventory", { context: { mode: "check" } }),
        write: await send("/proxy/adp/evaluation", { context: { mode: "commit" } }),
        forged: await send("/instances/challenge", { key: "x" }, "forged"),
      };
    }, REALM);
    expect(answers.read).toEqual([403, "account-instance-required"]);
    expect(answers.write).toEqual([403, "account-instance-required"]);
    expect(answers.forged).toEqual([403, "csrf-token-invalid"]);
  });

  test("@live a password-only sign-in is asked to confirm again before a device is set up", async ({
    page,
    baseURL,
  }) => {
    await signIn(page, baseURL ?? "");
    await page.goto(`${REALM}/account/authority`);
    await page.getByRole("button", { name: "Set up this device" }).click();
    await expect(page.getByTestId("device-message")).toHaveText(
      "Confirm it's you again, then set up this device.",
    );
  });
});
