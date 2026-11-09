// OP-153 m.3 (gg), (w), TN-128, TN-131, G57, OP-149 m.6: the account pages against the running
// local deployment (deploy/compose/access.yaml), signed in once as its bootstrap test user through
// the hosted login's own API (signin.setup.ts). The cookie reads the Account section; it reads and
// changes no authority without the browser's device key, and setting one up shows what the device
// signs before anything is signed.
import { expect, test } from "@playwright/test";

import { PASSWORD, REALM } from "./signin.js";

test.describe("@live account pages", () => {
  test.skip(PASSWORD === "", "ACCESS_LOCAL_TEST_PASSWORD names the bootstrap test user's password");

  test.describe("without a session", () => {
    test.use({ storageState: { cookies: [], origins: [] } });

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
  });

  test("@live the Account section reads the realm's own privacy routes with the cookie", async ({
    page,
  }) => {
    await page.goto(`${REALM}/account`);
    await expect(page.getByTestId("brand")).toHaveText("acme");
    await expect(page.getByTestId("preferences").getByRole("checkbox")).toHaveCount(12);
    await expect(page.getByTestId("deletion")).toBeVisible();
    await expect(page.getByTestId("security-history")).toBeVisible();
  });

  test("@live the cookie alone reads and changes no authority", async ({ page }) => {
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

  test("@live a fresh two-factor sign-in sees what a device signs, and Cancel signs nothing", async ({
    page,
  }) => {
    await page.goto(`${REALM}/account/authority`);
    await page.getByRole("button", { name: "Set up this device" }).click();
    const dialog = page.getByRole("dialog", { name: "Check what you're signing" });
    await expect(dialog).toContainText("access.instance_create");
    await dialog.getByRole("button", { name: "Cancel" }).click();
    await expect(dialog).toHaveCount(0);
    await expect(page.getByTestId("device-setup")).toBeVisible();
    await expect(page.getByTestId("device-message")).toHaveCount(0);
  });
});
