// OP-156 m.3 (v), OP-153 m.3 (gg), S2 (§8.11, §8.17.7.2), §8.17.5.11, §8.13, INV-24, R8, X8: the
// merchants page, the one-time payment page and the relay status against the running local
// deployment. A session holds one device Instance and the shared session's device is set up by
// another spec, so this one signs the bootstrap test user in on its own and sets its device up
// once. The bootstrap gives no merchant a pay Grant, so nobody can charge the test user; a request
// that would leave a merchant a Grant is refused before anything is signed; the public relay
// status reads as Access reports it.
import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { PASSWORD, REALM, signIn } from "./signin.js";

type AxePage = ConstructorParameters<typeof AxeBuilder>[0]["page"];

async function axe(page: Page): Promise<void> {
  const result = await new AxeBuilder({ page: page as unknown as AxePage })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(result.violations.map((v) => `${v.id}: ${v.help}`)).toEqual([]);
}

async function setUpDevice(page: Page): Promise<void> {
  await page.goto(`${REALM}/account/authority`);
  await page.getByRole("button", { name: "Set up this device" }).click();
  await page
    .getByRole("dialog", { name: "Check what you're signing" })
    .getByRole("button", { name: "Sign" })
    .click();
  await expect(page.getByTestId("hub")).toBeVisible();
}

test.describe("@live merchants and the one-time payment", () => {
  test.skip(PASSWORD === "", "ACCESS_LOCAL_TEST_PASSWORD names the bootstrap test user's password");
  test.use({ storageState: { cookies: [], origins: [] } });

  test("@live nobody can charge the test user, a repeat charge is refused before signing, and the relay status is public", async ({
    page,
    baseURL,
  }) => {
    // TN-59: up to one TOTP step of waiting
    test.setTimeout(120_000);
    await signIn(page.request, baseURL ?? "");
    await setUpDevice(page);

    const r = await page.request.get("/access/v1/relay-status");
    expect(r.status()).toBe(200);
    expect(r.headers()["cache-control"]).toBe("no-store");
    const body = (await r.json()) as { relay_lag_ms: unknown; notifications_delayed: unknown };
    expect(typeof body.notifications_delayed).toBe("boolean");
    await expect(page.getByTestId("notifications-delayed")).toHaveCount(
      body.notifications_delayed === true ? 1 : 0,
    );
    await expect(page.getByText(/pending/i)).toHaveCount(0);

    await page.goto(`${REALM}/account/merchants`);
    const list = page.getByTestId("merchants");
    await expect(
      list.getByRole("heading", { name: "Merchants that can charge you" }),
    ).toBeVisible();
    await expect(list).toContainText("No merchant can charge you.");
    await expect(page.locator("[data-party-kind]")).toHaveCount(0);
    await axe(page);

    const request = Buffer.from(
      JSON.stringify({
        envelope: "oA",
        intent: { action: { namespace: "access", name: "grant_issue", major: 1 } },
        anchor: "AAAAAAAAAAAAAAAAAAAAAA",
        merchant: "Shop",
      }),
    ).toString("base64url");
    await page.goto(`${REALM}/account/payment#request=${request}`);
    await expect(page.getByRole("alert")).toContainText("can't be paid here as a one-time payment");
    await expect(page.getByRole("button", { name: "Pay once" })).toHaveCount(0);
    await axe(page);
  });
});
