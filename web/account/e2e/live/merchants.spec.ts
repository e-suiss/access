// OP-156 m.3 (v), OP-153 m.3 (gg), S2 (§8.11, §8.17.7.2), §8.17.5.11, §8.13, INV-24, R8, X8: the
// merchants page, the one-time payment page and the relay status against the running local
// deployment, signed in once as its bootstrap test user. The bootstrap gives no merchant a pay
// Grant, so nobody can charge the test user; a request that would leave a merchant a Grant is
// refused before anything is signed; the public relay status reads as Access reports it.
import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { PASSWORD, REALM } from "./signin.js";

type AxePage = ConstructorParameters<typeof AxeBuilder>[0]["page"];

async function axe(page: Page): Promise<void> {
  const result = await new AxeBuilder({ page: page as unknown as AxePage })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(result.violations.map((v) => `${v.id}: ${v.help}`)).toEqual([]);
}

async function device(page: Page, path: string): Promise<void> {
  await page.goto(`${REALM}/account/${path}`);
  const setUp = page.getByRole("button", { name: "Set up this device" });
  if (await setUp.isVisible()) {
    await setUp.click();
    await page
      .getByRole("dialog", { name: "Check what you're signing" })
      .getByRole("button", { name: "Sign" })
      .click();
  }
}

test.describe("@live merchants and the one-time payment", () => {
  test.skip(PASSWORD === "", "ACCESS_LOCAL_TEST_PASSWORD names the bootstrap test user's password");

  test("@live S2 lists no merchant for the test user and passes axe", async ({ page }) => {
    await device(page, "merchants");
    const list = page.getByTestId("merchants");
    await expect(
      list.getByRole("heading", { name: "Merchants that can charge you" }),
    ).toBeVisible();
    await expect(list).toContainText("No merchant can charge you.");
    await expect(page.locator("[data-party-kind]")).toHaveCount(0);
    await axe(page);
  });

  test("@live a request that would let a merchant charge again is refused before signing", async ({
    page,
  }) => {
    const request = Buffer.from(
      JSON.stringify({
        envelope: "oA",
        intent: { action: { namespace: "access", name: "grant_issue", major: 1 } },
        anchor: "AAAAAAAAAAAAAAAAAAAAAA",
        merchant: "Shop",
      }),
    ).toString("base64url");
    await device(page, `payment#request=${request}`);
    await expect(page.getByRole("alert")).toContainText("can't be paid here as a one-time payment");
    await expect(page.getByRole("button", { name: "Pay once" })).toHaveCount(0);
    await axe(page);
  });

  test("@live the relay status is public, uncached and never makes the hub's rows pending", async ({
    page,
  }) => {
    const r = await page.request.get("/access/v1/relay-status");
    expect(r.status()).toBe(200);
    expect(r.headers()["cache-control"]).toBe("no-store");
    const body = (await r.json()) as { relay_lag_ms: unknown; notifications_delayed: unknown };
    expect(typeof body.notifications_delayed).toBe("boolean");
    await device(page, "authority");
    await expect(page.getByTestId("hub")).toBeVisible();
    await expect(page.getByTestId("notifications-delayed")).toHaveCount(
      body.notifications_delayed === true ? 1 : 0,
    );
    await expect(page.getByText(/pending/i)).toHaveCount(0);
  });
});
