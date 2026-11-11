// §8.17.6, §9.14.5, §11.4.5, §11.6, U7, E32, OP-157 m.3 (l), OP-153 m.3 (gg): the Approval
// Surface against the running local deployment through its real router; nothing is mocked.
// ACCESS_LIVE_APPROVAL names a pushed request (request, redirect_uri and state query) that the
// image workflow pushed for the bootstrap test user's allowed Exercise with the test user's
// device contribution (access-local-client push, OP-157 m.6 (i)); the test user signs in and
// opens it. Without it only the routes and the page script are checked.
import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { PASSWORD, signIn } from "./signin.js";

const REALM = process.env["ACCESS_LIVE_REALM"] ?? "/realms/acme";
const PUSHED = process.env["ACCESS_LIVE_APPROVAL"];
const wcag22aa = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];

async function clean(page: Page): Promise<void> {
  expect((await new AxeBuilder({ page }).withTags(wcag22aa).analyze()).violations).toEqual([]);
}

test.describe("@live approval surface", () => {
  // §11.4.5, §11.6, EI-18, Ek B 5426
  test("@live consent is the approval surface and never a form post", async ({ page }) => {
    const query = "request=urn%3Ax&redirect_uri=https%3A%2F%2Fshop.example%2Fa&state=s";
    const r = await page.request.get(`${REALM}/consent?${query}`, { maxRedirects: 0 });
    expect(r.status()).toBe(303);
    expect(r.headers()["location"]).toContain(`/v1/approve?${query}`);
    const login = await page.goto(`${REALM}/login`);
    expect(login?.status()).toBe(200);
    const origin = new URL(page.url()).origin;
    const posted = await page.request.post(`${REALM}/consent`, {
      form: { approve: "yes" },
      headers: { origin },
    });
    expect(posted.status()).toBe(405);
    expect(posted.headers()["allow"]).toBe("GET");
  });

  // §8.17.6.1, §8.17.6.3, E32, Ek B 5420, 5555, 5557, 5630
  test("@live the page script shows the quorum, eligibility and assurance lines", async ({
    page,
  }) => {
    const r = await page.request.get(`${REALM}/v1/approve/app.js`);
    expect(r.status()).toBe(200);
    const js = await r.text();
    for (const part of [
      "v.capacity",
      "v.still_needed",
      "v.counts_as_one",
      "v.does_not",
      "v.assurance_action",
      "v.requester_note",
      "v.blocked",
    ]) {
      expect(js, part).toContain(part);
    }
    expect(js.toLowerCase()).not.toContain("independent");
    expect(js).not.toContain("innerHTML");
    const unknown = await page.goto(
      `${REALM}/v1/approve?request=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aunknown&redirect_uri=https%3A%2F%2Fshop.example%2Fa&state=s`,
    );
    expect(unknown?.status()).not.toBe(501);
  });

  // U7, §8.17.6.4, Ek B 5467, 5555, 5629, 5630
  test("@live a pushed request shows its render, what is still needed and one act", async ({
    page,
    baseURL,
  }) => {
    test.skip(PUSHED === undefined, "ACCESS_LIVE_APPROVAL names no pushed request");
    test.skip(
      PASSWORD === "",
      "ACCESS_LOCAL_TEST_PASSWORD names the bootstrap test user's password",
    );
    // TN-59: up to one TOTP step of waiting
    test.setTimeout(120_000);
    await signIn(page.request, baseURL ?? "", REALM);
    const r = await page.goto(`${REALM}/v1/approve?${PUSHED ?? ""}`);
    expect(r?.status()).toBe(200);
    await expect(page.locator("dl.render dd.material").first()).toBeVisible();
    await expect(page.locator("p.capacity")).toContainText("You approve as:");
    const button = page.getByRole("button");
    const blocked = page.locator("p.blocked");
    await expect(button.or(blocked)).toBeVisible();
    if ((await blocked.count()) > 0) {
      await expect(blocked).toContainText("can't");
      await expect(button).toHaveCount(0);
    } else {
      await expect(button).toHaveText(/^Confirm with your (passkey|security key)$/);
    }
    await expect(page.locator("section.requester-note h2")).toHaveText("Requester's note");
    expect((await page.content()).toLowerCase()).not.toContain("independent");
    await clean(page);
  });
});
