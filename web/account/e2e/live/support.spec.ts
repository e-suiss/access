// OP-157 m.3 (cc), (f), m.6 (i), OP-153 m.3 (gg), §8.16, TN-137, XI-7, X37: support access
// against the running local deployment, signed in once as its bootstrap test user
// (signin.setup.ts). The bootstrap made a support operator in its support organization, the
// realm's case system and the test user's open case; before this run the image workflow had the
// operator ask, the test user's device give and the operator's own Instance view the account
// (access-local-client support-episode). Here the person reads that access and its use under the
// operator's name, the operator asks again, the person gives it on the page and revokes both.
import AxeBuilder from "@axe-core/playwright";
import { expect, request as http, test, type Page } from "@playwright/test";

import { PASSWORD, REALM, signInWithPassword } from "./signin.js";

type AxePage = ConstructorParameters<typeof AxeBuilder>[0]["page"];

const OPERATOR = process.env["ACCESS_LIVE_SUPPORT_OPERATOR"];
const SUBJECT = process.env["ACCESS_LIVE_TEST_SUBJECT"];
const CASE_SYSTEM = process.env["ACCESS_LIVE_SUPPORT_CASE_SYSTEM"] ?? "local-desk";
const CASE = process.env["ACCESS_LIVE_SUPPORT_CASE"] ?? "4411";
const NAMED = "Mehmet Y. (Acme Support)";

async function axe(page: Page): Promise<void> {
  const result = await new AxeBuilder({ page: page as unknown as AxePage })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(result.violations.map((v) => `${v.id}: ${v.help}`)).toEqual([]);
}

const sign = (page: Page) =>
  page
    .getByRole("dialog", { name: "Check what you're signing" })
    .getByRole("button", { name: "Sign" })
    .click();

async function setUpDevice(page: Page): Promise<void> {
  await page.goto(`${REALM}/account/authority`);
  await page.getByRole("button", { name: "Set up this device" }).click();
  await sign(page);
  await expect(page.getByTestId("hub")).toBeVisible();
}

test.describe("@live support access", () => {
  // the block toggle and the operator's request reach the same person
  test.describe.configure({ mode: "serial" });
  test.skip(PASSWORD === "", "ACCESS_LOCAL_TEST_PASSWORD names the bootstrap test user's password");

  test("@live the person's support page answers, blocks and is accessible", async ({ page }) => {
    await setUpDevice(page);
    await page.goto(`${REALM}/account/support`);
    await expect(page.getByTestId("support-access")).toBeVisible();
    await axe(page);
    await page.getByTestId("support-block").click();
    await expect(page.getByText("Support teams can't ask for access")).toBeVisible();
    await page.getByTestId("support-block").click();
    await expect(page.getByText("Support teams can't ask for access")).toHaveCount(0);
  });

  // §8.16, TN-137 (1), (4), XI-7, X37, Ek B 5524, 5527, 5529, 5613
  test("@live an operator's request is given on the person's page, its use names the operator, and the person revokes it", async ({
    page,
    baseURL,
  }) => {
    test.skip(
      OPERATOR === undefined || SUBJECT === undefined,
      "ACCESS_LIVE_SUPPORT_OPERATOR and ACCESS_LIVE_TEST_SUBJECT name the bootstrap's support operator and test user",
    );
    test.setTimeout(120_000);
    const origin = baseURL ?? "";
    await setUpDevice(page);

    // §8.16 S6: the episode's view is the operator's, never the person's
    await page.goto(`${REALM}/account/activity`);
    const use = page
      .getByTestId("activity")
      .getByTestId("use")
      .filter({ hasText: `by ${NAMED} on your behalf` });
    await expect(use.first()).toContainText(`Viewed your account — by ${NAMED} on your behalf`);
    await expect(use.first()).not.toContainText("You acted");

    // §8.16 S2: what the person gave, with whom and for which case
    await page.goto(`${REALM}/account/support`);
    const active = page.getByTestId("support-active");
    await expect(active.first()).toContainText(`${NAMED} · case ${CASE}`);
    await expect(active.first()).toContainText("View only");

    // XI-7: the operator only asks; the person is invited to their own page
    const operator = await http.newContext({ baseURL: origin, ignoreHTTPSErrors: true });
    await signInWithPassword(operator, origin, OPERATOR ?? "", PASSWORD);
    const asked = await operator.post(`${REALM}/v1/support/requests`, {
      headers: {
        origin,
        "sec-fetch-site": "same-origin",
        "content-type": "application/json",
        "idempotency-key": crypto.randomUUID(),
      },
      data: {
        subject: SUBJECT,
        case_system: CASE_SYSTEM,
        case: CASE,
        scope: "read",
        minutes: 30,
      },
    });
    expect(asked.status(), await asked.text()).toBe(201);
    expect(((await asked.json()) as { state: string }).state).toBe("waiting");
    await operator.dispose();

    // §8.16 S1, TN-137 (1)
    await page.reload();
    const sheet = page.getByRole("dialog", { name: "Give Acme Support access" });
    await expect(sheet).toContainText(`case ${CASE}`);
    await expect(sheet.getByRole("button", { name: /approve/i })).toHaveCount(0);
    await sheet.getByRole("button", { name: "Give access", exact: true }).click();
    await sign(page);
    await expect(active).toHaveCount(2);
    await axe(page);

    // §8.16 #11: each is ended by the person's own revoke
    for (let left = 2; left > 0; left -= 1) {
      await active.first().getByRole("button", { name: "Revoke" }).click();
      await sign(page);
      await expect(active).toHaveCount(left - 1);
    }
    await expect(page.getByTestId("support-past").first()).toContainText(
      "You revoked support access",
    );
  });
});
