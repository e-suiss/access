// INV-28, TN-93, OP-157 m.3 (h): the console's break-glass screen over mocked management
// answers; the rules are the server's (bins/access-server idp break-glass tests).
import AxeBuilder from "@axe-core/playwright";

import { BASE, open } from "./data.js";
import { expect, test } from "./fixtures.js";

const ORG = "CgoKCgoKCgoKCgoKCgoKCg";
const MEMBER = "AgICAgICAgICAgICAgICAg";
const USE = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";

test.beforeEach(async ({ context, bff }) => {
  await bff.signIn(context, BASE);
  bff.admin.set("realms/acme/breakglass/accounts", {
    items: [
      {
        account_id: "usr_01j00000000000000000000000",
        member: MEMBER,
        organization: ORG,
        organization_name: "Acme Security",
        marked_at: 1_800_000_000_000,
        position: 4,
      },
    ],
  });
  bff.admin.set("realms/acme/breakglass/reviews", {
    items: [
      {
        exercise: USE,
        drill: false,
        grant: "AwMDAwMDAwMDAwMDAwMDAw",
        actor: "RERERERERERERERERERERA",
        used_at: 1_800_000_000_000,
        due_at: 1_800_259_200_000,
        state: "pending",
        classification: null,
        reviewer: null,
      },
    ],
  });
});

// OP-157 m.3 (h), §12.3.8 (4)
test("a mark and a review change only through signed changes", async ({ page, bff }) => {
  await open(page, bff, "/console/admin/breakglass");
  await expect(page.getByRole("heading", { level: 2, name: "Break-glass" })).toBeVisible();
  await expect(page.getByTestId("breakglass-accounts")).toContainText("Acme Security");
  await expect(page.getByTestId("breakglass-minimum-two")).toContainText("at least two");
  expect(bff.writes).toEqual([]);

  await page
    .getByTestId("breakglass-reviews")
    .getByRole("button", { name: "Review as Emergency" })
    .click();
  await page
    .getByRole("dialog", { name: "Review and sign" })
    .getByRole("button", { name: "Sign" })
    .click();
  await expect(page.getByRole("status")).toContainText("Recorded as change");

  await page.getByLabel("Organization").fill(ORG);
  await page.getByLabel("Member").fill(MEMBER);
  await page.getByRole("button", { name: "Mark for break-glass" }).click();
  await page
    .getByRole("dialog", { name: "Review and sign" })
    .getByRole("button", { name: "Sign" })
    .click();
  await expect(page.getByRole("status")).toContainText("Recorded as change");

  expect(bff.writes.map((w) => [w.method, w.path])).toEqual([
    ["POST", `realms/acme/breakglass/reviews/${USE}`],
    ["POST", "realms/acme/breakglass/accounts"],
  ]);
  expect(bff.writes[0]?.body).toMatchObject({ classification: "emergency" });
  expect(bff.writes[1]?.body).toMatchObject({ organization: ORG, member: MEMBER });

  const result = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(result.violations.map((v) => `${v.id}: ${v.help}`)).toEqual([]);
});
