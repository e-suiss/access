// IDP-35, OP-156 m.3 (q), §8.17.9.8: the console's HR screen over mocked management answers;
// the HR rules are the server's (bins/access-server HR walkthroughs).
import AxeBuilder from "@axe-core/playwright";

import { BASE, open } from "./data.js";
import { expect, test } from "./fixtures.js";

/** The issuer Party the mocked sources search accepts for subject selection. */
const id = (n: number) => Buffer.alloc(16, n).toString("base64url");

test.beforeEach(async ({ context, bff }) => {
  await bff.signIn(context, BASE);
  bff.admin.set("realms/acme/hr-sources", {
    items: [
      { name: "workday", issuer: id(34), status: "live", people: 42, version: 1 },
      { name: "legacy", issuer: "aXNzdWVyLWxlZ2FjeQ", status: "live", people: 3, version: 1 },
    ],
  });
  bff.admin.set("realms/acme/hr-connectors", {
    items: [
      { name: "workday-1", source: "workday", vendor: "workday", status: "live", version: 1 },
    ],
  });
});

// OP-156 m.3 (q), §8.17.9.8
test("an HR source shows Sync from HR only when the domain accepts it", async ({ page, bff }) => {
  await open(page, bff, "/console/admin/hr");
  await expect(page.getByRole("heading", { level: 2, name: "HR" })).toBeVisible();
  const workday = page.locator('[data-testid="hr-source"][data-name="workday"]');
  await expect(workday.getByTestId("hr-sync")).toContainText("Sync from HR (workday)");
  const legacy = page.locator('[data-testid="hr-source"][data-name="legacy"]');
  await expect(legacy.getByTestId("hr-sync")).toContainText("Not accepted yet");
  await expect(workday).toContainText("42 people");
  await expect(page.getByTestId("hr-connectors")).toContainText("Workday");
  await expect(page.getByTestId("hr-lifecycle")).toContainText("24 hours");
  expect(bff.writes).toEqual([]);
});

// OP-156 m.3 (q)
test("sources, imports and connectors change only through signed changes", async ({
  page,
  bff,
}) => {
  await open(page, bff, "/console/admin/hr");
  const sign = async () => {
    await page
      .getByRole("dialog", { name: "Review and sign" })
      .getByRole("button", { name: "Sign" })
      .click();
    await expect(page.getByRole("status")).toContainText("Recorded as change");
  };

  await page.getByLabel("Name", { exact: true }).fill("personio-hr");
  await page.getByRole("button", { name: "Register", exact: true }).first().click();
  await sign();

  await page.getByLabel("HR source", { exact: true }).first().fill("workday");
  await page.getByLabel("File", { exact: true }).setInputFiles({
    name: "people.csv",
    mimeType: "text/csv",
    buffer: Buffer.from(
      'employee_id,email,title\r\nE1,ada@acme.example,"Engineer, Platform"\r\nE2,bob@acme.example,Analyst\r\n',
    ),
  });
  await page.getByRole("button", { name: "Import", exact: true }).click();
  await sign();

  await page.getByLabel("Connector name").fill("personio-1");
  await page.getByLabel("HR source", { exact: true }).nth(1).fill("personio-hr");
  await page.getByLabel("HR system").selectOption("personio");
  await page.getByRole("button", { name: "Register", exact: true }).nth(1).click();
  await sign();

  await page
    .locator('[data-testid="hr-source"][data-name="legacy"]')
    .getByRole("button", { name: "Retire legacy" })
    .click();
  await sign();

  expect(bff.writes.map((w) => [w.method, w.path])).toEqual([
    ["POST", "realms/acme/hr-sources"],
    ["POST", "realms/acme/hr-sources/workday/records:csv"],
    ["POST", "realms/acme/hr-connectors"],
    ["POST", "realms/acme/hr-sources/legacy/retire"],
  ]);
  expect(bff.writes[0]?.body).toMatchObject({ name: "personio-hr" });
  expect(bff.writes[1]?.body).toMatchObject({ records: 2 });
  expect(bff.writes[1]?.body).toMatchObject({ file: expect.any(String) });
  expect(bff.writes[2]?.body).toMatchObject({
    name: "personio-1",
    source: "personio-hr",
    vendor: "personio",
  });

  const result = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(result.violations.map((v) => `${v.id}: ${v.help}`)).toEqual([]);
});
