// TN-114, OP-157 m.3 (t): the Roles screen's staged opening of admin roles over mocked
// management answers; the rule is the server's (bins/access-server delegated tests).
import { BASE, open } from "./data.js";
import { expect, test } from "./fixtures.js";

test.beforeEach(async ({ context, bff }) => {
  await bff.signIn(context, BASE);
});

// OP-157 m.3 (t), §12.5.2
test("opening and closing admin roles are signed changes", async ({ page, bff }) => {
  await open(page, bff, "/console/admin/roles");
  await expect(page.getByRole("heading", { name: "Delegated administration" })).toBeVisible();
  expect(bff.writes).toEqual([]);

  await page.getByRole("button", { name: "Allow admin roles" }).click();
  await page
    .getByRole("dialog", { name: "Review and sign" })
    .getByRole("button", { name: "Sign" })
    .click();
  await expect(page.getByRole("status")).toContainText("Recorded as change");
  expect(bff.writes.map((w) => [w.method, w.path])).toEqual([
    ["PUT", "realms/acme/settings/delegated-admin"],
  ]);
  expect(bff.writes[0]?.body).toMatchObject({ enabled: true });
});
