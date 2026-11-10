// OP-156 m.3 (i), §10.2.4: the custom domains panel shows the two records to publish for a
// domain that is not served yet and the certificate's end for a served one.
import { expect, test } from "./fixtures.js";
import { BASE, open } from "./data.js";

test.beforeEach(async ({ context, bff }) => {
  await bff.signIn(context, BASE);
});

// OP-156 m.3 (i)
test("a pending domain shows its records and a served one its certificate", async ({
  page,
  bff,
}) => {
  await open(page, bff, "/console/admin/sign-in");
  const panel = page.getByRole("region", { name: "Custom domains" });
  await expect(panel.getByTestId("domain-txt").first()).toHaveText("challenge-value");
  await expect(panel.getByTestId("domain-cname").first()).toContainText("acme.access.test");
  await expect(panel.getByTestId("domain-state").nth(1)).toContainText("2027-02-01");
  await expect(panel.getByRole("button", { name: /passkeys/ })).toHaveCount(1);
});
