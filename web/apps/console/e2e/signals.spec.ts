// OP-156 m.3 (r), E38, §8.10: the console's signal sources over mocked management answers; what
// a source's Claims do is the server's (bins/access-server signal source walkthroughs).
import { expect, test } from "./fixtures.js";
import { BASE, open } from "./data.js";

test.beforeEach(async ({ context, bff }) => {
  await bff.signIn(context, BASE);
});

// OP-156 m.3 (r)
test("a signal source is registered and retired only by signed changes", async ({ page, bff }) => {
  await open(page, bff, "/console/admin/sign-in");
  const panel = page.getByRole("region", { name: "Signal sources" });
  await expect(panel.getByTestId("signal-sources")).toContainText("Acme MDM");
  await expect(panel.getByTestId("signal-sources")).toContainText("posture_mdm");
  await expect(panel.getByTestId("signal-posture-note")).toContainText(
    "Compliant per Acme MDM (statement)",
  );
  expect(bff.writes).toEqual([]);

  await panel.getByLabel("Source name").fill("fraud");
  await panel.getByLabel("Kind").selectOption("risk");
  await panel.getByLabel("Provider").fill("Fraud Signals");
  await panel.getByLabel("Issuer", { exact: true }).fill("CAgICAgICAgICAgICAgICA");
  await panel.getByRole("button", { name: "Register source" }).click();
  await page
    .getByRole("dialog", { name: "Review and sign" })
    .getByRole("button", { name: "Sign" })
    .click();
  await expect(panel.getByRole("status")).toContainText("Recorded as change");

  await panel.getByRole("button", { name: "Retire acme-mdm" }).click();
  await page
    .getByRole("dialog", { name: "Review and sign" })
    .getByRole("button", { name: "Sign" })
    .click();
  await expect(panel.getByRole("status")).toContainText("Recorded as change");

  expect(bff.writes.map((w) => [w.method, w.path])).toEqual([
    ["POST", "realms/acme/signal-sources"],
    ["POST", "realms/acme/signal-sources/acme-mdm/retire"],
  ]);
  expect(bff.writes[0]?.body).toMatchObject({
    name: "fraud",
    kind: "risk",
    provider: "Fraud Signals",
    issuer: "CAgICAgICAgICAgICAgICA",
  });
});
