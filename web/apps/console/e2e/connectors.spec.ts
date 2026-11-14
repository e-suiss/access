// §18.3, E22, IDP-39, OP-156 m.3 (x), Ek B 5238: one catalogue page of the enterprise connectors
// under Developer ▸ Integrations; it lists the products and what Access gives each, and calls
// nothing of its own.
import { expect, test } from "./fixtures.js";
import { BASE, open } from "./data.js";

test.beforeEach(async ({ context, bff }) => {
  await bff.signIn(context, BASE);
});

test("integrations list the enterprise connectors and what Access gives each", async ({
  page,
  bff,
}) => {
  const asked: string[] = [];
  page.on("request", (r) => asked.push(new URL(r.url()).pathname));
  await open(page, bff, "/console/developer/integrations");
  const panel = page.getByRole("region", { name: "Enterprise connectors" });
  await expect(panel).toBeVisible();
  const rows = panel.getByTestId("connectors").locator("tbody tr");
  await expect(rows).toHaveCount(9);
  await expect(panel.getByRole("row", { name: /Privileged access \(PAM\)/ })).toContainText(
    "Teleport, CyberArk",
  );
  await expect(panel.getByRole("row", { name: /Secret stores/ })).toContainText("secret.release");
  await expect(panel.getByRole("row", { name: /SIEM/ })).toContainText("Admin ▸ SIEM export");
  await expect(panel.getByRole("row", { name: /Identity governance/ })).toContainText(
    "a campaign grants nothing",
  );
  expect(asked.filter((p) => p.includes("connector"))).toEqual([]);
});
