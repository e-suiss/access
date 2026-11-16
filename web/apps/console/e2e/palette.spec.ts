// OP-159 m.46 (g), IA-5: the command palette lists only the screens the probes allowed and the
// environments the switcher offers; choosing a screen goes there and asks no probe again
import AxeBuilder from "@axe-core/playwright";

import { BASE, open } from "./data.js";
import { expect, test } from "./fixtures.js";

test.beforeEach(async ({ context, bff }) => {
  await bff.signIn(context, BASE);
});

test("Ctrl+K lists only the visible screens and goes to the one chosen", async ({ page, bff }) => {
  await open(page, bff, "/console/acme/admin/roles", ["idp.environment/branding"]);
  const probes = bff.probesAsked.length;
  await page.keyboard.press("Control+k");
  const palette = page.getByRole("dialog", { name: "Go to" });
  await expect(palette).toBeVisible();
  await expect(palette.getByRole("option")).toHaveText([/Sign-in settings/]);
  await expect(palette.getByRole("option", { name: /Roles/ })).toHaveCount(0);
  const result = await new AxeBuilder({ page })
    .include('[role="dialog"]')
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(
    result.violations.flatMap((v) => v.nodes.map((n) => `${v.id}: ${n.html} ${n.failureSummary}`)),
  ).toEqual([]);
  await palette.getByRole("combobox").fill("sign");
  await page.keyboard.press("Enter");
  await expect(palette).toBeHidden();
  await expect(page).toHaveURL(/\/console\/acme\/admin\/sign-in$/);
  await expect(page.getByRole("heading", { level: 2, name: "Sign-in settings" })).toBeVisible();
  expect(bff.probesAsked.length).toBe(probes);
});
