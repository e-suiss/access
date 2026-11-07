import { expect, test } from "./fixtures.js";

test.skip(process.platform !== "linux", "visual baselines are Linux-only");

test("console sign-in matches the visual baseline", async ({ page }) => {
  await page.goto("/console/");
  await expect(page.getByLabel("Realm")).toBeVisible();
  await expect(page).toHaveScreenshot("console-sign-in.png", { fullPage: true });
});
