import { expect, test } from "./fixtures.js";

test.skip(process.platform !== "linux", "visual baselines are Linux-only");

test("console home matches the visual baseline", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByTestId("kernel-api-version")).toHaveText("0.0");
  await expect(page).toHaveScreenshot("console-home.png", { fullPage: true });
});
