// OP-159 m.43 (b), m.42 (c), IA-5: the environment switcher in the console header. It lists the environments
// this browser signed in to (and, in a primary environment, the tenant's: tenant.spec.ts);
// choosing one opens that environment's console, which never switches the session silently.

import { BASE } from "./data.js";
import { expect, test } from "./fixtures.js";

const KNOWN = "access-console-environments";

// OP-159 m.43 (b)
test("the switcher lists the environments this browser signed in to and opens the chosen one", async ({
  page,
  context,
  bff,
}) => {
  await context.addInitScript((key) => {
    if (localStorage.getItem(key) === null) {
      localStorage.setItem(key, JSON.stringify(["shop", "Not An Environment", "api", "acme"]));
    }
  }, KNOWN);
  await bff.signIn(context, BASE);
  await page.goto("/console/acme");
  await expect(page.getByRole("heading", { level: 1, name: "Authority" })).toBeVisible();
  const switcher = page.getByRole("button", { name: "Environment acme: switch environment" });
  await expect(switcher).toHaveText("acme");
  await switcher.click();
  const menu = page.getByRole("menu");
  await expect(menu.getByRole("group", { name: "Signed in from this browser" })).toBeVisible();
  await expect(menu.getByRole("menuitemradio")).toHaveText(["acme", "shop"]);
  await expect(menu.getByRole("menuitemradio", { name: "acme" })).toHaveAttribute(
    "aria-checked",
    "true",
  );
  await expect(menu.getByRole("group", { name: "Your tenant" })).toHaveCount(0);
  expect(await page.evaluate((key) => localStorage.getItem(key), KNOWN)).toBe(
    JSON.stringify(["acme", "shop"]),
  );
  await menu.getByRole("menuitemradio", { name: "shop" }).click();
  await expect(page).toHaveURL(`${BASE}/console/shop`);
  await expect(page.getByRole("status")).toHaveText(
    "You're signed in to acme. This address is the console of shop.",
  );
  // TN-119
  expect(bff.seen.some((s) => s.path.startsWith("/proxy/admin/platform/"))).toBe(false);
});

// OP-159 m.43 (b): an unreadable store is no list; the current environment is still there
test("a browser that refuses storage still shows the current environment", async ({
  page,
  context,
  bff,
}) => {
  await context.addInitScript(() => {
    Object.defineProperty(window, "localStorage", {
      get() {
        throw new DOMException("denied", "SecurityError");
      },
    });
  });
  await bff.signIn(context, BASE);
  await page.goto("/console/acme");
  await page.getByRole("button", { name: "Environment acme: switch environment" }).click();
  await expect(page.getByRole("menu").getByRole("menuitemradio")).toHaveText(["acme"]);
});
