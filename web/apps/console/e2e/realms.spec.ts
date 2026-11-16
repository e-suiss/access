// OP-159 m.43 (b), m.42 (c), IA-5: the realm switcher in the console header. It lists the realms
// this browser signed in to (and, in a platform session, the platform's realms: platform.spec.ts);
// choosing one opens that realm's console, which never switches the session silently.
import { expect, test } from "./fixtures.js";
import { BASE } from "./data.js";

const KNOWN = "access-console-realms";

// OP-159 m.43 (b)
test("the switcher lists the realms this browser signed in to and opens the chosen one", async ({
  page,
  context,
  bff,
}) => {
  await context.addInitScript((key) => {
    if (localStorage.getItem(key) === null) {
      localStorage.setItem(key, JSON.stringify(["shop", "Not A Realm", "api", "acme"]));
    }
  }, KNOWN);
  await bff.signIn(context, BASE);
  await page.goto("/console/acme");
  await expect(page.getByRole("heading", { level: 1, name: "Authority" })).toBeVisible();
  const switcher = page.getByRole("button", { name: "Realm acme: switch realm" });
  await expect(switcher).toHaveText("acme");
  await switcher.click();
  const menu = page.getByRole("menu");
  await expect(menu.getByRole("group", { name: "Signed in from this browser" })).toBeVisible();
  await expect(menu.getByRole("menuitemradio")).toHaveText(["acme", "shop"]);
  await expect(menu.getByRole("menuitemradio", { name: "acme" })).toHaveAttribute(
    "aria-checked",
    "true",
  );
  await expect(menu.getByRole("group", { name: "Realms on this platform" })).toHaveCount(0);
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

// OP-159 m.43 (b): an unreadable store is no list; the current realm is still there
test("a browser that refuses storage still shows the current realm", async ({
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
  await page.getByRole("button", { name: "Realm acme: switch realm" }).click();
  await expect(page.getByRole("menu").getByRole("menuitemradio")).toHaveText(["acme"]);
});
