import type { Page } from "@playwright/test";

import { expect, test } from "./fixtures.js";

const BASE = "http://127.0.0.1:4173";

async function registerDevice(page: Page) {
  await page.getByRole("button", { name: "Register this browser" }).click();
  const dialog = page.getByRole("dialog", { name: "Review and sign" });
  await expect(dialog).toBeVisible();
  return dialog;
}

/** Answers the hosted login hand-off with a stand-in page and resolves with the environment it names. */
async function signInStarted(page: Page): Promise<() => Promise<string | null>> {
  await page.route("**/console/api/sign-in?**", (route) =>
    route.fulfill({ status: 200, contentType: "text/html", body: "<title>Sign-in</title>" }),
  );
  const started = page.waitForRequest((r) => r.url().includes("/console/api/sign-in?"));
  return async () => new URL((await started).url()).searchParams.get("environment");
}

function ended(reason: string) {
  return {
    status: 401,
    contentType: "application/json",
    body: JSON.stringify({ status: 401, code: "console-session-required", reason }),
  };
}

// TN-128, OP-159 m.42 (a): signed out at an environment's console, its hosted login starts on its own
test("signed out, an environment's console starts that environment's hosted login", async ({
  page,
  bff,
}) => {
  const environment = await signInStarted(page);
  await page.goto("/console/acme/admin/roles");
  expect(await environment()).toBe("acme");
  expect(bff.seen.some((s) => s.ais)).toBe(false);
});

// OP-159 m.42 (b): the bare console names no environment and asks for none
test("signed out at the bare console with no remembered environment, nothing asks for an environment", async ({
  page,
}) => {
  let started = false;
  page.on("request", (r) => {
    if (r.url().includes("/console/api/sign-in")) started = true;
  });
  await page.goto("/console/");
  await expect(
    page.getByRole("heading", { level: 1, name: "Use your organization's console link" }),
  ).toBeVisible();
  await expect(page.getByTestId("console-link-shape")).toHaveText(`${BASE}/console/<environment>`);
  await expect(page.getByRole("textbox")).toHaveCount(0);
  await expect(page.locator("input")).toHaveCount(0);
  expect(started).toBe(false);
});

// OP-159 m.42 (b): the environment this browser last signed in to
test("signed out at the bare console, the remembered environment's console opens", async ({
  page,
  context,
}) => {
  await context.addInitScript(() => {
    localStorage.setItem("access-console-environment", "shop");
  });
  const environment = await signInStarted(page);
  await page.goto("/console/");
  expect(await environment()).toBe("shop");
});

// OP-159 m.42 (b): an unreadable store is no remembered environment
test("a browser that refuses storage still gets the bare console page", async ({
  page,
  context,
}) => {
  await context.addInitScript(() => {
    Object.defineProperty(window, "localStorage", {
      get() {
        throw new DOMException("denied", "SecurityError");
      },
    });
  });
  await page.goto("/console/");
  await expect(page.getByTestId("console-link-shape")).toBeVisible();
});

// OP-159 m.42 (a), (b): signed in, the bare console moves to the session's environment and remembers it
test("signed in at the bare console, the console moves to the session's environment", async ({
  page,
  context,
  bff,
}) => {
  await bff.signIn(context, BASE);
  await page.goto("/console/");
  await expect(page).toHaveURL(`${BASE}/console/acme`);
  await expect(page.getByRole("heading", { level: 1, name: "Authority" })).toBeVisible();
  expect(await page.evaluate(() => localStorage.getItem("access-console-environment"))).toBe(
    "acme",
  );
  await page.getByRole("link", { name: "Your profile" }).click();
  await expect(page).toHaveURL(`${BASE}/console/acme/profile`);
});

// OP-159 m.42 (c): signed in to one environment at another environment's console, nothing switches silently
test("signed in to another environment, the console says so and offers both ways", async ({
  page,
  context,
  bff,
}) => {
  await bff.signIn(context, BASE);
  await page.goto("/console/shop/admin");
  await expect(page.getByRole("status")).toHaveText(
    "You're signed in to acme. This address is the console of shop.",
  );
  await expect(page.getByRole("navigation")).toHaveCount(0);
  await page.getByRole("button", { name: "Go to acme" }).click();
  await expect(page).toHaveURL(`${BASE}/console/acme`);
  await expect(page.getByRole("heading", { level: 1, name: "Authority" })).toBeVisible();

  await page.goto("/console/shop");
  const environment = await signInStarted(page);
  await page.getByRole("button", { name: "Sign out and sign in to shop" }).click();
  expect(await environment()).toBe("shop");
  expect(bff.seen.find((s) => s.path === "/sign-out")?.status).toBe(204);
});

// TN-129, OP-159 m.42 (a): an ended console session says why and waits for the viewer
test("an idle session explains the sign-out and offers the environment's sign-in", async ({
  page,
  context,
}) => {
  let started = false;
  page.on("request", (r) => {
    if (r.url().includes("/console/api/sign-in")) started = true;
  });
  await context.route("**/console/api/session", (route) => route.fulfill(ended("idle-expired")));
  await page.goto("/console/acme");
  await expect(page.getByRole("status")).toHaveText(
    "You were signed out: the console was idle for 15 minutes.",
  );
  expect(started).toBe(false);
  const environment = await signInStarted(page);
  await page.getByRole("button", { name: "Sign in to acme" }).click();
  expect(await environment()).toBe("acme");
});

// OP-159 m.42 (a): a sign-in that came back without a session does not start again on its own
test("a sign-in that just started is not started again on its own", async ({ page }) => {
  const environment = await signInStarted(page);
  await page.goto("/console/acme");
  expect(await environment()).toBe("acme");
  await page.goto("/console/acme");
  await expect(page.getByRole("button", { name: "Sign in to acme" })).toBeVisible();
});

// X11, OP-151 m.3 (e), OP-149 m.6: registering the browser shows the Kernel's decoding of the
// intent first; cancelling signs nothing
test("the signature screen shows what the Kernel decoded before anything is signed", async ({
  page,
  context,
  bff,
}) => {
  await bff.signIn(context, BASE);
  await page.goto("/console/");
  await expect(page.getByTestId("device-state")).toContainText("no device key");
  let dialog = await registerDevice(page);
  await expect(dialog).toContainText("access.instance_create v1");
  await expect(dialog).toContainText("access.party:[0101]");
  await expect(dialog).toContainText("For yourself");
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await expect(dialog).toBeHidden();
  expect(bff.seen.filter((s) => s.path === "/instances")).toEqual([]);

  dialog = await registerDevice(page);
  await dialog.getByRole("button", { name: "Sign" }).click();
  await expect(page.getByTestId("device-state")).toContainText("Device key registered");
  expect(bff.seen.find((s) => s.path === "/instances")?.status).toBe(201);
});

// IA-5: sections appear only when the eligibility check allows; nothing is shown disabled
test("Admin, Developer and Audit appear only for an eligible viewer with a device key", async ({
  page,
  context,
  bff,
}) => {
  await bff.signIn(context, BASE);
  bff.eligible.add("acc_ada");
  await page.goto("/console/");
  const nav = page.getByRole("navigation", { name: "Console sections" });
  await expect(nav.getByRole("link", { name: "Your profile" })).toBeVisible();
  await expect(nav.getByRole("link", { name: "Admin" })).toHaveCount(0);
  const dialog = await registerDevice(page);
  await dialog.getByRole("button", { name: "Sign" }).click();
  await expect(nav.getByRole("link", { name: "Admin" })).toBeVisible();
  await expect(nav.getByRole("link", { name: "Audit" })).toBeVisible();
  await page.goto("/console/acme/audit");
  await expect(page.getByRole("heading", { level: 1, name: "Audit" })).toBeVisible();
});

// IA-5: without eligibility the sections are absent, and their URLs fall back to the hub
test("a viewer without eligibility sees no section and no stub", async ({ page, context, bff }) => {
  await bff.signIn(context, BASE);
  await page.goto("/console/");
  const dialog = await registerDevice(page);
  await dialog.getByRole("button", { name: "Sign" }).click();
  await expect(page.getByTestId("device-state")).toContainText("Device key registered");
  const nav = page.getByRole("navigation", { name: "Console sections" });
  for (const name of ["Admin", "Developer", "Audit"]) {
    await expect(nav.getByRole("link", { name })).toHaveCount(0);
  }
  await page.goto("/console/acme/admin");
  await expect(page.getByRole("heading", { level: 1, name: "Authority" })).toBeVisible();
});

// Ek B 3089, TN-128: own profile and own sign-ins with the cookie alone
test("own profile and sign-ins need only the cookie", async ({ page, context, browser, bff }) => {
  await bff.signIn(context, BASE);
  const elsewhere = await browser.newContext();
  await bff.signIn(elsewhere, BASE);
  const other = [...bff.sessions.values()][1];
  if (other === undefined) throw new Error("no second session");
  await page.goto("/console/acme/profile");
  await expect(page.getByRole("heading", { level: 1, name: "Your profile" })).toBeVisible();
  await page.getByRole("link", { name: "Your sign-ins" }).click();
  const rows = page.getByRole("row");
  await expect(rows).toHaveCount(3);
  await rows
    .filter({ hasText: "Environment sign-in" })
    .getByRole("button", { name: "End sign-in" })
    .click();
  await expect(rows).toHaveCount(2);
  expect(other.ended).toBe(true);
  await elsewhere.close();
});

// Ek B 3090
test("About shows the Kernel and server versions", async ({ page, context, bff }) => {
  await bff.signIn(context, BASE);
  await page.goto("/console/acme/about");
  await expect(page.getByTestId("kernel-api-version")).toHaveText("0.0");
  await expect(page.getByTestId("server-version")).toHaveText("0.3.1");
});

// Ek B 2973: a session store failure shows nothing but the failure
test("an unavailable BFF shows the failure and nothing else", async ({ page, bff }) => {
  bff.down = true;
  await page.goto("/console/");
  await expect(page.getByRole("alert")).toContainText("cannot reach Access");
  await expect(page.getByRole("navigation")).toHaveCount(0);
});
