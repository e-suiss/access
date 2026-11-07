import type { Page } from "@playwright/test";

import { expect, test } from "./fixtures.js";

const BASE = "http://127.0.0.1:4173";

async function registerDevice(page: Page) {
  await page.getByRole("button", { name: "Register this browser" }).click();
  const dialog = page.getByRole("dialog", { name: "Review and sign" });
  await expect(dialog).toBeVisible();
  return dialog;
}

// TN-128: signed out, the console offers only the hosted login hand-off
test("signed out, the console starts the hosted login for a realm", async ({ page, bff }) => {
  await page.goto("/console/");
  await expect(
    page.getByRole("heading", { level: 1, name: "Sign in to the console" }),
  ).toBeVisible();
  const started = page.waitForRequest((r) => r.url().includes("/console/api/sign-in?"));
  await page.getByLabel("Realm").fill("acme");
  await page.getByRole("button", { name: "Continue to sign-in" }).click();
  expect(new URL((await started).url()).searchParams.get("realm")).toBe("acme");
  expect(bff.seen.some((s) => s.ais)).toBe(false);
});

// TN-129: an ended console session says why
test("an idle session explains the sign-out", async ({ page, context }) => {
  await context.route("**/console/api/session", (route) =>
    route.fulfill({
      status: 401,
      contentType: "application/json",
      body: JSON.stringify({
        status: 401,
        code: "console-session-required",
        reason: "idle-expired",
      }),
    }),
  );
  await page.goto("/console/");
  await expect(page.getByRole("status")).toHaveText(
    "You were signed out: the console was idle for 15 minutes.",
  );
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
  await page.goto("/console/audit");
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
  await page.goto("/console/admin");
  await expect(page.getByRole("heading", { level: 1, name: "Authority" })).toBeVisible();
});

// Ek B 3089, TN-128: own profile and own sign-ins with the cookie alone
test("own profile and sign-ins need only the cookie", async ({ page, context, browser, bff }) => {
  await bff.signIn(context, BASE);
  const elsewhere = await browser.newContext();
  await bff.signIn(elsewhere, BASE);
  const other = [...bff.sessions.values()][1];
  if (other === undefined) throw new Error("no second session");
  await page.goto("/console/profile");
  await expect(page.getByRole("heading", { level: 1, name: "Your profile" })).toBeVisible();
  await page.getByRole("link", { name: "Your sign-ins" }).click();
  const rows = page.getByRole("row");
  await expect(rows).toHaveCount(3);
  await rows
    .filter({ hasText: "Realm sign-in" })
    .getByRole("button", { name: "End sign-in" })
    .click();
  await expect(rows).toHaveCount(2);
  expect(other.ended).toBe(true);
  await elsewhere.close();
});

// Ek B 3090
test("About shows the Kernel and server versions", async ({ page, context, bff }) => {
  await bff.signIn(context, BASE);
  await page.goto("/console/about");
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
