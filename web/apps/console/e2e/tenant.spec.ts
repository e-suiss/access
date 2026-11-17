// OP-159 m.47 (a), (d)–(h), TN-138–TN-142, IA-5: the tenant's home at its management environment and
// the tenant's environments administered from one sign-in. The first visit to an environment of the
// tenant registers this browser's key there with one signature (`party_register` and
// `instance_create`), and every read and change there is made with that key; another tenant's
// environment is still another sign-in (m.42 (c)).
import AxeBuilder from "@axe-core/playwright";
import type { Page } from "@playwright/test";

import { en } from "../src/i18n/en.js";
import { BASE } from "./data.js";
import { expect, test } from "./fixtures.js";
import { type ConsoleMock, foreignDomain } from "./mock.js";

const M = "acme-admin";

function seedTenant(bff: ConsoleMock): void {
  bff.environment = M;
  bff.eligible.add("acc_ada");
  bff.admin.set(`envs/${M}/tenant/environments`, {
    items: [
      {
        slug: "acme",
        kind: "standard",
        issuer: `${BASE}/env/acme`,
        created_at: "2026-11-16T10:00:00Z",
        sandbox: false,
      },
      {
        slug: M,
        kind: "management",
        issuer: `${BASE}/env/${M}`,
        created_at: "2026-11-16T09:00:00Z",
        sandbox: false,
      },
      {
        slug: "acme-lab",
        kind: "standard",
        issuer: `${BASE}/env/acme-lab`,
        created_at: "2026-11-16T11:00:00Z",
        sandbox: true,
      },
    ],
  });
  bff.admin.set(`envs/${M}/tenant/admins`, {
    items: [
      {
        id: "adm_owner",
        identifier: "admin@acme.example",
        role: "owner",
        status: "active",
        since: "2026-11-16T09:00:00Z",
      },
      {
        id: "adm_bob",
        identifier: "bob@acme.example",
        role: "admin",
        status: "active",
        since: "2026-11-16T12:00:00Z",
      },
      {
        id: "adm_eve",
        identifier: "<b>eve</b>@acme.example",
        role: "admin",
        status: "invited",
        since: "2026-11-16T13:00:00Z",
      },
    ],
  });
  bff.admin.set("envs/acme/accounts", { items: [{ account_id: "usr_one", status: "active" }] });
}

/** Signs in to the management environment and registers this browser's key there. */
async function openHome(page: Page): Promise<void> {
  await page.goto(`/console/${M}`);
  await page.getByRole("button", { name: "Register this browser" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Sign" }).click();
  await expect(page.getByRole("heading", { level: 1, name: en.tenantHomeTitle })).toBeVisible();
}

test.beforeEach(async ({ context, bff }) => {
  seedTenant(bff);
  await bff.signIn(context, BASE);
});

// OP-159 m.47 (a)
test("the management environment's home lists the tenant's environments and administrators", async ({
  page,
}) => {
  await openHome(page);
  const environments = page.getByTestId("tenant-environments");
  await expect(environments.getByTestId("tenant-environment-link")).toHaveText([
    M,
    "acme",
    "acme-lab",
  ]);
  await expect(environments.locator('[data-slug="acme-admin"]')).toContainText("Management");
  await expect(environments.locator('[data-slug="acme-lab"]')).toContainText("Sandbox");
  await expect(environments.getByRole("link", { name: "acme", exact: true })).toHaveAttribute(
    "href",
    "/console/acme",
  );
  const admins = page.getByTestId("tenant-admins");
  await expect(admins.locator('[data-admin="adm_owner"]')).toContainText("Owner");
  await expect(admins.locator('[data-admin="adm_bob"]')).toContainText("Administrator");
  await expect(admins.locator('[data-admin="adm_eve"]')).toContainText("Invited");
  // TN-131
  await expect(admins.locator('[data-admin="adm_eve"] b')).toHaveCount(0);
  await expect(admins).toContainText("<b>eve</b>@acme.example");
  // the switcher: the tenant's home and environments
  await page.getByRole("button", { name: `Environment ${M}: switch environment` }).click();
  const group = page.getByRole("menu").getByRole("group", { name: "Your tenant" });
  await expect(group.getByRole("menuitemradio")).toHaveText([
    `${M} (tenant home)`,
    "acme",
    "acme-lab",
  ]);
});

// OP-159 m.47 (h), TN-110
test("a new environment is drafted in the management environment, signed and sent", async ({
  page,
  bff,
}) => {
  await openHome(page);
  const panel = page.getByRole("region", { name: "New environment" });
  const send = panel.getByRole("button", { name: "Create environment" });
  await panel.getByLabel("Short name").fill("API");
  await expect(send).toBeDisabled();
  await panel.getByLabel("Short name").fill("shop");
  await panel.getByLabel(/^Sandbox/).check();
  await panel.getByLabel("Its own subdomain").check();
  await send.click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toContainText("idp.tenant.environment_create");
  await dialog.getByRole("button", { name: "Sign" }).click();
  await expect(panel.getByRole("status")).toContainText("Recorded as change");
  await expect(panel.getByTestId("tenant-environment-created")).toContainText(
    `${BASE}/console/shop`,
  );
  expect(bff.drafts.length).toBeGreaterThan(0);
  expect(bff.writes).toEqual([
    {
      method: "POST",
      path: `envs/${M}/tenant/environments`,
      body: expect.objectContaining({ slug: "shop", sandbox: true, issuer_style: "subdomain" }),
    },
  ]);
});

// OP-159 m.48 (c): the founder records the management defaults with one signature
test("the management environment's sign-in rules are recorded with one signature", async ({
  page,
  bff,
}) => {
  bff.admin.set(`envs/${M}/settings`, { signin_policy_recorded: false });
  await openHome(page);
  const panel = page.getByRole("region", { name: en.tenantDefaultsTitle });
  await panel.getByRole("button", { name: en.tenantDefaultsAction }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toContainText("idp.environment.signin_policy");
  await dialog.getByRole("button", { name: "Sign" }).click();
  await expect(panel.getByRole("status")).toContainText("Recorded as change");
  expect(bff.writes).toEqual([
    expect.objectContaining({
      method: "PUT",
      path: `envs/${M}/settings/signin-policy`,
      body: expect.objectContaining({
        methods: ["email", "passkey"],
        mfa_required: true,
        registration: "invite_only",
      }),
    }),
  ]);
});

test("recorded sign-in rules ask for nothing", async ({ page, bff }) => {
  bff.admin.set(`envs/${M}/settings`, { signin_policy_recorded: true });
  await openHome(page);
  await expect(page.getByRole("region", { name: en.tenantDefaultsTitle })).toHaveCount(0);
});

// OP-159 m.47 (e), (f)
test("an administrator is invited, made an owner and removed; the last owner is refused", async ({
  page,
  bff,
}) => {
  await openHome(page);
  const invite = page.getByRole("region", { name: "Invite an administrator" });
  await invite.getByLabel("Email address").fill("carol@acme.example");
  await invite.getByRole("button", { name: "Send invitation" }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toContainText("idp.tenant.admin_invite");
  await dialog.getByRole("button", { name: "Sign" }).click();
  await expect(invite.getByRole("status")).toContainText("Recorded as change");

  await page.getByRole("button", { name: "Make bob@acme.example an owner" }).click();
  await expect(dialog).toContainText("idp.tenant.owner_add");
  await dialog.getByRole("button", { name: "Sign" }).click();
  const outcome = page.getByTestId("tenant-admin-change");
  await expect(outcome.getByRole("status")).toContainText("Recorded as change");
  await expect(page.getByRole("button", { name: "Make admin@acme.example an owner" })).toHaveCount(
    0,
  );

  bff.refuse.set(`envs/${M}/tenant/admins/adm_owner/remove`, [409, "last-tenant-owner"]);
  await page.getByRole("button", { name: "Remove admin@acme.example" }).click();
  await expect(dialog).toContainText("idp.tenant.admin_remove");
  await dialog.getByRole("button", { name: "Sign" }).click();
  await expect(outcome.getByRole("alert")).toHaveText(en.tenantLastOwner);

  expect(bff.writes.map((w) => [w.path, w.body["email"] ?? null])).toEqual([
    [`envs/${M}/tenant/admins`, "carol@acme.example"],
    [`envs/${M}/tenant/admins/adm_bob/owner`, null],
  ]);
});

// IA-5: without eligibility the controls are not there
test("an administrator who may not change the tenant sees no change controls", async ({
  page,
  bff,
}) => {
  bff.eligibleActions.add("idp.environment/branding");
  await openHome(page);
  await expect(page.getByTestId("tenant-admins")).toBeVisible();
  await expect(page.getByRole("region", { name: "New environment" })).toHaveCount(0);
  await expect(page.getByRole("region", { name: "Invite an administrator" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: /^Remove / })).toHaveCount(0);
});

// OP-159 m.47 (d), (g), TN-142
test("entering an environment of the tenant takes one signature and no new sign-in", async ({
  page,
  bff,
}) => {
  await openHome(page);
  await page
    .getByTestId("tenant-environments")
    .getByRole("link", { name: "acme", exact: true })
    .click();
  await expect(page).toHaveURL(`${BASE}/console/acme`);
  const enter = page.getByTestId("enter-environment");
  await expect(page.getByRole("heading", { level: 1, name: "Manage acme" })).toBeVisible();
  await enter.getByRole("button", { name: "Register and open acme" }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByLabel("access.party_register")).toBeVisible();
  await expect(dialog.getByLabel("access.instance_create")).toBeVisible();
  await dialog.getByRole("button", { name: "Sign" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Authority" })).toBeVisible();
  await expect(page.getByTestId("device-state")).toContainText("Device key registered");
  expect(bff.registeredIn).toEqual(["acme"]);
  // the environment's screens, probed with the key there, in its domain
  const nav = page.getByRole("navigation", { name: "Console sections" });
  await expect(nav.getByRole("link", { name: "Admin" })).toBeVisible();
  expect(bff.drafts.length).toBeGreaterThan(0);
  expect(bff.seen.some((x) => x.path === "/sign-in")).toBe(false);
  await nav.getByRole("link", { name: "Admin" }).click();
  await page.getByRole("link", { name: "People & agents" }).click();
  await expect(page.getByText("usr_one")).toBeVisible();
  const reads = bff.adminSeen.filter((x) => x.path.startsWith("envs/acme/"));
  expect(reads.length).toBeGreaterThan(0);
  expect(reads.every((x) => x.environment === "acme")).toBe(true);
  // the switcher stays on the tenant; the home is one step away
  await page.getByRole("button", { name: "Environment acme: switch environment" }).click();
  await page.getByRole("menuitemradio", { name: `${M} (tenant home)` }).click();
  await expect(page.getByRole("heading", { level: 1, name: en.tenantHomeTitle })).toBeVisible();
  await page
    .getByTestId("tenant-environments")
    .getByRole("link", { name: "acme", exact: true })
    .click();
  await expect(page.getByRole("heading", { level: 1, name: "Authority" })).toBeVisible();
  expect(bff.registeredIn).toEqual(["acme"]);
  expect(foreignDomain("acme")).not.toBe(foreignDomain("acme-lab"));
});

// OP-159 m.47 (g): a change in an environment of the tenant is drafted and signed there
test("a change in an environment of the tenant is drafted for it and signed with its key", async ({
  page,
  bff,
}) => {
  await openHome(page);
  await page.goto("/console/acme");
  await page.getByRole("button", { name: "Register and open acme" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Sign" }).click();
  await expect(page.getByTestId("device-state")).toContainText("Device key registered");
  await page.goto("/console/acme/admin/people");
  await expect(page.getByText("usr_one")).toBeVisible();
  await page.getByRole("button", { name: "Suspend" }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toContainText("idp.account.suspend");
  await dialog.getByRole("button", { name: "Sign" }).click();
  await expect.poll(() => bff.writes.length).toBe(1);
  expect(bff.writes[0]?.path).toBe("envs/acme/accounts/usr_one/suspend");
  const there = bff.adminSeen.filter((x) => x.path.startsWith("envs/acme/"));
  expect(there.map((x) => x.method)).toEqual(expect.arrayContaining(["GET", "POST"]));
  expect(there.every((x) => x.environment === "acme")).toBe(true);
  expect(bff.drafts.some((d) => d["mode"] === "check")).toBe(true);
});

// OP-159 m.42 (c), m.47 (a): another tenant's environment is another sign-in
test("another tenant's environment shows the other-environment notice", async ({ page }) => {
  await openHome(page);
  await page.goto("/console/globex");
  await expect(page.getByRole("status")).toHaveText(
    `You're signed in to ${M}. This address is the console of globex.`,
  );
  await expect(page.getByRole("button", { name: "Sign out and sign in to globex" })).toBeVisible();
});

// OP-159 m.47 (g): without this browser's key in the management environment, nothing is entered
test("an environment of the tenant asks for the management key first", async ({ page, bff }) => {
  await page.goto(`/console/${M}`);
  await page.getByRole("button", { name: "Register this browser" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Sign" }).click();
  await expect(page.getByRole("heading", { level: 1, name: en.tenantHomeTitle })).toBeVisible();
  await page
    .getByTestId("tenant-environments")
    .getByRole("link", { name: "acme", exact: true })
    .click();
  await page.getByRole("button", { name: "Register and open acme" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Cancel" }).click();
  await expect(page.getByTestId("enter-environment")).toBeVisible();
  expect(bff.registeredIn).toEqual([]);
});

// OP-83: the tenant's pages are accessible
test("the tenant home and the first visit to an environment have no WCAG 2.2 AA violations", async ({
  page,
}) => {
  await openHome(page);
  for (const path of [`/console/${M}`, "/console/acme"]) {
    await page.evaluate((p) => {
      history.pushState(null, "", p);
      dispatchEvent(new PopStateEvent("popstate"));
    }, path);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    await expect(page.locator("[aria-busy=true]")).toHaveCount(0);
    const a11y = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
      .analyze();
    expect(a11y.violations).toEqual([]);
  }
});
