// OP-159 m.41 (b), (c), m.47 (c), (h), TN-119, INV-29, IA-5, XI-11: the Platform section over mocked
// management answers. The section shows only for a viewer whose own Grant covers an `idp.platform.*`
// action; it reads metadata only, opens no environment, and each tenant change is drafted, shown on
// the signature screen and signed on that Grant (bins/access-server `management::platform` runs the
// same path for real).
import AxeBuilder from "@axe-core/playwright";
import type { Page } from "@playwright/test";

import { en } from "../src/i18n/en.js";
import { BASE } from "./data.js";
import { expect, test } from "./fixtures.js";
import type { ConsoleMock } from "./mock.js";

const GRANT = Buffer.alloc(16, 0x47).toString("base64url");
const PARTY = Buffer.alloc(16, 2).toString("base64url");
const ACTIONS = [
  "tenant_create",
  "tenant_suspend",
  "tenant_reactivate",
  "tenant_placement",
] as const;

function seedPlatform(bff: ConsoleMock, held: readonly string[] = ACTIONS): void {
  bff.environment = "platform";
  for (const a of held) bff.heldActions.add(`idp.platform/${a}`);
  bff.searches.set("holdings", {
    results: [
      {
        grant: GRANT,
        holder: PARTY,
        since: 7,
        actions: held.map((name) => ({ namespace: "idp.platform", name })),
      },
    ],
    page: { next_token: "", total: 1 },
    context: { advisory: true },
  });
  bff.admin.set("platform/tenants", {
    items: [
      {
        tenant_id: "tnt_acme",
        display_name: "Acme",
        primary_slug: "acme",
        founding: "completed",
        status: "active",
        placement: "pool-default",
        created_at: "2026-11-16T09:00:00Z",
      },
      {
        tenant_id: "tnt_globex",
        display_name: "<i>Globex</i>",
        primary_slug: "globex-admin",
        founding: "expired",
        status: "provisioning",
        placement: "pool-default",
      },
      {
        tenant_id: "tnt_initech",
        display_name: "Initech",
        primary_slug: "initech-admin",
        founding: "completed",
        status: "suspended",
        placement: "pool-eu",
      },
    ],
  });
  bff.admin.set("platform/tenants/tnt_acme/envs", {
    items: [
      { slug: "acme", kind: "primary", tenant_id: "tnt_acme", status: "active" },
      {
        slug: "acme-staging",
        kind: "standard",
        tenant_id: "tnt_acme",
        status: "active",
        sandbox: false,
      },
    ],
  });
  bff.admin.set("platform/tenants/tnt_acme/sandbox-domains", {
    items: [
      {
        slug: "acme-lab",
        tenant_id: "tnt_acme",
        status: "active",
        sandbox: true,
        budget: { exercises_per_day: "10000", projections_per_day: "50000" },
      },
    ],
  });
  bff.admin.set("platform/envs/acme", {
    slug: "acme",
    kind: "standard",
    tenant_id: "tnt_acme",
    issuer: "https://access-server:8443/env/acme",
    status: "active",
    placement: "pool-default",
    domain: Buffer.alloc(32, 9).toString("base64url"),
    sandbox: false,
    budget: null,
    key_state: "signing",
    signing_available_at: "2026-11-15T10:30:00Z",
    kex_share: "optimistic",
    created_at: "2026-11-15T09:00:00Z",
  });
  bff.admin.set("platform/operator/health", {
    status: "degraded",
    checks: [
      { name: "database", ok: true },
      { name: "identity-signer", ok: false },
    ],
  });
}

/** Signs in to the platform environment, registers this browser's key and opens `path`. */
async function openPlatform(page: Page, path: string): Promise<void> {
  await page.goto("/console/");
  await page.getByRole("button", { name: "Register this browser" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Sign" }).click();
  await expect(page.getByTestId("device-state")).toContainText("Device key registered");
  await expect(
    page.getByRole("navigation", { name: "Console sections" }).getByRole("link", {
      name: "Platform",
    }),
  ).toBeVisible();
  await page.evaluate((p) => {
    history.pushState(null, "", p);
    dispatchEvent(new PopStateEvent("popstate"));
  }, path);
}

test.beforeEach(async ({ context, bff }) => {
  await bff.signIn(context, BASE);
});

// IA-5, XI-11, INV-29: on its Grant alone, and only the Platform section
test("the platform section shows only for a viewer whose Grant covers a platform action", async ({
  page,
  bff,
}) => {
  seedPlatform(bff);
  await openPlatform(page, "/console/platform/platform");
  const nav = page.getByRole("navigation", { name: "Console sections" });
  for (const name of ["Admin", "Developer", "Audit"]) {
    await expect(nav.getByRole("link", { name })).toHaveCount(0);
  }
  await expect(page.getByRole("heading", { level: 1, name: "Platform" })).toBeVisible();
  const screens = page.getByRole("navigation", { name: "Screens in this section" });
  await expect(screens.getByRole("link")).toHaveText([
    "Tenants",
    "Environments",
    "Sandbox domains",
    "Operator health",
  ]);
  // OP-159 m.43 (c), m.47 (h), §13.7.4: asked on the Grant naming it, which answers, and not again
  for (const a of ACTIONS) {
    expect(bff.probesAsked).toContain(`idp.platform/${a}|holding`);
    expect(bff.probesAsked).not.toContain(`idp.platform/${a}|anchor`);
  }
  // m.47 (h): catalog version 1's environment creation is not asked about
  expect(bff.probesAsked.some((p) => /environment_create|sandbox_create/.test(p))).toBe(false);
});

// OP-159 m.47 (a), TN-119: the platform lists tenants, never enters them
test("the switcher lists no tenant's environments in a platform session", async ({ page, bff }) => {
  seedPlatform(bff);
  await openPlatform(page, "/console/platform/platform");
  await page.getByRole("button", { name: "Environment platform: switch environment" }).click();
  const menu = page.getByRole("menu");
  await expect(menu.getByRole("menuitemradio")).toHaveText(["platform"]);
  expect(bff.seen.some((x) => /\/tnt_[a-z]+\/envs$/.test(x.path))).toBe(false);
});

// OP-159 m.47 (c), m.42 (d), TN-131
test("tenants show their name, primary environment, console link, state and founding", async ({
  page,
  bff,
}) => {
  seedPlatform(bff);
  await openPlatform(page, "/console/platform/platform/tenants");
  const list = page.getByTestId("tenant-list");
  const acme = list.locator('[data-tenant="tnt_acme"]');
  await expect(acme).toContainText("Acme");
  await expect(acme).toContainText("acme");
  await expect(acme).toContainText("Active");
  await expect(acme).toContainText("Done");
  await expect(acme.getByTestId("environment-console-link")).toHaveText(`${BASE}/console/acme`);
  await expect(acme.getByTestId("environment-console-link")).toHaveAttribute(
    "href",
    "/console/acme",
  );
  const globex = list.locator('[data-tenant="tnt_globex"]');
  await expect(globex).toContainText("<i>Globex</i>");
  await expect(globex.locator("i")).toHaveCount(0);
  await expect(globex).toContainText("Waiting for its founder");
  await expect(globex).toContainText("Invitation expired");
  await expect(list.locator('[data-tenant="tnt_initech"]')).toContainText("Suspended");
});

// OP-159 m.47 (c), TN-110, OP-151 m.11 (a): a tenant is drafted, signed on the Grant and sent
test("a new tenant with its founder is drafted, shown, signed on the platform Grant and listed", async ({
  page,
  bff,
}) => {
  seedPlatform(bff);
  await openPlatform(page, "/console/platform/platform/tenants");
  await expect(page.getByTestId("tenant-list")).toContainText("Acme");
  const listings = () =>
    bff.seen.filter((x) => x.method === "GET" && x.path.endsWith("/tenants")).length;
  const before = listings();
  const panel = page.getByRole("region", { name: "New tenant" });
  const send = panel.getByRole("button", { name: "Create tenant" });
  await expect(send).toBeDisabled();
  await panel.getByLabel("Name").fill("Hooli");
  await panel.getByLabel("Primary environment").fill("hooli-admin");
  await panel.getByLabel("Founder's email address").fill("founder@hooli.example");
  await panel.getByLabel("Placement (optional)").fill("pool-eu");
  await send.click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toContainText("idp.platform.tenant_create");
  await expect(dialog).toContainText("idp:[platform/platform/tenant/hooli-admin]");
  await dialog.getByRole("button", { name: "Sign" }).click();
  await expect(panel.getByRole("status")).toContainText("Recorded as change");
  await expect(panel.getByTestId("tenant-console-created")).toContainText(
    `${BASE}/console/hooli-admin`,
  );
  expect(bff.writes).toHaveLength(1);
  const w = bff.writes[0];
  expect(w?.path).toBe("platform/tenants");
  expect(w?.body).toMatchObject({
    tenant_id: "tnt_new",
    display_name: "Hooli",
    primary_slug: "hooli-admin",
    founder_email: "founder@hooli.example",
    placement: "pool-eu",
  });
  expect(bff.bases[0]).toEqual({ holding: { grant: GRANT, holder: PARTY, since: "7" } });
  await expect.poll(listings).toBe(before + 1);
  // m.47 (h): the platform opens no environment
  await expect(page.getByText(/New environment|New sandbox domain|Founding root/)).toHaveCount(0);
});

// OP-159 m.47 (c), (h), TN-141
test("a tenant's founder is invited again, and a tenant is suspended, reactivated and moved", async ({
  page,
  bff,
}) => {
  seedPlatform(bff);
  await openPlatform(page, "/console/platform/platform/tenants");
  const dialog = page.getByRole("dialog");
  const picker = page.getByLabel("Tenant", { exact: true });
  await picker.selectOption("tnt_globex");
  const globex = page.getByRole("region", { name: "Tenant <i>Globex</i>" });
  await globex.getByLabel("Founder's email address").fill("founder@globex.example");
  await globex.getByRole("button", { name: "Send a new invitation" }).click();
  await expect(dialog).toContainText("idp.platform.tenant_create");
  await dialog.getByRole("button", { name: "Sign" }).click();
  await expect(globex.getByRole("status")).toContainText("Recorded as change");
  await expect(globex.getByRole("button", { name: "Suspend tenant" })).toHaveCount(0);

  await picker.selectOption("tnt_acme");
  const acme = page.getByRole("region", { name: "Tenant Acme" });
  await expect(acme.getByRole("button", { name: "Send a new invitation" })).toHaveCount(0);
  await acme.getByRole("button", { name: "Suspend tenant" }).click();
  await expect(dialog).toContainText("idp.platform.tenant_suspend");
  await dialog.getByRole("button", { name: "Sign" }).click();
  await expect(acme.getByRole("status")).toContainText("Recorded as change");
  await acme.getByLabel("New placement").fill("pool-eu");
  await acme.getByRole("button", { name: "Move placement" }).click();
  await expect(dialog).toContainText("idp.platform.tenant_placement");
  await dialog.getByRole("button", { name: "Sign" }).click();

  await picker.selectOption("tnt_initech");
  const initech = page.getByRole("region", { name: "Tenant Initech" });
  await initech.getByRole("button", { name: "Reactivate tenant" }).click();
  await expect(dialog).toContainText("idp.platform.tenant_reactivate");
  await dialog.getByRole("button", { name: "Sign" }).click();
  await expect(initech.getByRole("status")).toContainText("Recorded as change");

  expect(bff.writes.map((w) => [w.path, w.body])).toEqual([
    [
      "platform/tenants/tnt_globex/reinvite-founder",
      expect.objectContaining({ founder_email: "founder@globex.example" }),
    ],
    ["platform/tenants/tnt_acme/suspend", expect.any(Object)],
    ["platform/tenants/tnt_acme/placement", expect.objectContaining({ placement: "pool-eu" })],
    ["platform/tenants/tnt_initech/reactivate", expect.any(Object)],
  ]);
});

// OP-159 m.47 (h): environments are metadata here; none is created
test("an environment's metadata and key state show, with no way to create one", async ({
  page,
  bff,
}) => {
  seedPlatform(bff);
  await openPlatform(page, "/console/platform/platform/envs");
  await page.getByLabel("Tenant").selectOption("tnt_acme");
  await expect(page.getByTestId("envs-list")).toContainText("Primary");
  await page.getByRole("button", { name: "acme", exact: true }).click();
  await expect(page.getByTestId("environment-key-state")).toHaveAttribute("data-state", "signing");
  await expect(page.getByTestId("environment-meta")).toContainText(
    "https://access-server:8443/env/acme",
  );
  await expect(page.getByRole("region", { name: "New environment" })).toHaveCount(0);
  await page.evaluate(() => {
    history.pushState(null, "", "/console/platform/platform/sandboxes");
    dispatchEvent(new PopStateEvent("popstate"));
  });
  await page.getByLabel("Tenant").selectOption("tnt_acme");
  await expect(page.getByTestId("sandbox-domains-list")).toContainText("acme-lab");
  await expect(page.getByRole("region", { name: "New sandbox domain" })).toHaveCount(0);
  expect(bff.writes).toEqual([]);
});

// INV-29: without a Grant nothing shows, even in the platform environment
test("a platform environment account without a Grant sees no platform section", async ({
  page,
  bff,
}) => {
  bff.environment = "platform";
  await page.goto("/console/");
  await page.getByRole("button", { name: "Register this browser" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Sign" }).click();
  await expect(page.getByTestId("device-state")).toContainText("Device key registered");
  await expect(
    page.getByRole("navigation", { name: "Console sections" }).getByRole("link", {
      name: "Platform",
    }),
  ).toHaveCount(0);
  await page.goto("/console/platform/platform/tenants");
  await expect(page.getByRole("heading", { level: 1, name: "Authority" })).toBeVisible();
});

// X11: a draft that is not what was asked for is never signed
test("a tampered platform draft is refused before the signature screen", async ({ page, bff }) => {
  seedPlatform(bff);
  await openPlatform(page, "/console/platform/platform/tenants");
  bff.tamper = true;
  const panel = page.getByRole("region", { name: "New tenant" });
  await panel.getByLabel("Name").fill("Hooli");
  await panel.getByLabel("Primary environment").fill("hooli-admin");
  await panel.getByLabel("Founder's email address").fill("founder@hooli.example");
  await panel.getByRole("button", { name: "Create tenant" }).click();
  await expect(panel.getByRole("alert")).toContainText(en.signatureMismatch);
  await expect(page.getByRole("dialog")).toHaveCount(0);
  expect(bff.writes).toEqual([]);
});

// OP-159 m.41 (b): the operator's readiness, by check name
test("operator health shows each readiness check", async ({ page, bff }) => {
  seedPlatform(bff);
  await openPlatform(page, "/console/platform/platform/operator");
  await expect(page.getByTestId("operator-status")).toHaveAttribute("data-status", "degraded");
  await expect(page.getByTestId("operator-checks").locator("[data-ok=false]")).toContainText(
    "identity-signer",
  );
  expect(bff.writes).toEqual([]);
});

// OP-83, X24: every platform screen is accessible and uses no forbidden word
test("every platform screen has no WCAG 2.2 AA violations", async ({ page, bff }) => {
  seedPlatform(bff);
  await openPlatform(page, "/console/platform/platform/tenants");
  await page.getByLabel("Tenant", { exact: true }).selectOption("tnt_acme");
  for (const [path, heading] of [
    ["platform/tenants", "Tenants"],
    ["platform/envs", "Environments"],
    ["platform/sandboxes", "Sandbox domains"],
    ["platform/operator", "Operator health"],
  ] as const) {
    await page.evaluate((p) => {
      history.pushState(null, "", p);
      dispatchEvent(new PopStateEvent("popstate"));
    }, `/console/platform/${path}`);
    await expect(page.getByRole("heading", { level: 2, name: heading })).toBeVisible();
    await expect(page.locator("[aria-busy=true]")).toHaveCount(0);
    await page.mouse.move(0, 0);
    const a11y = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
      .analyze();
    expect(a11y.violations).toEqual([]);
  }
});
