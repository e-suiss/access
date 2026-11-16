// OP-159 m.41 (b), (c), TN-119, INV-29, IA-5, XI-11: the Platform section over mocked management
// answers. The section shows only for a viewer whose own Grant covers an `idp.platform.*` action;
// it reads metadata only, and each creation is drafted, shown on the signature screen and signed on
// that Grant (bins/access-server `management::platform` runs the same path for real).
import AxeBuilder from "@axe-core/playwright";
import type { Page } from "@playwright/test";

import { en } from "../src/i18n/en.js";
import { BASE } from "./data.js";
import { expect, test } from "./fixtures.js";
import type { ConsoleMock } from "./mock.js";

const GRANT = Buffer.alloc(16, 0x47).toString("base64url");
const PARTY = Buffer.alloc(16, 2).toString("base64url");
const ACTIONS = ["tenant_create", "realm_create", "sandbox_create"] as const;

function seedPlatform(bff: ConsoleMock, held: readonly string[] = ACTIONS): void {
  bff.realm = "platform";
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
      { tenant_id: "tnt_platform", status: "active", placement: "pool-default" },
      { tenant_id: "tnt_acme", status: "active", placement: "pool-default" },
    ],
  });
  bff.admin.set("platform/tenants/tnt_acme/realms", {
    items: [{ slug: "acme", tenant_id: "tnt_acme", status: "active", sandbox: false }],
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
  bff.admin.set("platform/realms/acme", {
    slug: "acme",
    tenant_id: "tnt_acme",
    issuer: "https://access-server:8443/realms/acme",
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

/** Signs in to the platform realm, registers this browser's key and opens `path`. */
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
    "Realms",
    "Sandbox domains",
    "Operator health",
  ]);
  for (const a of ACTIONS) {
    expect(bff.probesAsked).toContain(`idp.platform/${a}|anchor`);
    expect(bff.probesAsked).toContain(`idp.platform/${a}|holding`);
  }
});

// IA-5, fail closed: a Grant of one action shows only its screens
test("a Grant of one platform action shows only that action's screens", async ({ page, bff }) => {
  seedPlatform(bff, ["sandbox_create"]);
  await openPlatform(page, "/console/platform/platform");
  const screens = page.getByRole("navigation", { name: "Screens in this section" });
  await expect(screens.getByRole("link")).toHaveText([
    "Tenants",
    "Sandbox domains",
    "Operator health",
  ]);
});

// INV-29: without a Grant nothing shows, even in the platform realm
test("a platform realm account without a Grant sees no platform section", async ({ page, bff }) => {
  bff.realm = "platform";
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

// OP-159 m.41 (b), TN-110, OP-151 m.11 (a): a tenant is drafted, signed on the Grant and sent
test("a new tenant is drafted, shown, signed on the platform Grant and listed", async ({
  page,
  bff,
}) => {
  seedPlatform(bff);
  await openPlatform(page, "/console/platform/platform/tenants");
  await expect(page.getByTestId("tenant-list")).toContainText("tnt_acme");
  const panel = page.getByRole("region", { name: "New tenant" });
  await panel.getByRole("button", { name: "Create tenant" }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toContainText("idp.platform.tenant_create");
  await expect(dialog).toContainText("idp:[platform/platform/tenant/tnt_new]");
  await dialog.getByRole("button", { name: "Sign" }).click();
  await expect(panel.getByRole("status")).toContainText("Recorded as change");
  expect(bff.writes).toHaveLength(1);
  const w = bff.writes[0];
  expect(w?.path).toBe("platform/tenants");
  expect(w?.body["tenant_id"]).toBe("tnt_new");
  expect(bff.bases[0]).toEqual({ holding: { grant: GRANT, holder: PARTY, since: "7" } });
  await expect
    .poll(() => bff.seen.filter((x) => x.method === "GET" && x.path.endsWith("/tenants")).length)
    .toBe(2);
});

// TN-111, §13.7.7: a realm is opened with the viewer's founding root, never the operator's
test("a realm's metadata and key state show, and a new realm names its own founding root", async ({
  page,
  bff,
}) => {
  seedPlatform(bff);
  await openPlatform(page, "/console/platform/platform/realms");
  await page.getByLabel("Tenant").selectOption("tnt_acme");
  // OP-159 m.42 (d)
  await expect(page.getByTestId("realm-console-link")).toHaveText(`${BASE}/console/acme`);
  await expect(page.getByTestId("realm-console-link")).toHaveAttribute("href", "/console/acme");
  await page.getByRole("button", { name: "acme" }).click();
  await expect(page.getByTestId("realm-key-state")).toHaveAttribute("data-state", "signing");
  await expect(page.getByTestId("realm-meta")).toContainText(
    "https://access-server:8443/realms/acme",
  );
  const panel = page.getByRole("region", { name: "New realm" });
  await panel.getByLabel("Short name").fill("shop");
  await expect(panel.getByRole("button", { name: "Create realm" })).toBeDisabled();
  await panel.getByLabel("Party IDs").fill(`${PARTY}\nAwMDAwMDAwMDAwMDAwMDAw`);
  await panel.getByRole("button", { name: "Create realm" }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toContainText("idp.platform.realm_create");
  await dialog.getByRole("button", { name: "Sign" }).click();
  await expect(panel.getByRole("status")).toContainText("Recorded as change");
  await expect(panel.getByTestId("realm-console-created")).toContainText(`${BASE}/console/shop`);
  const w = bff.writes[0];
  expect(w?.path).toBe("platform/tenants/tnt_acme/realms");
  expect(w?.body["root"]).toEqual({
    joint: { k: 2, parties: [PARTY, "AwMDAwMDAwMDAwMDAwMDAw"] },
  });
  expect(bff.bases[0]).toEqual({ holding: { grant: GRANT, holder: PARTY, since: "7" } });
  await expect(page.getByText(/password|email|redirect/i)).toHaveCount(0);
});

// OP-151 m.3 (m), TN-60: a sole root is only with the acknowledgement that it can't be recovered
test("a sandbox domain with a sole founding root needs the no-recovery acknowledgement", async ({
  page,
  bff,
}) => {
  seedPlatform(bff);
  await openPlatform(page, "/console/platform/platform/sandboxes");
  await page.getByLabel("Tenant").selectOption("tnt_acme");
  await expect(page.getByTestId("sandbox-domains-list")).toContainText("acme-lab");
  await expect(page.getByTestId("realm-console-link")).toHaveCount(0);
  const panel = page.getByRole("region", { name: "New sandbox domain" });
  await panel.getByLabel("Short name").fill("acme-try");
  await panel.getByLabel("Only me").check();
  const send = panel.getByRole("button", { name: "Create sandbox domain" });
  await expect(send).toBeDisabled();
  await panel.getByRole("checkbox").check();
  await send.click();
  await page.getByRole("dialog").getByRole("button", { name: "Sign" }).click();
  await expect(panel.getByRole("status")).toContainText("Recorded as change");
  const w = bff.writes[0];
  expect(w?.path).toBe("platform/tenants/tnt_acme/sandbox-domains");
  expect(w?.body).toMatchObject({
    slug: "acme-try",
    root: { sole: PARTY },
    acknowledge_no_recovery: true,
  });
});

// X11: a draft that is not what was asked for is never signed
test("a tampered platform draft is refused before the signature screen", async ({ page, bff }) => {
  seedPlatform(bff);
  await openPlatform(page, "/console/platform/platform/realms");
  bff.tamper = true;
  await page.getByLabel("Tenant").selectOption("tnt_acme");
  const panel = page.getByRole("region", { name: "New realm" });
  await panel.getByLabel("Short name").fill("shop");
  await panel.getByLabel("Party IDs").fill(`${PARTY},AwMDAwMDAwMDAwMDAwMDAw`);
  await panel.getByRole("button", { name: "Create realm" }).click();
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
  for (const [path, heading] of [
    ["platform/tenants", "Tenants"],
    ["platform/realms", "Realms"],
    ["platform/sandboxes", "Sandbox domains"],
    ["platform/operator", "Operator health"],
  ] as const) {
    await page.evaluate((p) => {
      history.pushState(null, "", p);
      dispatchEvent(new PopStateEvent("popstate"));
    }, `/console/platform/${path}`);
    await expect(page.getByRole("heading", { level: 2, name: heading })).toBeVisible();
    await expect(page.locator("[aria-busy=true]")).toHaveCount(0);
    const a11y = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
      .analyze();
    expect(a11y.violations).toEqual([]);
  }
});
