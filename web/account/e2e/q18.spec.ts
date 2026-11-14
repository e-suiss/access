// OP-156 m.3 (v): merchants that can charge you (S2, §8.11, §8.17.7.2), the one-time payment
// (§8.17.5.11), the two limit rows (XI-14), Sync from HR (§8.17.9.8) and the degraded states
// (§8.13): X30, E26, R8, X8, INV-20, INV-24, XI-3, X11
import AxeBuilder from "@axe-core/playwright";
import type { Page } from "@playwright/test";

import { encode } from "./cbor.js";
import { expect, test } from "./fixtures.js";
import { type AccountMock, holding } from "./mock.js";

async function axe(page: Page): Promise<void> {
  const result = await new AxeBuilder({ page: page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(result.violations.map((v) => `${v.id}: ${v.help}`)).toEqual([]);
}

async function setUp(page: Page, path: string): Promise<void> {
  await page.goto(path);
  await page.getByRole("button", { name: "Set up this device" }).click();
  await page
    .getByRole("dialog", { name: "Check what you're signing" })
    .getByRole("button", { name: "Sign" })
    .click();
}

const SCHEMA = Buffer.alloc(32, 7);
const MERCHANT = Buffer.alloc(16, 0x4d).toString("base64url");

/** The payment request a merchant hands the customer: the envelope's bytes and wire JSON. */
function request(action: { namespace: string; name: string }, minutes: number): string {
  const from = Date.now() - 60_000;
  const until = from + minutes * 60_000;
  const envelope = encode({
    action: {
      name: action.name,
      major: 1,
      schema: [-16, Uint8Array.from(SCHEMA)],
      namespace: action.namespace,
    },
    params: { amount: { amount: { unit: "try", value: 30_000 } } },
    purpose: { code: "order_1182" },
    validity: [from, until],
    recipient: Uint8Array.from(Buffer.alloc(16, 0x4d)),
    resources: [{ path: ["o-1182"], namespace: "pay.order", incarnation: 0 }],
  });
  const body = {
    envelope: Buffer.from(envelope).toString("base64url"),
    intent: {
      action: { ...action, major: 1, schema: SCHEMA.toString("base64url") },
      resources: [{ namespace: "pay.order", path: ["o-1182"], incarnation: 0 }],
      params: { amount: { amount: { value: 30_000, unit: "try" } } },
      recipient: MERCHANT,
      purpose: { code: "order_1182" },
      validity: { from, until },
    },
    anchor: Buffer.alloc(16, 0x61).toString("base64url"),
    merchant: "Kaya Tekstil",
  };
  return Buffer.from(JSON.stringify(body)).toString("base64url");
}

function merchant(bff: AccountMock): void {
  bff.searches.set("inventory", [
    holding("g-shop", {
      holder: { party: "kaya" },
      actions: [{ namespace: "pay", name: "initiate" }],
      budget: [{ dimension: { amount: "try" }, capacity: 50_000, window: "transaction" }],
      agent: { operator: "kaya" },
    }),
    holding("g-work"),
    { type: "root", anchor: "root-anchor", sole: true },
  ]);
}

test.beforeEach(async ({ bff, context, baseURL }) => {
  await bff.signIn(context, baseURL ?? "");
});

test("S2 lists the merchants that can charge you and Stop charges is the person's own revoke", async ({
  page,
  bff,
}) => {
  merchant(bff);
  await setUp(page, "/account/merchants");
  const list = page.getByTestId("merchants");
  await expect(list.getByRole("heading", { name: "Merchants that can charge you" })).toBeVisible();
  const rows = list.locator("[data-grant]");
  await expect(rows).toHaveCount(1);
  // X30: the merchant's agent is an agent, never a person
  await expect(rows.first().locator("[data-party-kind]")).toHaveText("AI agent · acting for kaya");
  // XI-14
  await expect(rows.first().locator('[data-owner="access"]')).toContainText(
    "Authority limit (Access)",
  );
  await expect(rows.first().locator('[data-owner="pay"]')).toHaveCount(0);
  // E26
  await expect(rows.first()).toContainText(
    "What kaya decides inside its own business isn't shown here.",
  );
  await rows.first().getByRole("button", { name: "Stop charges" }).click();
  const dialog = page.getByRole("dialog", { name: "Check what you're signing" });
  await expect(dialog).toContainText("access.grant_revoke");
  await dialog.getByRole("button", { name: "Sign" }).click();
  await expect(page.getByTestId("outcome")).toHaveText("Done");
  await axe(page);
});

test("a one-time payment pays exactly once and leaves no Grant", async ({ page, bff }) => {
  await setUp(
    page,
    `/account/payment#request=${request({ namespace: "pay", name: "initiate" }, 10)}`,
  );
  const pay = page.getByTestId("payment");
  await expect(pay.getByTestId("one-time")).toHaveText(
    /^Pay TRY\s?300\.00 to Kaya Tekstil once\. Nothing more can be charged with this\.$/,
  );
  await expect(pay).toContainText("For order_1182");
  await axe(page);
  await pay.getByRole("button", { name: "Pay once" }).click();
  const dialog = page.getByRole("dialog", { name: "Check what you're signing" });
  await expect(dialog).toContainText("pay.initiate");
  await dialog.getByRole("button", { name: "Sign" }).click();
  await expect(page.getByTestId("outcome")).toHaveText("Done");
  // R8, X8, INV-20: the payment is the customer's own Exercise; no grant.issue is drafted or sent
  const sent = bff.seen.filter((s) => s.path.endsWith("/proxy/adp/evaluation"));
  expect(sent).toHaveLength(1);
  const context = sent[0]?.body["context"] as Record<string, unknown>;
  expect((sent[0]?.body["action"] as Record<string, unknown>)["name"]).toBe("initiate");
  expect(context["payload"]).toBeUndefined();
  expect(context["mode"]).toBe("commit");
  expect(bff.seen.some((s) => JSON.stringify(s.body).includes("grant_issue"))).toBe(false);
});

test("a request that would let the merchant charge again is not a one-time payment", async ({
  page,
  bff,
}) => {
  await setUp(
    page,
    `/account/payment#request=${request({ namespace: "access", name: "grant_issue" }, 10)}`,
  );
  await expect(page.getByRole("alert")).toContainText("would let Kaya Tekstil charge you again");
  await expect(page.getByRole("button", { name: "Pay once" })).toHaveCount(0);
  await page.goto(
    `/account/payment#request=${request({ namespace: "pay", name: "initiate" }, 2 * 24 * 60)}`,
  );
  await expect(page.getByRole("alert")).toContainText("can't be paid here as a one-time payment");
  expect(bff.seen.some((s) => s.path.endsWith("/proxy/adp/evaluation"))).toBe(false);
});

test("a Relay delay is a notice and a revoke still reads done, never pending", async ({
  page,
  bff,
}) => {
  bff.relay = { relay_lag_ms: 61_000, notifications_delayed: true };
  bff.searches.set("inventory", [
    holding("g-given", {
      budget: [{ dimension: { amount: "try" }, capacity: 50_000, window: "total" }],
    }),
    holding("g-hr", {
      groups: ["your_authority"],
      holder: { group: ["hr_department"] },
      selection: { state: "current", since: 4, by: "acme-hr", stated_at: 1_699_000_000_000 },
    }),
    { type: "root", anchor: "root-anchor", sole: true },
  ]);
  await setUp(page, "/account/authority");
  await expect(page.getByTestId("notifications-delayed")).toHaveText(
    "Notifications are delayed. What you changed still took effect.",
  );
  // §8.17.9.8
  await expect(page.getByTestId("hr-source")).toHaveText("Sync from HR (acme-hr)");
  // XI-14
  const given = page.locator('[data-grant="g-given"]').first();
  await expect(given.locator('[data-owner="access"]')).toContainText("Authority limit (Access)");
  await given.getByRole("button", { name: "Revoke" }).click();
  const panel = page.getByTestId("revoke");
  await expect(panel.getByRole("button", { name: "Revoke" })).toBeEnabled();
  await panel.getByRole("button", { name: "Revoke" }).click();
  await expect(page.getByTestId("outcome")).toHaveText("Done");
  await expect(page.getByText(/pending/i)).toHaveCount(0);
  await axe(page);
});

test("Access unavailable says authority can't be changed and points to the runtime's stop", async ({
  page,
  bff,
}) => {
  bff.searchDown = true;
  await setUp(page, "/account/authority");
  await expect(page.getByTestId("access-unavailable")).toHaveText(
    "Authority can't be changed right now. You can still ask the runtime to stop for now (Work control), if it supports it.",
  );
  await expect(page.getByText(/agent disabled|queued/i)).toHaveCount(0);
});

function saveRequest(depth: number): string {
  const authority = {
    authority: {
      actions: { exact: [{ namespace: "pay", name: "initiate", major: 1, schema: "cw" }] },
      resource: { namespace: "access.party", prefix: ["c", "instrument"] },
      params: { amount: { range: { min: 0, max: 50_000, unit: "try" } } },
      recipient: { party: MERCHANT },
      purpose: [{ code: "orders" }],
    },
    constraints: { validity: { from: 0, until: 1_798_675_200_000 } },
    delegation: { depth },
    requirements: [],
  };
  return Buffer.from(
    JSON.stringify({ merchant: "Kaya Tekstil", party: MERCHANT, anchor: "c2VsZg", authority }),
  ).toString("base64url");
}

test("saving a card is the customer's own grant.issue to the merchant from their self-anchor", async ({
  page,
  bff,
}) => {
  await setUp(page, `/account/save-card#request=${saveRequest(0)}`);
  const preview = page.getByTestId("save-card");
  await expect(preview).toContainText("Let Kaya Tekstil charge your card: up to TRY");
  await expect(preview).toContainText("per order, until");
  await expect(preview).toContainText("only for orders you place");
  await axe(page);
  await page.getByRole("button", { name: "Let Kaya Tekstil charge my card" }).click();
  const dialog = page.getByRole("dialog", { name: "Check what you're signing" });
  await expect(dialog).toContainText("access.grant_issue");
  await dialog.getByRole("button", { name: "Sign" }).click();
  await expect(page.getByTestId("outcome")).toHaveText("Done");
  const drafted = bff.seen.find(
    (s) => s.path.endsWith("/intents") && s.body["payload"] !== undefined,
  );
  const issue = (drafted?.body["payload"] as Record<string, Record<string, unknown>>)[
    "grant_issue"
  ];
  expect(issue?.["basis"]).toEqual({ anchor: "c2VsZg" });
  expect(issue?.["holder"]).toEqual({ party: MERCHANT });
  expect(issue?.["agency"]).toEqual(["own"]);
  const sent = bff.seen.filter((s) => s.path.endsWith("/proxy/adp/evaluation"));
  expect((sent[0]?.body["action"] as Record<string, unknown>)["name"]).toBe("grant_issue");
});

test("a card request that lets the merchant pass it on can't be saved", async ({ page, bff }) => {
  await setUp(page, `/account/save-card#request=${saveRequest(1)}`);
  await expect(page.getByRole("alert")).toContainText("It can't be saved here.");
  expect(bff.seen.some((s) => s.path.endsWith("/proxy/adp/evaluation"))).toBe(false);
});
