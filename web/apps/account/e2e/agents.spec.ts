// XI-17, A-12, E64, X13, X30, X31, §8.13, §8.17.5.8, §8.17.7.1, §8.17.7.4, §8.17.7.5, §12.4.1,
// TN-133: the agent surfaces of the hub and S11 over mocked answers; the rules behind the data
// are the server's (bins/access-server bootstrap tests).
import AxeBuilder from "@axe-core/playwright";
import type { Page } from "@playwright/test";

import { expect, test } from "./fixtures.js";
import { type AccountMock, holding, PARTY } from "./mock.js";

const HOUR = 3_600_000;

async function setUp(page: Page): Promise<void> {
  await page.goto("/account/authority");
  await page.getByRole("button", { name: "Set up this device" }).click();
  await page
    .getByRole("dialog", { name: "Check what you're signing" })
    .getByRole("button", { name: "Sign" })
    .click();
  await expect(page.getByTestId("hub")).toBeVisible();
}

function agentRows(bff: AccountMock, horizon: number, reportAt?: number): void {
  bff.searches.set("inventory", [
    holding("g-agent", {
      groups: ["acting_for_you"],
      holder: { party: "agent-a" },
      capacities: [{ for: PARTY }],
      agent: { party_kind: "agent", operator: "acme-ops" },
    }),
    holding("g-sub", {
      groups: ["acting_for_you"],
      holder: { party: "sub-b" },
      capacities: [{ for: PARTY }],
      source: { grant: "g-agent", holder: "agent-a" },
      budget: [{ dimension: { amount: "TRY" }, capacity: 1000, window: "total" }],
      agent: { party_kind: "agent" },
    }),
    holding("g-person", { holder: { party: "bob" } }),
    { type: "root", anchor: "root-anchor", sole: true },
  ]);
  bff.searches.set("revocation-impact", [
    {
      type: "revocation_impact",
      subtree: ["g-agent", "g-sub"],
      exposed: [{ exercise: "ex-a", holder: "agent-a", horizon_ms: horizon, window_ms: 0 }],
    },
  ]);
  bff.searches.set("activity", [
    {
      type: "use",
      pos: 8,
      at: 1_700_000_000_000,
      exercise: "ex-a",
      by_viewer: false,
      capacity: { for: PARTY },
      basis: { grant: "g-agent" },
      agent: { party_kind: "agent", party: "agent-a", operator: "acme-ops" },
      reports: {
        attested: [
          {
            reporter: "acme-ops",
            outcome: "done",
            evidence: ["upstream-confirmation"],
            at: reportAt ?? 1_700_000_000_000,
            intent: "same",
          },
        ],
        control: [],
      },
    },
    {
      type: "use",
      pos: 3,
      at: 1_600_000_000_000,
      by_viewer: true,
      capacity: {},
      basis: { grant: "g-held" },
      reports: { attested: [], control: [] },
    },
  ]);
}

test.beforeEach(async ({ bff, context, baseURL }) => {
  await bff.signIn(context, baseURL ?? "");
});

test("an agent is shown as an agent with whom it acts for and its operator", async ({
  page,
  bff,
}) => {
  // XI-17, A-12
  agentRows(bff, Date.now() + HOUR);
  await setUp(page);
  const acting = page.getByTestId("acting-for-you");
  const agent = acting.locator('[data-grant="g-agent"]');
  await expect(agent.getByTestId("agent-badge")).toHaveText(
    "Agent · Acting for you · operated by acme-ops",
  );
  await expect(acting.locator('[data-grant="g-sub"]').getByTestId("agent-badge")).toHaveText(
    "Agent · Acting for you · operator not confirmed",
  );
  const person = page.getByTestId("shared-from-you").locator('[data-grant="g-person"]');
  await expect(person.getByTestId("agent-badge")).toHaveCount(0);
  await expect(page.getByText(/human/i)).toHaveCount(0);
});

test("a long-running task says when authority is checked next", async ({ page, bff }) => {
  // §8.17.5.8, E31
  agentRows(bff, Date.now() + HOUR);
  await setUp(page);
  const agent = page.getByTestId("acting-for-you").locator('[data-grant="g-agent"]');
  await expect(agent.getByTestId("agent-next-check")).toContainText(
    "Authority re-checked before each step; next check by",
  );
});

test("what an agent passed on shows under its row with its limits", async ({ page, bff }) => {
  // §8.17.7.1, X31
  agentRows(bff, Date.now() + HOUR);
  await setUp(page);
  const agent = page.getByTestId("acting-for-you").locator('[data-grant="g-agent"]');
  await expect(agent.getByTestId("passed-on")).toHaveText(
    "agent-a passed part of this to sub-b: at most 1000 TRY",
  );
});

test("Stop is two rows, the runtime's and Access's, and never one Stopped", async ({
  page,
  bff,
}) => {
  // §8.17.7.5, X13, §8.17.7.4, §13.8, §8.13
  agentRows(bff, Date.now() + HOUR);
  await setUp(page);
  const agent = page.getByTestId("acting-for-you").locator('[data-grant="g-agent"]');
  await agent.getByRole("button", { name: "Stop" }).click();
  const before = agent.getByTestId("revoke").getByTestId("stop-rows");
  await expect(before.locator("li")).toHaveCount(2);
  await expect(before.locator('[data-owner="executor"]')).toHaveText(
    "Runtime We can't tell right now whether it is running.",
  );
  await expect(before.locator('[data-owner="access"]')).toHaveText(
    "Access Authority not changed yet",
  );
  await agent.getByTestId("revoke").getByRole("button", { name: "Revoke" }).click();
  const after = agent.getByTestId("aftermath");
  await expect(after.getByTestId("outcome")).toHaveText("Done");
  await expect(after.getByTestId("stop-rows").locator('[data-owner="access"]')).toContainText(
    "Authority revoked",
  );
  await expect(after.getByTestId("agent-status")).toHaveText(
    "Agent: We can't tell right now whether it is running.",
  );
  await expect(after.getByTestId("agent-next")).toContainText(
    "Steps within what was already allowed are within the declared window until",
  );
  await expect(after.getByTestId("containment")).toHaveCount(0);
  await expect(page.getByText("Stopped", { exact: true })).toHaveCount(0);
  const commit = bff.seen.find((s) => s.path.endsWith("/proxy/adp/evaluation"));
  expect((commit?.body["context"] as { ais?: unknown } | undefined)?.ais).toEqual(
    expect.any(String),
  );
});

test("a runtime that went on past its horizon is named, and only then is containment offered", async ({
  page,
  bff,
}) => {
  // §8.13
  const horizon = Date.now() - HOUR;
  agentRows(bff, horizon, horizon + 60_000);
  await setUp(page);
  const agent = page.getByTestId("acting-for-you").locator('[data-grant="g-agent"]');
  await agent.getByRole("button", { name: "Revoke" }).click();
  await agent.getByTestId("revoke").getByRole("button", { name: "Revoke" }).click();
  const after = agent.getByTestId("aftermath");
  await expect(after.getByTestId("agent-next")).toContainText(
    "The runtime is ignoring the revocation: any effect after",
  );
  await expect(after.getByTestId("containment")).toHaveText(
    "To contain it, end this agent's running copies or suspend it.",
  );
});

test("Activity shows the runtime's report with its reporter and evidence, not the agent's word", async ({
  page,
  bff,
}) => {
  // E64, INV-18, X30, §8.17.10.3
  agentRows(bff, Date.now() + HOUR);
  await setUp(page);
  await page.getByRole("link", { name: "Activity" }).click();
  const uses = page.getByTestId("activity").getByTestId("use");
  await expect(uses).toHaveCount(2);
  await expect(uses.first().getByTestId("agent-badge")).toHaveText(
    "Agent · Acting for you · operated by acme-ops",
  );
  await expect(uses.first()).toContainText(
    "Done as approved, reported by acme-ops · confirmed by the service it acted on",
  );
  await expect(uses.nth(1).getByTestId("agent-badge")).toHaveCount(0);
  await expect(uses.nth(1).locator(".access-outcomes")).toHaveCount(0);
});

test("the agent screens pass axe", async ({ page, bff }) => {
  agentRows(bff, Date.now() + HOUR);
  await setUp(page);
  const agent = page.getByTestId("acting-for-you").locator('[data-grant="g-agent"]');
  await agent.getByRole("button", { name: "Stop" }).click();
  await expect(agent.getByTestId("stop-rows")).toBeVisible();
  const result = await new AxeBuilder({ page: page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(result.violations.map((v) => `${v.id}: ${v.help}`)).toEqual([]);
});

test("S11 shows which agent used which connected account, with one-click Disconnect", async ({
  page,
  bff,
}) => {
  // §12.4.1, TN-133, OP-73
  bff.vault = [
    {
      connection: "c-mail",
      resource: "mail",
      upstream: "Gmail",
      client_id: "https://agent.example/client.json",
      scopes: ["gmail.readonly"],
      status: "active",
      used: [
        {
          exercise: "ex-1",
          agent: "agent-a",
          delivery: "a",
          tier: 1,
          released_ms: 1_700_000_000_000,
        },
      ],
    },
    {
      connection: "c-chat",
      resource: "chat",
      upstream: "Slack",
      scopes: [],
      status: "needs_reconnect",
      used: [],
    },
  ];
  bff.agents = [
    {
      agent: "agent-a",
      name: "Mail helper",
      kind: "cloud",
      status: "active",
      sponsor: true,
      connections: ["c-mail"],
      last_used_ms: 1_700_000_000_000,
    },
  ];
  await page.goto("/account/");
  const box = page.getByTestId("agent-accounts");
  await expect(box.getByRole("heading", { name: "Connected accounts for agents" })).toBeVisible();
  const mail = box.locator('[data-connection="c-mail"]');
  await expect(mail).toContainText("Gmail · Connected");
  await expect(mail).toContainText("Agent Used by Mail helper, last on");
  expect(bff.seen.some((s) => s.path.endsWith("/v1/account/agent-connections"))).toBe(true);
  await expect(box.locator('[data-connection="c-chat"]')).toContainText("Needs reconnecting");
  await mail.getByRole("button", { name: "Disconnect" }).click();
  await expect(box.getByTestId("said")).toHaveText("Disconnected");
  await expect(mail).toContainText("Gmail · Disconnected");
  await expect(mail.getByRole("button", { name: "Disconnect" })).toHaveCount(0);
  const del = bff.seen.find((s) => s.path.endsWith("/vault/connections/c-mail"));
  expect(del?.headers["idempotency-key"]).toEqual(expect.any(String));
  expect(del?.headers["x-csrf-token"]).toBe("csrf-token");
});
