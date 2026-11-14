// §8.5 S7, XI-17, AG-21, AG-41, OP-154 m.3 (c), (e), (f): the console's agent registry over
// mocked management answers; the registry's rules are the server's (bins/access-server
// bootstrap management tests).
import AxeBuilder from "@axe-core/playwright";

import { BASE, open } from "./data.js";
import { expect, test } from "./fixtures.js";

const AGENT = Buffer.alloc(16, 12).toString("base64url");
const ROOT = Buffer.alloc(16, 1).toString("base64url");
const COPY = Buffer.alloc(16, 13).toString("base64url");

test.beforeEach(async ({ context, bff }) => {
  await bff.signIn(context, BASE);
  bff.admin.set("realms/acme/agents", {
    items: [
      {
        agent: AGENT,
        display_name: "Mail helper",
        agent_kind: "cloud",
        operator: ROOT,
        status: "suspended",
        sponsors: [],
      },
    ],
  });
  bff.admin.set(`realms/acme/agents/${AGENT}`, {
    agent: AGENT,
    display_name: "Mail helper",
    description: null,
    agent_kind: "cloud",
    operator: ROOT,
    sponsors: [],
    status: "suspended",
    status_at: "2026-11-09T10:00:00Z",
    connections: ["Y29ubmVjdGlvbg"],
    last_run_at: null,
    created_at: "2026-11-01T10:00:00Z",
    registered_exercise: "ZXg",
    sponsorships: [
      {
        account_id: "usr_dave",
        assigned_at: "2026-11-01T10:00:00Z",
        assigned_exercise: "YQ",
        ended_at: "2026-11-09T10:00:00Z",
        ended_by: "account",
        ended_exercise: "Yg",
      },
    ],
    instances: [COPY],
  });
});

// XI-17, AG-41, OP-154 m.3 (e), SI-21
test("the registry shows each agent as an agent with its operator, sponsors and status", async ({
  page,
  bff,
}) => {
  await open(page, bff, "/console/admin/agents");
  const list = page.getByTestId("agent-list");
  await expect(list.getByTestId("agent-badge")).toHaveText(`AI agent · operated by ${ROOT}`);
  await expect(list).toContainText("Suspended: it has no sponsor");
  await list.getByRole("button", { name: "Mail helper" }).click();
  const a = page.getByTestId("agent");
  await expect(a.getByTestId("agent-no-sponsor")).toBeVisible();
  await expect(a.getByTestId("agent-sponsorships")).toContainText("usr_dave");
  await expect(a.getByTestId("agent-sponsorships")).toContainText("(account)");
  await expect(a.getByTestId("agent-connections")).toContainText("Y29ubmVjdGlvbg");
  await expect(page.getByText("Human", { exact: true })).toHaveCount(0);
  const result = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(result.violations.map((v) => `${v.id}: ${v.help}`)).toEqual([]);
});

// AG-21, OP-154 m.3 (f), §8.6: each running copy ends with its own signed change
test("a running copy ends only through its own signed change", async ({ page, bff }) => {
  await open(page, bff, "/console/admin/agents");
  await page.getByTestId("agent-list").getByRole("button", { name: "Mail helper" }).click();
  const copies = page.getByTestId("agent-instances");
  await expect(copies).toContainText(COPY);
  expect(bff.metaCommits).toEqual([]);
  await copies.getByRole("button", { name: "End this running copy" }).click();
  const dialog = page.getByRole("dialog", { name: "Review and sign" });
  await expect(dialog).toContainText("access.instance_terminate");
  await dialog.getByRole("button", { name: "Sign" }).click();
  await expect(copies).toContainText("Recorded as change");
  expect(bff.metaCommits.map((c) => c.action)).toEqual(["instance_terminate"]);
  await expect(page.getByRole("button", { name: /stop all|stop everything/i })).toHaveCount(0);
});
