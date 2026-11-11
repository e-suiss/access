import type { Page } from "@playwright/test";

import { expect, test } from "./fixtures.js";
import { BASE, open, UNDISCLOSED } from "./data.js";

async function intent(page: Page): Promise<void> {
  await page.getByLabel("Action namespace").fill("commerce");
  await page.getByLabel("Action name", { exact: true }).fill("refund");
  await page.getByLabel("Resource namespace").fill("commerce.order");
  await page.getByLabel(/Resource path/).fill("8812");
}

test.beforeEach(async ({ context, bff }) => {
  await bff.signIn(context, BASE);
});

// IA-5, XI-11: each screen appears only for an action the viewer can exercise; no stubs
test("only the screens the viewer can exercise are listed", async ({ page, bff }) => {
  await open(page, bff, "/console/admin/roles", ["idp.realm/branding"]);
  const nav = page.getByRole("navigation", { name: "Console sections" });
  await expect(nav.getByRole("link", { name: "Developer" })).toHaveCount(0);
  await expect(nav.getByRole("link", { name: "Audit" })).toHaveCount(0);
  const screens = page.getByRole("navigation", { name: "Screens in this section" });
  await expect(screens.getByRole("link")).toHaveText(["Sign-in settings"]);
  await expect(page.getByRole("heading", { level: 2, name: "Sign-in settings" })).toBeVisible();
});

// IA-5, §13.7.4: a session's check limit counts every probe, so each is asked once per device
test("each screen's probe is asked once however often the page sets the device", async ({
  page,
  bff,
}) => {
  await open(page, bff, "/console/admin/roles", ["idp.realm/branding"]);
  await expect(page.getByRole("heading", { level: 2, name: "Sign-in settings" })).toBeVisible();
  await page.getByRole("link", { name: "Your profile" }).click();
  await page.getByRole("link", { name: "Admin" }).click();
  await expect(page.getByRole("heading", { level: 2, name: "Sign-in settings" })).toBeVisible();
  const asked = bff.probesAsked.filter((p) => p.endsWith("|anchor"));
  expect(asked.length).toBeGreaterThan(0);
  expect(new Set(asked).size).toBe(asked.length);
});

// Ek B 2995, §8.11: Sign-in settings is apart from authority admin; billing is not here
test("Sign-in settings and authority admin are separate screens", async ({ page, bff }) => {
  await open(page, bff, "/console/admin/sign-in");
  const screens = page.getByRole("navigation", { name: "Screens in this section" });
  await expect(screens.getByRole("link", { name: "Sign-in settings" })).toBeVisible();
  await expect(screens.getByRole("link", { name: "Roles & templates" })).toBeVisible();
  await expect(page.getByText(/billing/i)).toContainText("billing is not managed here");
});

// §8.17.9.2, X20, Ek B 3098: the change-impact preview sentence
test("a role move shows who gains and who loses an ability", async ({ page, bff }) => {
  await open(page, bff, "/console/admin/roles");
  const preview = page.getByRole("region", { name: "Change-impact preview" });
  await preview.getByLabel("Role", { exact: true }).fill("finance-approver");
  await preview.getByLabel("Current version").fill("4");
  await preview.getByLabel("New version").fill("5");
  await preview.getByRole("button", { name: "Show" }).click();
  await expect(page.getByTestId("impact-sentence")).toHaveText(
    "Moving 3 role delegations to v5 gives 41 people a new ability: commerce.refund; removes 1 ability from 12 people: commerce.void.",
  );
  await expect(page.getByTestId("expansion")).toContainText("tier CT3, 2 root approvals");
  await expect(page.getByTestId("advisory").first()).toHaveText(
    "Advisory — not recorded, not a promise",
  );
  expect(bff.queries.find((q) => q.kind === "change-impact")).toEqual({
    kind: "change-impact",
    query: { role: "finance-approver", from: 4, to: 5 },
    ais: true,
  });
});

// §8.17.9.2, E11, C28, OP-151 m.20 (b), Ek B 3097, 3355, 3354: the role editor saves a version
test("the role editor saves a new version as one signed change", async ({ page, bff }) => {
  await open(page, bff, "/console/admin/roles");
  const editor = page.getByRole("region", { name: "Role editor" });
  await editor.getByLabel("Role name").fill("helpdesk");
  await editor.getByRole("button", { name: "Open" }).click();
  await expect(page.getByTestId("role-version")).toContainText("Editing from v1");
  await expect(page.getByTestId("role-covers")).toHaveText(
    "All non-protected actions in commerce as of catalog v12 — future actions not included.",
  );
  await expect(page.getByTestId("not-included")).toContainText(
    "Only delegations that name it can include a protected action.",
  );
  await editor.getByLabel("idp.account.reactivate").check();
  await editor.getByRole("button", { name: "Save as a new version" }).click();
  const dialog = page.getByRole("dialog", { name: "Review and sign" });
  await expect(dialog).toContainText("access.authority_set_define v1");
  expect(bff.metaCommits).toEqual([]);
  await dialog.getByRole("button", { name: "Sign" }).click();
  await expect(editor.getByRole("status")).toContainText("Recorded as change");
  expect(bff.metaCommits).toHaveLength(1);
  const define = bff.metaCommits[0]?.payload as {
    authority_set_define: { name: string; authority: { actions: { exact: unknown[] } } };
  };
  expect(define.authority_set_define.name).toBe("helpdesk");
  expect(define.authority_set_define.authority.actions.exact).toHaveLength(2);
});

// X20, §8.17.9.8, INV-10, Ek B 3098: the move is an explicit bulk grant_amend, one Exercise each
test("moving role delegations signs one amend per delegation", async ({ page, bff }) => {
  await open(page, bff, "/console/admin/roles");
  const preview = page.getByRole("region", { name: "Change-impact preview" });
  await preview.getByLabel("Role", { exact: true }).fill("finance-approver");
  await preview.getByLabel("Current version").fill("4");
  await preview.getByLabel("New version").fill("5");
  await preview.getByRole("button", { name: "Show" }).click();
  await page.getByTestId("move-delegations").click();
  const dialog = page.getByRole("dialog", { name: "Review and sign" });
  await expect(dialog).toContainText("access.grant_amend v1");
  await dialog.getByRole("button", { name: "Sign" }).click();
  await expect(page.getByTestId("moved").getByRole("listitem")).toHaveCount(3);
  expect(bff.metaCommits.map((c) => c.action)).toEqual([
    "grant_amend",
    "grant_amend",
    "grant_amend",
  ]);
});

// INV-10, XI-4: a held widening move says it is held, never done
test("a held move says it waits", async ({ page, bff }) => {
  await open(page, bff, "/console/admin/roles");
  bff.metaOutcome = "require_action";
  const preview = page.getByRole("region", { name: "Change-impact preview" });
  await preview.getByLabel("Role", { exact: true }).fill("finance-approver");
  await preview.getByLabel("Current version").fill("4");
  await preview.getByLabel("New version").fill("5");
  await preview.getByRole("button", { name: "Show" }).click();
  await page.getByTestId("move-delegations").click();
  await page.getByRole("dialog").getByRole("button", { name: "Sign" }).click();
  await expect(page.getByTestId("moved")).toContainText("Not done yet");
  expect(bff.metaCommits).toHaveLength(1);
});

// §8.17.9.2, Ek B 3100, 3354: an admin delegation's meta-actions one by one, protected apart
test("an admin delegation lists its meta-actions with protected ones apart", async ({
  page,
  bff,
}) => {
  await open(page, bff, "/console/admin/roles");
  const region = page.getByRole("region", { name: "What an admin delegation can cover" });
  await region.getByLabel("Admin delegation ID").fill("grant");
  await region.getByRole("button", { name: "Show" }).click();
  await expect(page.getByTestId("meta-ordinary").getByRole("listitem")).toHaveCount(2);
  const reserved = page.getByTestId("meta-reserved").getByRole("listitem");
  await expect(reserved).toHaveCount(2);
  await expect(reserved.first()).toContainText("Protected action");
  await expect(reserved.first()).toContainText("needs 2 approvals");
  await expect(region).not.toContainText("grant_amend");
  expect(bff.queries.find((q) => q.kind === "admin-grant")?.query).toEqual({ grant: "grant" });
});

// IA-5, OP-152 m.7 (b): a delegated admin sees a section through its own holding
test("a delegated admin sees the roles screen through its own holding", async ({ page, bff }) => {
  bff.heldActions.add("access/grant_amend");
  await open(page, bff, "/console/admin/roles", ["idp.realm/branding"]);
  const screens = page.getByRole("navigation", { name: "Screens in this section" });
  await expect(screens.getByRole("link", { name: "Roles & templates" })).toBeVisible();
  expect(bff.queries.some((q) => q.kind === "holdings" && q.ais)).toBe(true);
});

// §8.17.9.6, E6, EI-8, OP-157 m.3 (v), Ek B 5572, 5649: every channel needs its own choice
test("offboarding asks for a choice on every channel and labels only a committed departure", async ({
  page,
  bff,
}) => {
  bff.admin.set("realms/acme/offboarding/cGFydHk/preview", {
    party: "cGFydHk",
    status: "active",
    survive: 2,
    channels: {
      grants: [
        { grant: "Z3JhbnQx", choices: ["keep", "revoke"] },
        { grant: "Z3JhbnQy", choices: ["keep", "revoke"] },
      ],
      instances: [{ instance: "aW5zdDE", choices: ["terminate"] }],
      holdings: [
        {
          grant: "aDE",
          selects: [{ class: "hr_department", value: "Finance" }],
          choices: ["retain", "exclude", "restrict"],
        },
      ],
      self_anchor: { anchor: "YW5jaG9y", given: [], choices: ["retire", "transfer"] },
      reentry: { choices: ["allowed", "blocked"] },
    },
    ended: [
      {
        grant: "ZW5kZWQ",
        selects: [{ class: "hr_department", value: "Sales" }],
        at: "2026-10-06T09:00:00Z",
        source: "workday",
      },
    ],
  });
  await open(page, bff, "/console/admin/offboarding");
  await page.getByLabel("Party ID").fill("cGFydHk");
  await page.getByTestId("preview").click();
  await expect(page.getByTestId("role-ended")).toContainText("Sales role ended (workday");
  await expect(page.getByTestId("survive")).toContainText("2 delegations");
  const depart = page.getByTestId("depart");
  await expect(depart).toBeDisabled();
  await expect(page.getByTestId("offboarded")).toHaveCount(0);
  await page.getByRole("group", { name: "Z3JhbnQx" }).getByLabel("Keep").check();
  await page.getByRole("group", { name: "Z3JhbnQy" }).getByLabel("Revoke").check();
  await page.getByRole("group", { name: "aW5zdDE" }).getByLabel("End").check();
  await page
    .getByRole("group", { name: "aDE (Finance)" })
    .getByLabel("Leave this person out")
    .check();
  await page.getByRole("group", { name: "YW5jaG9y" }).getByLabel("Retire").check();
  await expect(depart).toBeDisabled();
  await page.getByRole("group", { name: "Coming back" }).getByLabel("Blocked").check();
  await expect(depart).toBeDisabled();
  await page.getByRole("group", { name: "aDE (Finance)" }).getByLabel("Keep").check();
  await expect(depart).toBeEnabled();
  await depart.click();
  await page.getByRole("dialog").getByRole("button", { name: "Sign" }).click();
  await expect(page.getByTestId("offboarded")).toHaveText("Offboarded");
  const commit = bff.writes.find((w) => w.path === "realms/acme/offboarding/cGFydHk/commit");
  expect(commit?.body["choices"]).toEqual({
    grants: { Z3JhbnQx: "keep", Z3JhbnQy: "revoke" },
    instances: { aW5zdDE: "terminate" },
    holdings: { aDE: "retain" },
    self_anchor: "retire",
    reentry: "blocked",
  });
  const ops = commit?.body["operations"] as { operation: string; key: string }[];
  expect(ops.map((o) => [o.operation, o.key])).toEqual([
    ["revokeGrant", "Z3JhbnQy"],
    ["terminateInstance", "aW5zdDE"],
    ["departParty", "cGFydHk"],
  ]);
  expect(bff.drafts.some((d) => JSON.stringify(d).includes("party_depart"))).toBe(true);
});

// IA-2: Changes is information only
test("changes lists what changed and asks nothing", async ({ page, bff }) => {
  await open(page, bff, "/console/admin/changes");
  const rows = page.getByTestId("changes").getByRole("listitem");
  await expect(rows).toHaveCount(2);
  await expect(rows.first()).toContainText("Role version helpdesk v2 · by you");
  await expect(rows.nth(1)).toContainText("ended");
  await expect(page.getByText(/action required/i)).toHaveCount(0);
  await expect(page.getByRole("button", { name: /accept|approve/i })).toHaveCount(0);
});

// §8.17.10.2, X21, E10, E12, L1-ADP-18, Ek B 3104, 3105, 3106, 3107
test("publishing names unmapped parameters, then shows where the version waits", async ({
  page,
  bff,
}) => {
  await open(page, bff, "/console/developer/schemas");
  const region = page.getByRole("region", { name: "Publish a version" });
  await region.getByRole("textbox", { name: "Namespace" }).fill("commerce");
  await region.getByLabel("Catalog version").fill("3");
  await region.getByLabel(/^Actions/).fill("refund irreversible");
  await region.getByLabel(/^Parameters/).fill("refund.note text recipient");
  await region.getByRole("button", { name: "Publish" }).click();
  await expect(page.getByTestId("publish-warnings")).toHaveText(
    "note affects recipient — map it to a recipient type or it will be rejected",
  );
  expect(bff.published).toEqual([]);
  await region.getByLabel(/^Parameters/).fill("refund.note text opaque");
  await region.getByRole("button", { name: "Publish" }).click();
  await expect(page.getByTestId("published-pending")).toHaveText("Pending acceptance in: acme");
  await expect(page.getByTestId("published-unchanged")).toBeVisible();
  await expect(page.getByRole("button", { name: /accept/i })).toHaveCount(0);
  expect(bff.published).toHaveLength(1);
});

// TN-110, MD-14, X11: an account change is drafted, shown as decoded and signed before it is sent
test("suspending an account is one signed change", async ({ page, bff }) => {
  await open(page, bff, "/console/admin/people");
  const row = page.getByRole("row").filter({ hasText: "usr_active" });
  await row.getByRole("button", { name: "Suspend" }).click();
  const dialog = page.getByRole("dialog", { name: "Review and sign" });
  await expect(dialog).toContainText("idp.account.suspend v1");
  await expect(dialog).toContainText("idp.realm:[acme]");
  expect(bff.writes).toEqual([]);
  await dialog.getByRole("button", { name: "Sign" }).click();
  await expect(page.getByRole("status")).toContainText("Recorded as change");
  expect(bff.writes).toEqual([
    { method: "POST", path: "realms/acme/accounts/usr_active/suspend", body: expect.anything() },
  ]);
});

// TN-110, PI-7: a draft that does not decode to what was asked is never signed or sent
test("a draft for another action is refused before the signature screen", async ({ page, bff }) => {
  await open(page, bff, "/console/admin/sign-in");
  bff.tamper = true;
  await page.getByLabel("Display name on the sign-in page").fill("Acme Shop");
  await page.getByRole("region", { name: "Branding" }).getByRole("button").click();
  await expect(page.getByRole("region", { name: "Branding" }).getByRole("alert")).toHaveText(
    "What would be signed does not match what was shown. Nothing was signed.",
  );
  await expect(page.getByRole("dialog")).toHaveCount(0);
  expect(bff.writes).toEqual([]);
});

// X31, §8.17.7.1, TN-119: own holdings only, unless explicit authority to see more
test("people & agents shows only the viewer's own authority by default", async ({ page, bff }) => {
  await open(page, bff, "/console/admin/people", [
    "access/instance_terminate",
    "idp.account/suspend",
  ]);
  await expect(page.getByLabel("Party ID to look up")).toHaveCount(0);
  await page.getByRole("region", { name: "Authority you may see" }).getByRole("button").click();
  await expect(page.getByTestId("holdings")).toContainText("refund");
  const q = bff.queries.find((x) => x.kind === "action");
  expect(q?.query).toEqual({
    party: "acc_ada",
    resource: { namespace: "access.domain", path: ["acme"] },
  });
});

test("audit authority lets the viewer look up another party", async ({ page, bff }) => {
  await open(page, bff, "/console/admin/people");
  await page.getByLabel("Party ID to look up").fill("acc_bob");
  await page.getByRole("region", { name: "Authority you may see" }).getByRole("button").click();
  await expect(page.getByTestId("holdings")).toBeVisible();
  expect(bff.queries.find((x) => x.kind === "action")?.query).toMatchObject({ party: "acc_bob" });
});

// OP-142, §8.17.7.4, XI-3, Ek B 3353, 3361: ending running copies, its impact and aftermath
test("ending an agent's running copies shows the aftermath, never 'stopped'", async ({
  page,
  bff,
}) => {
  await open(page, bff, "/console/admin/people");
  const region = page.getByRole("region", { name: "End this agent's running copies" });
  await region.getByLabel("Running copy ID").fill("inst");
  await region.getByRole("button", { name: "Show" }).click();
  const after = page.getByTestId("aftermath");
  await expect(after).toContainText("New requests using this authority will be refused.");
  await expect(after).toContainText("Steps already allowed may continue until 2026-11-07T14:30");
  await expect(after).toContainText("Runtime: hasn't reported — status unknown.");
  await expect(after).not.toContainText(/stopped/i);
});

// §8.17.9.3, INV-15, Ek B 3818: each source by its use, with its blast radius
test("sources list each acceptance by use with its blast radius", async ({ page, bff }) => {
  await open(page, bff, "/console/admin/sources");
  const membership = page.locator('[data-use="subject-selection"]');
  await expect(membership).toContainText("Membership source");
  await expect(membership).toContainText("Protected change");
  await expect(membership.getByTestId("blast")).toHaveText(
    "Blast radius: 12 delegations depend on it.",
  );
  await expect(page.locator('[data-use="actor-binding"]')).toContainText(
    "This doesn't make it a Membership source.",
  );
  expect(bff.queries.some((q) => q.kind === "sources" && q.ais)).toBe(true);
});

// §5.13, Ek B 3372: a partner's authority up to its bridging Grants' ceilings
test("the domain page shows partner authority up to its ceiling", async ({ page, bff }) => {
  await open(page, bff, "/console/admin/domain");
  await expect(page.getByTestId("partners")).toContainText(
    "Partner authority (up to commerce.refund)",
  );
});

// §8.17.10.2, X21, Ek B 3104, 3105, 3107, 3330: pending acceptance, no accept button
for (const path of ["/console/admin/sources", "/console/developer/schemas"]) {
  test(`a pending schema shows its fingerprint and diff, and nothing accepts it (${path})`, async ({
    page,
    bff,
  }) => {
    await open(page, bff, path);
    await page.getByRole("textbox", { name: "Namespace", exact: true }).last().fill("commerce");
    await page.getByRole("button", { name: "Show" }).click();
    await expect(page.getByTestId("fingerprint")).toHaveText(
      Buffer.alloc(32, 8).toString("base64url"),
    );
    await expect(page.getByTestId("standing")).toHaveText("Pending acceptance");
    await expect(page.getByTestId("compatibility")).toHaveText(
      "The publisher declares it narrows v2; Access can't verify the meaning — this relies on trusting the publisher.",
    );
    await expect(page.getByTestId("existing-unchanged")).toBeVisible();
    await expect(page.getByTestId("new-actions")).toContainText(
      "Not included in existing delegations that use commerce.* (catalog pinned at issue)",
    );
    await expect(page.getByRole("button", { name: /accept/i })).toHaveCount(0);
    if (path.includes("developer")) {
      await expect(page.getByTestId("pending-in")).toHaveText("Pending acceptance in: acme");
    }
  });
}

// E12, Ek B 3106: an authority-relevant parameter without a type is warned about
test("publishing warns about an unmapped authority-relevant parameter", async ({ page, bff }) => {
  await open(page, bff, "/console/developer/schemas");
  await page.getByLabel(/What it affects/).fill("recipient");
  await expect(page.getByTestId("e12-warning")).toHaveText(
    "note affects recipient — map it to a recipient type or it will be rejected",
  );
  await page.getByLabel("Mapped type").fill("recipient");
  await expect(page.getByTestId("e12-warning")).toHaveCount(0);
});

// §8.13, Ek B 2963, 3034, 3381, 3382, 3383, OP-151 m.3 (b)
test("sign-in settings states delays, missing sources and the first signing time", async ({
  page,
  bff,
}) => {
  await open(page, bff, "/console/admin/sign-in");
  const status = page.getByTestId("signal-status");
  await expect(status).toContainText(
    "Signals from Acme IdP delayed since 2026-11-07T14:02:00.000Z — decisions use declared validity windows",
  );
  await expect(status).toContainText("GeoIP source not configured");
  await expect(status).toContainText(
    "POS-7's clock/profile report is missing; exposure window unknown beyond declared 2026-11-07T18:00:00.000Z.",
  );
  await expect(page.getByTestId("signing-at")).toContainText("2026-11-07T15:30:00.000Z");
  await expect(page.getByTestId("rp-warning")).toHaveText(
    "Changing the sign-in domain can't be undone for passkeys: users must create new passkeys.",
  );
  await expect(page.getByTestId("related-origins")).toContainText("public suffix list");
  await expect(page.getByTestId("related-origins")).toContainText("at most 5 distinct labels");
});

// IDP-31 (5), Ek B 3655: a native app offering another social sign-in is told to add Apple
test("sign-in settings recommend Sign in with Apple next to another social provider", async ({
  page,
  bff,
}) => {
  await open(page, bff, "/console/admin/sign-in");
  await expect(page.getByTestId("social-providers")).toContainText("google");
  await expect(page.getByTestId("social-warning")).toHaveText(
    "Your iOS app offers another social sign-in without Sign in with Apple. The App Store asks for Sign in with Apple next to it: enable Apple too.",
  );
});

// IDI-4, TN-17, Ek B 3382: the RP ID change needs the passkey count and is marked irreversible
test("an RP ID change needs the passkey count", async ({ page, bff }) => {
  await open(page, bff, "/console/admin/sign-in");
  await page.getByLabel("New sign-in domain").fill("login.acme.example");
  await page.getByLabel("Number of passkeys registered in this realm").fill("2");
  await page.getByRole("region", { name: /RP ID/ }).getByRole("button").click();
  await page.getByRole("dialog").getByRole("button", { name: "Sign" }).click();
  await expect(page.getByRole("alert")).toHaveText(
    "The count does not match this realm's passkeys. Nothing was changed.",
  );
  await page.getByLabel("Number of passkeys registered in this realm").fill("3");
  await page.getByRole("region", { name: /RP ID/ }).getByRole("button").click();
  await page.getByRole("dialog").getByRole("button", { name: "Sign" }).click();
  await expect(page.getByRole("region", { name: /RP ID/ }).getByRole("status")).toHaveText(
    "Recorded. This change can't be reversed for passkeys.",
  );
  expect(bff.writes.map((w) => w.path)).toEqual(["realms/acme/settings/rp-id"]);
});

// OP-153 m.22 (g), m.25 (b): report-only loosens the page and is said so before signing
test("the CSP mode is changed with the settings' ETag and says when it loosens", async ({
  page,
  bff,
}) => {
  await open(page, bff, "/console/admin/sign-in");
  const csp = page.getByRole("region", { name: "Page security policy" });
  await expect(page.getByTestId("csp-current")).toContainText("Enforce");
  await expect(page.getByTestId("csp-loosens")).toHaveCount(0);
  await csp.getByLabel(/Report only/).check();
  await expect(page.getByTestId("csp-loosens")).toContainText("higher-tier signature");
  await csp.getByRole("button").click();
  await page.getByRole("dialog").getByRole("button", { name: "Sign" }).click();
  await expect(csp.getByRole("status")).toContainText("Recorded");
  expect(bff.writes).toEqual([
    {
      method: "PUT",
      path: "realms/acme/settings/csp-mode",
      body: expect.objectContaining({ csp_mode: "report_only" }) as unknown,
      ifMatch: '"settings-1"',
    },
  ]);
});

// TN-33, OP-153 m.22 (c), m.25 (b), Ek B 4103: the DBSC switch is a sign-in policy patch
test("the device key offer is turned off by a sign-in policy patch", async ({ page, bff }) => {
  await open(page, bff, "/console/admin/sign-in");
  const panel = page.getByRole("region", { name: "Sign-in policy" });
  await expect(page.getByTestId("dbsc-state")).toHaveText("Sign-ins are offered a device key.");
  await panel.getByRole("checkbox").uncheck();
  await panel.getByRole("button").click();
  await page.getByRole("dialog").getByRole("button", { name: "Sign" }).click();
  await expect(panel.getByRole("status")).toContainText("Recorded");
  expect(bff.writes.map((w) => [w.method, w.path, w.body["dbsc"], w.ifMatch])).toEqual([
    ["PATCH", "realms/acme/settings/signin-policy", false, '"settings-1"'],
  ]);
});

// TN-18, OP-153 m.22 (k): the Related Origins are one list, one change
test("the related origins are set as one list", async ({ page, bff }) => {
  await open(page, bff, "/console/admin/sign-in");
  await page
    .getByLabel("Related origins, one per line (https://…)")
    .fill("https://shop.acme.example\n\nhttps://acme-brand.example ");
  const related = page.getByRole("region", { name: "Related origins" });
  await related.getByRole("button").click();
  await page.getByRole("dialog").getByRole("button", { name: "Sign" }).click();
  await expect(related.getByRole("status")).toContainText("Recorded");
  expect(bff.writes.map((w) => [w.path, w.body["origins"]])).toEqual([
    [
      "realms/acme/settings/related-origins",
      ["https://shop.acme.example", "https://acme-brand.example"],
    ],
  ]);
});

// OP-151 m.3, GitOps: a section the repository manages is read-only
test("a GitOps-managed section is read-only", async ({ page, bff }) => {
  await open(page, bff, "/console/admin/sign-in");
  bff.admin.set("realms/acme/settings", {
    rp_id: "acme.example",
    branding: { display_name: "Acme" },
    managed: ["branding", "rp_id"],
  });
  await page.reload();
  await expect(page.getByTestId("branding-name")).toHaveText("Acme");
  await expect(page.getByLabel("Display name on the sign-in page")).toHaveCount(0);
  await expect(page.getByLabel("New sign-in domain")).toHaveCount(0);
});

// IDP-36, Ek B 3093: counts only, labelled as not a decision input
test("the analytics panel shows counts and says they are not a decision input", async ({
  page,
  bff,
}) => {
  await open(page, bff, "/console/admin/sign-in");
  await expect(page.getByTestId("analytics-note")).toHaveText(
    "Counts only — not a decision input.",
  );
  const table = page.getByRole("region", { name: "Sign-in analytics" }).getByRole("table");
  await expect(table).toContainText("passkey: 60, email: 40");
  await expect(page.getByRole("region", { name: "Sign-in analytics" })).toContainText(
    "Failed sign-ins surged on 2026-11-06: 300",
  );
  // TN-85, CR-37, Ek B 3569, 3894
  await expect(page.getByTestId("analytics-legacy")).toHaveText(
    "Imported passwords still waiting to move to Argon2id at their next sign-in: 7",
  );
});

// §8.17.10.4, E-2, X21, Ek B 3114–3117: advisory check, explain, sandbox as an ordinary domain
test("the decision lab answers advisory and lists the sandbox as a domain", async ({
  page,
  bff,
}) => {
  await open(page, bff, "/console/developer/lab");
  await expect(page.getByLabel("Domain").locator("option")).toHaveText(["acme", "acme-sandbox"]);
  await expect(page.getByRole("checkbox")).toHaveCount(0);
  await page.getByLabel("Action namespace").fill("commerce");
  await page.getByLabel("Action name", { exact: true }).fill("refund");
  await page.getByLabel("Resource namespace").fill("commerce.order");
  await page.getByLabel(/Resource path/).fill("8812");
  await page.getByRole("button", { name: "Check" }).click();
  await expect(page.getByTestId("lab-check")).toContainText(
    "Advisory — not recorded, not a promise",
  );
  await expect(page.getByTestId("lab-check")).toContainText("Would be allowed now.");
  await page.getByRole("button", { name: "Explain" }).click();
  const why = page.getByTestId("explanation");
  await expect(why).toContainText("Blocked by a restriction set by your organization.");
  await expect(why).toContainText("The delegation ended (revoked, expired or lapsed).");
  await expect(page.locator("body")).not.toContainText(UNDISCLOSED);
  await page.getByLabel("Domain").selectOption("acme-sandbox");
  await expect(page.getByRole("button", { name: "Check" })).toBeDisabled();
});

// §9.9.2, Ek B 3018: the causal-binding warning
test("logs warn when a chain link is audit-only", async ({ page, bff }) => {
  await open(page, bff, "/console/developer/logs");
  await intent(page);
  await page.getByLabel("Record position").fill("12");
  await page.getByRole("button", { name: "Show" }).click();
  await expect(page.getByTestId("causal-warning")).toHaveText(
    "Chain link is audit-only in this domain (not enforced)",
  );
});

// §8.11, Ek B 3109: OAuth words only qualified
test("integrations name OAuth terms only as protocol terms", async ({ page, bff }) => {
  await open(page, bff, "/console/developer/integrations");
  await expect(page.getByRole("columnheader", { name: "OAuth grant type" })).toBeVisible();
  const text = await page.locator("main").innerText();
  for (const m of text.matchAll(/\bgrant type\b/gi)) {
    expect(text.slice(Math.max(0, m.index - 6), m.index)).toBe("OAuth ");
  }
  await expect(page.getByRole("heading", { name: "Delivery log" })).toBeVisible();
  // TN-136, Ek B 3108
  await expect(page.getByTestId("deliveries")).toContainText(
    "account.created · delivered · 1 attempts · HTTP 200",
  );
});

// OP-151 m.8 (d), (e), Ek B 3088, 3357: audit depth, pseudonyms and the two-part reason
test("a record at audit depth shows its basis, pseudonyms and both parts of a selection", async ({
  page,
  bff,
}) => {
  await open(page, bff, "/console/audit/records");
  await page.getByRole("spinbutton", { name: "Record position" }).fill("12");
  await page.getByLabel("Action (namespace.name)").fill("commerce.refund");
  await page.getByLabel("Resource (namespace:path)").fill("commerce.order:8812");
  await page.getByRole("button", { name: "Show" }).click();
  const admin = page.getByTestId("reason-admin");
  await expect(admin).toContainText("Read at record position 11");
  await expect(admin).toContainText(Buffer.alloc(32, 6).toString("base64url"));
  await expect(admin).toContainText("a2V5 v3");
  await expect(page.getByTestId("lineage")).toContainText("Pseudonymous holder ps_holder_2");
  await expect(page.getByTestId("selection")).toContainText("accepted for membership");
  await expect(page.getByTestId("lineage")).toBeVisible();
});

// OP-151 m.8 (g): totals only within the reader's disclosure
test("a search beyond the first page gives no total", async ({ page, bff }) => {
  await open(page, bff, "/console/audit/records");
  await page.getByRole("button", { name: "Who may do an action on a resource" }).click();
  await expect(page.getByTestId("result-count")).toHaveText(
    "More results you may see exist; totals are not shown beyond your view.",
  );
  await expect(page.getByRole("button", { name: "Next page" })).toBeVisible();
});

// INV-27: replay reports a mismatch as a finding
test("replay reports a mismatch", async ({ page, bff }) => {
  await open(page, bff, "/console/audit/replay");
  await intent(page);
  await page.getByLabel("Record position").fill("12");
  await page.getByRole("button", { name: "Replay" }).click();
  await expect(page.getByTestId("replay-result")).toContainText("evaluator mismatch finding");
});

// §5.4, §8.10, Ek B 3226, 3339, 3359, 3360: revocation impact; revoke is "from now on"
test("revocation impact shows exposure and never offers undo", async ({ page, bff }) => {
  await open(page, bff, "/console/audit/revocation");
  await page.getByLabel("Delegation ID").fill("g1");
  await page.getByRole("button", { name: "Show" }).click();
  const r = page.getByTestId("revocation-impact");
  await expect(r).toContainText("Revoke (from now on)");
  await expect(r).toContainText("Delegations that end with it: 1");
  await expect(r).toContainText("Longest exposure: 1200 s");
  await expect(page.getByRole("button", { name: /undo/i })).toHaveCount(0);
  expect(bff.queries.find((q) => q.kind === "revocation-impact")?.query).toEqual({ grant: "g1" });
});

// §9.12.3, E30, Ek B 3883: where a revocation took effect is each PEP's own report
test("revocation impact lists where it took effect and calls the rest unknown", async ({
  page,
  bff,
}) => {
  await open(page, bff, "/console/audit/revocation");
  await page.getByLabel("Delegation ID").fill("g1");
  await page.getByRole("button", { name: "Show" }).click();
  const acks = page.getByTestId("acknowledged");
  await expect(acks.getByRole("row")).toHaveCount(2);
  await expect(acks).toContainText("ledger-pep");
  await expect(acks).toContainText("2026-11-07T12:01:00.000Z");
  await expect(acks).toContainText("its status is unknown, not");
  await expect(page.getByTestId("revocation-impact")).toContainText("Not reported — unknown");
});

// EI-22, RR-13, Ek B 3227, 3362: a missing report is "Result unknown"
test("unknown outcomes say so", async ({ page, bff }) => {
  await open(page, bff, "/console/audit/unknown");
  await page.getByLabel("ID", { exact: true }).fill("inst");
  await page.getByLabel(/From/).fill("1");
  await page.getByLabel(/Until/).fill("2");
  await page.getByRole("button", { name: "Show" }).click();
  const c = page.getByTestId("compromise-impact");
  await expect(c.getByRole("row").filter({ hasText: "41" })).toContainText("Result unknown");
  await expect(c).toContainText("Offline passes issued: 1");
  await expect(c).not.toContainText(/failed/i);
});

// OP-151 m.8 (b), m.19 (d): the export is a signed `audit_export` Exercise; nothing leaves
// without the signature screen, the commit goes first and the package is the same request again
test("an export is never sent without a decoded, signed intent", async ({ page, bff }) => {
  await open(page, bff, "/console/audit/export");
  await page.getByLabel("From position").fill("1");
  await page.getByLabel("To position").fill("10");
  await page.getByRole("button", { name: "Review export" }).click();
  const dialog = page.getByRole("dialog", { name: "Review and sign" });
  await expect(dialog).toContainText("access.audit_export v1");
  await expect(dialog).toContainText("access.audit:[acme]");
  await dialog.getByRole("button", { name: "Cancel" }).click();
  expect(bff.commits).toEqual([]);
  expect(bff.seen.some((s) => s.path.startsWith("/proxy/adp/audit"))).toBe(false);
  await page.getByRole("button", { name: "Review export" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Sign" }).click();
  await expect(page.getByRole("status")).toContainText("Export recorded as");
  await expect(page.getByRole("link", { name: "Save the export package" })).toBeVisible();
  expect(bff.commits).toHaveLength(1);
  const order = bff.seen
    .map((s) => s.path)
    .filter((p) => p === "/proxy/adp/evaluation" || p === "/proxy/adp/audit/export");
  expect(order).toEqual(["/proxy/adp/evaluation", "/proxy/adp/audit/export"]);
});

// §8.5 S7, §8.17.9.3, TN-91, TN-92, TN-120, Ek B 3735, 3808, 3819, 3821
test("organizations show roots, membership sources apart from sign-in, domains and handovers", async ({
  page,
  bff,
}) => {
  await open(page, bff, "/console/admin/organizations");
  await page.getByRole("button", { name: "Acme <b>Corp</b>" }).click();
  const o = page.getByTestId("organization");
  await expect(o.getByRole("heading", { level: 4 })).toHaveText("Acme <b>Corp</b>");
  await expect(page.getByTestId("org-roots")).toHaveText("1 owners");
  const members = page.getByTestId("org-members");
  await expect(members).toContainText("Founded it");
  await expect(members).toContainText("Domain rule");
  await expect(members).toContainText("member v2 · waiting for the inviter's signed change");
  await expect(members).toContainText("protected scope starts 2026-11-08T12:00:00.000Z");
  await expect(o).toContainText("It is not the sign-in source");
  await expect(page.getByTestId("org-domains")).toContainText(
    "another organization claims it too — locked",
  );
  await expect(page.getByTestId("org-handovers")).toContainText("Accepted by the recipient");
  await expect(page.getByTestId("org-dns-recovery")).toContainText(
    "only when the domain's founding terms declared it",
  );
  await expect(page.getByTestId("org-drafts")).toContainText("draft only");
  await expect(o).toContainText("Who pays is not decided here.");
  await expect(page.getByText(/transfer/i)).toHaveCount(0);
});

// TN-94, C10, X20, OP-155 m.3 (i), Ek B 4872: the preview first, service accounts included, and
// no enforcement until the pending invitations' fate is chosen
test("SSO enforcement shows its preview and needs the invitations' fate", async ({ page, bff }) => {
  await open(page, bff, "/console/admin/organizations");
  await page.getByRole("button", { name: "Acme <b>Corp</b>" }).click();
  const sso = page.getByRole("region", { name: "Enterprise sign-in (SSO)" });
  await expect(page.getByTestId("sso-state")).toHaveText("Not enforced");
  await expect(page.getByTestId("sso-preview")).toContainText("ends 3 members' sign-ins");
  await expect(page.getByTestId("sso-service-accounts")).toContainText(": 1");
  const enforce = sso.getByRole("button", { name: "Enforce SSO" });
  await expect(enforce).toBeDisabled();
  await sso.getByLabel("Cancel them").check();
  await enforce.click();
  await page.getByRole("dialog").getByRole("button", { name: "Sign" }).click();
  await expect(sso.getByRole("status")).toContainText("Recorded");
  expect(bff.writes).toEqual([
    {
      method: "POST",
      path: `realms/acme/organizations/${Buffer.alloc(16, 10).toString("base64url")}/sso-enforcement`,
      body: expect.objectContaining({ invitations: "cancel" }) as unknown,
    },
  ]);
});

// §8.5 S7, §8.17.9.1, Ek B 3874: every change grouped by the record that made it
test("history lists each recorded change under its record and asks nothing", async ({
  page,
  bff,
}) => {
  await open(page, bff, "/console/admin/history");
  const h = page.getByTestId("history");
  await expect(h.locator(":scope > li")).toHaveCount(2);
  await expect(h).toContainText("Record 42 · 2026-11-07T11:02:00.000Z · by you");
  await expect(h).toContainText("helpdesk v2");
  await expect(
    page.getByRole("main").getByRole("button", { name: /sign|approve|revoke/i }),
  ).toHaveCount(0);
});

// §8.6, §8.13, §8.17.9.7, Ek B 3921: containment is one signed change per step
test("containment proposes each step as its own signed change", async ({ page, bff }) => {
  await open(page, bff, "/console/audit/containment");
  await page.getByLabel("Running copy ID").fill("inst");
  await page.getByLabel("From (Unix ms)").fill("1");
  await page.getByLabel("Until (Unix ms)").fill("2");
  await page.getByRole("button", { name: "Show" }).click();
  const steps = page.getByTestId("containment");
  await expect(steps.getByRole("listitem")).toHaveCount(1);
  await expect(steps).toContainText("End running copy");
  await expect(page.getByRole("button", { name: /stop all|stop everything/i })).toHaveCount(0);
  expect(bff.metaCommits).toEqual([]);
  await steps.getByRole("button", { name: "Review and sign" }).click();
  const dialog = page.getByRole("dialog", { name: "Review and sign" });
  await expect(dialog).toContainText("access.instance_terminate");
  await dialog.getByRole("button", { name: "Sign" }).click();
  await expect(steps).toContainText("Recorded as change");
  expect(bff.metaCommits).toHaveLength(1);
  expect(bff.metaCommits[0]?.action).toBe("instance_terminate");
});
