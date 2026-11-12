// TI-17, CMP-26, HL-40, OP-158 m.3 (o), (p): Settings ▸ Placement and Durability over mocked
// management answers; the placement, residency, rehome ends and declarations are the server's
// (bins/access-server placement tests).
import AxeBuilder from "@axe-core/playwright";

import { BASE, open } from "./data.js";
import { expect, test } from "./fixtures.js";

test.beforeEach(async ({ context, bff }) => {
  await bff.signIn(context, BASE);
  bff.admin.set("realms/acme/placement", {
    cell: "eu-central-1",
    region: "eu-central",
    dedicated_cell: false,
    tenant: null,
    realm: { cell: "eu-central-1", dedicated: false, version: 2 },
    domain: null,
    governing_domain: "ZG9tYWluLWlk",
    residency: { region: "eu-central", class: "regional" },
    pending_rehome: [{ side: "from", to: "bmV3LWRvbWFpbg", position: "12" }],
    routing_only: true,
  });
  bff.admin.set("realms/acme/durability", {
    durability: "single-node",
    class: "regional",
    region: "eu-central",
    dr_profile: null,
    rpo_s: null,
    governing_domain: "ZG9tYWluLWlk",
    witnesses: [{ name: "w-1", operator: "Example Witness Ltd", independent: true }],
    replicas: [],
    declared_durability: "single-node",
    acknowledges: false,
  });
});

// TI-17, CMP-26, E14
test("the placement screen shows the cell, the residency and a rehome waiting for its second end", async ({
  page,
  bff,
}) => {
  await open(page, bff, "/console/admin/placement");
  await expect(page.getByRole("heading", { level: 2, name: "Placement" })).toBeVisible();
  await expect(page.getByTestId("placement-realm-cell")).toHaveText("eu-central-1");
  await expect(page.getByTestId("placement-domain-cell")).toContainText("eu-central-1");
  await expect(page.getByTestId("placement-residency")).toContainText(
    "Data stays in eu-central (regional)",
  );
  await expect(page.getByTestId("placement-pending")).toContainText("from → bmV3LWRvbWFpbg");
  expect(bff.writes).toEqual([]);
  const a11y = await new AxeBuilder({ page }).include("main").analyze();
  expect(a11y.violations).toEqual([]);
});

// HL-40, SEC23
test("the durability screen says single node and never shows revocations as confirmed", async ({
  page,
  bff,
}) => {
  await open(page, bff, "/console/admin/durability");
  await expect(page.getByRole("heading", { level: 2, name: "Durability" })).toBeVisible();
  await expect(page.getByTestId("durability-profile")).toHaveAttribute(
    "data-durability",
    "single-node",
  );
  await expect(page.getByTestId("durability-profile")).toContainText("Single node");
  await expect(page.getByTestId("durability-witnesses")).toContainText("Example Witness Ltd");
  await expect(page.getByTestId("durability-unconfirmed")).toBeVisible();
  expect(bff.writes).toEqual([]);
  const a11y = await new AxeBuilder({ page }).include("main").analyze();
  expect(a11y.violations).toEqual([]);
});

// RR-35, OP-159 m.3 (g), (j)
test("the durability screen says there is no post-quantum anchor yet and marks a proposed witness", async ({
  page,
  bff,
}) => {
  bff.admin.set("realms/acme/durability", {
    durability: "replicated",
    class: "regional",
    region: "eu-central",
    dr_profile: null,
    rpo_s: null,
    witnesses: [
      { name: "w-1", operator: "Example Witness Ltd", independent: true, canonical: true },
      { name: "w-2", operator: "Other Witness Ltd", independent: true, canonical: false },
    ],
    replicas: [
      { name: "r-1", operator: "Example Replica Ltd", independent: true, canonical: true },
    ],
    acknowledges: true,
    pq_reanchor: null,
  });
  await open(page, bff, "/console/admin/durability");
  await expect(page.getByTestId("durability-pq-anchor")).toHaveText("No post-quantum anchor yet");
  await expect(page.getByTestId("durability-proposed")).toHaveCount(1);
  await expect(page.getByTestId("durability-witnesses")).toContainText(
    "Other Witness Ltd · Independent of the provider · Proposed by the provider",
  );
  await expect(page.getByTestId("durability-unconfirmed")).toHaveCount(0);
  expect(bff.writes).toEqual([]);
  const a11y = await new AxeBuilder({ page }).include("main").analyze();
  expect(a11y.violations).toEqual([]);
});

// RR-35, HL-34, OP-159 m.3 (g)
test("the durability screen shows the last post-quantum anchor and claims nothing more", async ({
  page,
  bff,
}) => {
  bff.admin.set("realms/acme/durability", {
    durability: "replicated",
    class: "regional",
    region: "eu-central",
    dr_profile: null,
    rpo_s: null,
    witnesses: [],
    replicas: [],
    acknowledges: false,
    pq_reanchor: { size: 42, time: 1800000000000, witnesses: ["w-pq"] },
  });
  await open(page, bff, "/console/admin/durability");
  await expect(page.getByTestId("durability-pq-anchor")).toHaveText(
    "Post-quantum anchor at log size 42, 2027-01-15T08:00:00.000Z",
  );
  await expect(page.getByTestId("durability")).not.toContainText(
    /quantum[- ]safe|continuity|proves/i,
  );
});
