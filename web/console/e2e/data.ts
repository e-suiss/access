// Answers of the management API and ADP for the section screens, in the shapes of
// `sdks/openapi/admin-v1.json` and `access-v1.json` (`crates/http/src/adp/report.rs`).
import type { Page } from "@playwright/test";

import { expect } from "./fixtures.js";
import type { ConsoleMock } from "./mock.js";

export const BASE = "http://127.0.0.1:4173";

const id = (n: number) => Buffer.alloc(16, n).toString("base64url");
const digest = (n: number) => Buffer.alloc(32, n).toString("base64url");

/** A threshold a restriction holds; the console must never render it (§8.17.8.5). */
export const UNDISCLOSED = "refunds over 4,321 TRY at night";

export function seed(bff: ConsoleMock): void {
  bff.admin.set("realms/acme", { audience: "access-admin:realm:acme", sandbox: false });
  bff.admin.set("realms/acme/accounts", {
    items: [
      { account_id: "usr_active", status: "active" },
      { account_id: "usr_held", status: "suspended" },
    ],
  });
  bff.admin.set("realms/acme/settings", {
    rp_id: "acme.example",
    branding: { display_name: "Acme" },
    managed: [],
  });
  bff.admin.set("realms/acme/signals", {
    transmitters: [{ name: "Acme IdP", delayed_since: Date.UTC(2026, 10, 7, 14, 2) }],
    geoip: "not_configured",
    verifiers: [{ name: "POS-7", declared_until: Date.UTC(2026, 10, 7, 18, 0) }],
  });
  bff.admin.set("platform/realms/acme", {
    slug: "acme",
    tenant_id: "tnt_one",
    key_state: "published",
    signing_available_at: "2026-11-07T15:30:00Z",
  });
  bff.admin.set("platform/tenants/tnt_one/sandbox-domains", {
    items: [{ slug: "acme-sandbox", domain: digest(9) }],
  });
  bff.admin.set("realms/acme/clients", {
    items: [
      {
        client_id: "cli_shop",
        display_name: "Shop",
        token_endpoint_auth_method: "private_key_jwt",
        redirect_uris: ["https://shop.example/cb"],
        grant_types: ["authorization_code"],
        status: "active",
      },
    ],
  });
  bff.admin.set("realms/acme/upstream-idps", { items: [{ name: "corp", status: "active" }] });
  bff.admin.set("realms/acme/hooks", {
    items: [
      {
        hook_id: "hok_1",
        point: "token_issuance",
        url: "https://hooks.example/t",
        on_no_answer: "refuse",
      },
    ],
  });
  bff.admin.set("realms/acme/webhooks", {
    items: [{ webhook_id: "whk_1", url: "https://hooks.example/w", events: ["account.created"] }],
  });
  bff.admin.set("realms/acme/analytics", {
    days: [
      {
        day: "2026-11-06",
        started: 120,
        completed: 100,
        failed: 20,
        passkey_accounts: 40,
        mfa_setup: 55,
        methods: { passkey: 60, email: 40 },
      },
    ],
    surges: [{ day: "2026-11-06", failed: 300 }],
  });
  bff.searches.set("change-impact", {
    results: [
      {
        type: "change_impact",
        role: { name: "finance-approver", from: 4, to: 5 },
        pin: { name: "finance-approver", version: 5, digest: digest(4) },
        relation: "incomparable",
        moves: [id(1), id(2), id(3)],
        holders: { parties: 53, everyone: false, upper_bound: false },
        abilities: [
          {
            ability: { action: { namespace: "commerce", name: "refund" }, bounds: {} },
            holders_gaining: 41,
            holders_losing: 0,
          },
          {
            ability: { action: { namespace: "commerce", name: "void" }, bounds: {} },
            holders_gaining: 0,
            holders_losing: 12,
          },
        ],
        expansion: { tier: "ct3", joint_root_quorum: 2, delay_s: 3600, requirements: [] },
        orphans: { empty_scopes: [], unselecting: [] },
        capped: false,
        advisory: true,
      },
    ],
    page: { next_token: "", total: 1 },
    context: { advisory: true },
  });
  bff.searches.set("schema-publications", {
    results: [
      {
        type: "schema_publication",
        fingerprint: digest(8),
        publisher: id(5),
        namespace: "commerce",
        catalog_version: 3,
        standing: "pending_acceptance",
        accepted_version: 2,
        diff: {
          added: ["commerce.refund_partial"],
          removed: [],
          changed: ["commerce.refund"],
          reserved_added: [],
          reserved_removed: [],
        },
        reserved: ["commerce.payout"],
        parameters: [
          {
            action: "commerce.refund",
            parameter: "amount",
            class: "authority-relevant",
            affects: "amount",
          },
          { action: "commerce.refund", parameter: "note", class: "authority-opaque" },
        ],
        compatibility: { from: 2, relation: "narrowing" },
        existing_grants_unchanged: true,
        new_actions: ["commerce.refund_partial"],
        text: [],
        advisory: true,
      },
    ],
    page: { next_token: "", total: 1 },
    context: { advisory: true },
  });
  const revocation = {
    type: "revocation_impact",
    revoked: { instance: id(6) },
    at: 1,
    subtree: [id(7)],
    exposed: [
      {
        exercise: digest(1),
        holder: id(8),
        class: "reusable",
        horizon_ms: Date.UTC(2026, 10, 7, 14, 30),
        window_ms: 1_200_000,
      },
    ],
    max_exposure_ms: 1_200_000,
    index_lag: 0,
    orphan_tuples: 0,
    aftermath: {
      grants_ending: 1,
      projections_open: 1,
      honoured_until_ms: Date.UTC(2026, 10, 7, 18, 0),
      running_copies: 2,
    },
    advisory: true,
  };
  bff.searches.set("revocation-impact", {
    results: [revocation],
    page: { next_token: "", total: 1 },
    context: { advisory: true },
  });
  bff.searches.set("compromise-impact", {
    results: [
      {
        type: "compromise_impact",
        compromised: { instance: id(6) },
        window: { from: 1, until: 2 },
        instance: id(6),
        exercises: [
          { pos: 41, intent: digest(2), outcome: null },
          { pos: 42, intent: digest(3), outcome: "reported-done" },
        ],
        grants: [],
        contributions: [],
        projections: [digest(5)],
        claims: [],
        capped: false,
        advisory: true,
      },
    ],
    page: { next_token: "", total: 1 },
    context: { advisory: true },
  });
  bff.searches.set("subject", {
    results: [{ type: "access_party", id: id(1) }],
    page: { next_token: "more", has_more: true },
    context: { advisory: true },
  });
  bff.searches.set("action", {
    results: [{ namespace: "commerce", name: "refund" }],
    page: { next_token: "", total: 1 },
    context: { advisory: true },
  });
  const blockers = [
    { class: "restricted", subcode: "restricted/policy:night", detail: UNDISCLOSED },
    { class: "ended", subcode: "ended/some-future-subcode" },
  ];
  bff.explains.set("requester", {
    decision: false,
    context: { advisory: true, blockers, policy: { threshold: UNDISCLOSED } },
  });
  bff.explains.set("viewer", {
    decision: true,
    context: {
      causal_binding: "audit-only",
      lineage: [{ hop: 1, grant: { id: id(1) }, holder: { id: id(2) } }],
    },
  });
  bff.explains.set("audit", {
    decision: true,
    context: {
      replay: { match: false },
      selection: { source: id(4) },
      lineage: [
        { hop: 1, grant: { id: id(1) }, holder: { id: id(2) } },
        { hop: 2, grant: { pseudonym: "ps_grant_2" }, holder: { pseudonym: "ps_holder_2" } },
      ],
      reason_admin: {
        basis_ref: {
          domain: digest(3),
          position_q_minus_1: 11,
          version_vector_digest: digest(6),
        },
        state_basis: {
          evaluated_at: Date.UTC(2026, 10, 7, 14, 2),
          reads: [{ key: "a2V5", version: 3 }],
        },
        reasons: [{ category: "authority", code: "no-covering-authority" }],
        cited: [id(9)],
      },
    },
  });
}

/** Signs in, registers this browser's key and opens `path`, the viewer eligible for `actions`. */
export async function open(
  page: Page,
  bff: ConsoleMock,
  path: string,
  actions: readonly string[] = [],
): Promise<void> {
  bff.eligible.add("acc_ada");
  for (const a of actions) bff.eligibleActions.add(a);
  seed(bff);
  await page.goto("/console/");
  await page.getByRole("button", { name: "Register this browser" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Sign" }).click();
  await expect(page.getByTestId("device-state")).toContainText("Device key registered");
  const names: Readonly<Record<string, string>> = {
    admin: "Admin",
    developer: "Developer",
    audit: "Audit",
  };
  const section = names[path.split("/")[2] ?? ""];
  if (section !== undefined) {
    await expect(
      page
        .getByRole("navigation", { name: "Console sections" })
        .getByRole("link", { name: section }),
    ).toBeVisible();
  }
  await page.evaluate((p) => {
    history.pushState(null, "", p);
    dispatchEvent(new PopStateEvent("popstate"));
  }, path);
}
