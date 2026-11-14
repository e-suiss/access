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
  bff.admin.set("realms/acme/organizations", {
    items: [{ organization: id(10), display_name: "Acme <b>Corp</b>", hrd: false }],
  });
  // TN-94, X20
  bff.admin.set(`realms/acme/organizations/${id(10)}/sso-enforcement/preview`, {
    organization: id(10),
    enforced: false,
    invitations: null,
    members: [],
    service_accounts: ["usr_bot"],
    pending_invitations: 2,
    totals: { members: 3 },
  });
  bff.admin.set(`realms/acme/organizations/${id(10)}`, {
    organization: id(10),
    display_name: "Acme <b>Corp</b>",
    hrd: true,
    roots: 1,
    members: [
      {
        account_id: "usr_owner",
        owner: true,
        membership_source: "founder",
        role: null,
        role_grant: null,
        cooling_until: null,
      },
      {
        account_id: "usr_dave",
        owner: false,
        membership_source: "domain_autojoin",
        role: { name: "member", version: 2 },
        role_grant: "pending",
        cooling_until: "2026-11-08T12:00:00Z",
      },
    ],
    domains: [
      {
        domain: "acme.example",
        method: "dns_txt",
        verified_at: "2026-11-01T00:00:00Z",
        reverify_by: "2027-01-30T00:00:00Z",
        changed_at: null,
        contested_at: null,
        autojoin: true,
        claimed: true,
      },
      {
        domain: "acme.test",
        method: "https",
        verified_at: null,
        reverify_by: null,
        changed_at: null,
        contested_at: "2026-11-02T00:00:00Z",
        autojoin: false,
        claimed: false,
      },
    ],
    handovers: [
      {
        handover: id(11),
        from: "usr_owner",
        to: "usr_dave",
        state: "contributed",
        effective_at: "2026-11-09T10:00:00Z",
        dns_recovery: false,
      },
    ],
    connection_drafts: [
      {
        protocol: "oidc",
        issuer: "https://login.acme.example",
        client_id: "access",
        drafted_by: id(2),
      },
    ],
  });
  bff.admin.set("realms/acme/upstream-idps", { items: [{ name: "corp", status: "active" }] });
  // OP-156 m.3 (i)
  bff.admin.set("realms/acme/domains", {
    items: [
      {
        host: "login.acme.example",
        status: "pending",
        served: false,
        txt_name: "_access-challenge.login.acme.example",
        txt_value: "challenge-value",
        cname_target: "acme.access.test",
        bound_as: null,
      },
      {
        host: "id.acme.example",
        status: "verified",
        served: true,
        txt_name: "_access-challenge.id.acme.example",
        txt_value: "other-value",
        cname_target: "acme.access.test",
        bound_as: null,
        certificate_expires_at: "2027-02-01T00:00:00.000Z",
      },
    ],
  });
  // OP-156 m.3 (r)
  bff.admin.set("realms/acme/signal-sources", {
    items: [
      {
        name: "acme-mdm",
        kind: "mdm",
        class: "posture_mdm",
        provider: "Acme MDM",
        issuer: "BwcHBwcHBwcHBwcHBwcHBw",
        format: "intune",
        transmitter: null,
        status: "live",
      },
    ],
  });
  bff.admin.set("realms/acme/social-providers", {
    items: [
      {
        preset: "google",
        client_id: "goog-1",
        client_secret_ref: "secret://social/google",
        shared_development_client: false,
        status: "active",
        warnings: [{ code: "apple-sign-in-recommended" }],
      },
    ],
  });
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
  bff.admin.set("realms/acme/webhooks/whk_1/deliveries", {
    items: [
      {
        event_id: "evt_1",
        event: "account.created",
        state: "delivered",
        attempts: 1,
        last_status: 200,
        occurred_at: "2026-11-07T10:00:00Z",
        queued_at: "2026-11-07T10:00:00Z",
      },
    ],
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
        legacy_password_accounts: 7,
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
        amends: [1, 2, 3].map((n) => ({
          grant_amend: {
            grant: id(n),
            authority: { authority: {}, constraints: {}, delegation: {}, requirements: [] },
            named: { name: "finance-approver", version: 5, digest: digest(4) },
          },
        })),
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
        pep: "shop-gateway",
        applied_at: null,
      },
    ],
    max_exposure_ms: 1_200_000,
    index_lag: 0,
    orphan_tuples: 0,
    acknowledged: [{ pep: "ledger-pep", applied_at: Date.UTC(2026, 10, 7, 12, 1), basis: 88 }],
    aftermath: {
      grants_ending: 1,
      projections_open: 1,
      honoured_until_ms: Date.UTC(2026, 10, 7, 18, 0),
      running_copies: 2,
      confirmed_applied: 0,
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
  const action = (name: string) => ({
    namespace: "idp.account",
    name,
    major: 1,
    schema: digest(7),
  });
  bff.searches.set("role", {
    results: [
      {
        type: "role",
        name: "helpdesk",
        version: 1,
        latest: 1,
        digest: digest(4),
        since: 7,
        authority: {
          actions: { exact: [action("suspend")] },
          resource: { namespace: "idp", prefix: ["acme"] },
        },
        not_included: {
          reserved: [{ namespace: "commerce", name: "payout", major: 1, schema: digest(6) }],
          catalogs: [{ namespace: "commerce", catalog: digest(5), catalog_version: 12, newer: [] }],
        },
        advisory: true,
      },
    ],
    page: { next_token: "" },
    context: { advisory: true },
  });
  bff.searches.set("sources", {
    results: [
      {
        type: "sources",
        sources: [
          {
            acceptance: id(31),
            use: "actor-binding",
            issuer: { party: id(32) },
            classes: ["authentication"],
            namespace: null,
            since: "3",
            protected: false,
            dependents: 0,
          },
          {
            acceptance: id(33),
            use: "subject-selection",
            issuer: { party: id(34) },
            classes: ["employee"],
            namespace: null,
            since: "5",
            protected: true,
            dependents: 12,
          },
        ],
        partners: [
          {
            domain: digest(7),
            acceptances: [id(35)],
            ceilings: [
              {
                grant: id(36),
                class: "buyer",
                actions: [{ namespace: "commerce", name: "refund", major: 1, schema: digest(6) }],
                resource: { namespace: "commerce", prefix: [] },
                until: 9_999_999_999_999,
              },
            ],
          },
        ],
        advisory: true,
      },
    ],
    page: { next_token: "" },
    context: { advisory: true },
  });
  bff.searches.set("holdings", {
    results: [
      {
        type: "holding",
        grant: id(11),
        holder: id(2),
        since: 4,
        actions: [action("reactivate"), { ...action("grant_amend"), namespace: "access" }],
        resource: { namespace: "idp", prefix: ["acme"] },
        advisory: true,
      },
    ],
    page: { next_token: "" },
    context: { advisory: true },
  });
  const line = (a: string, tier: string) => ({
    action: a,
    tier_when_widening: tier,
    grant_quorum: 0,
    joint_root_quorum: tier === "ct3" ? 2 : 0,
  });
  bff.searches.set("admin-grant", {
    results: [
      {
        type: "admin_grant",
        grant: id(12),
        role: { name: "admins", version: 2 },
        actions: [line("grant_issue", "ct2"), line("grant_amend", "ct3")],
        reserved: [line("anchor_amend", "ct3"), line("acceptance_amend", "ct3")],
        advisory: true,
      },
    ],
    page: { next_token: "" },
    context: { advisory: true },
  });
  bff.searches.set("changes", {
    results: [
      {
        type: "change",
        position: "42",
        at: Date.UTC(2026, 10, 7, 11, 2),
        kind: "authority_set",
        id: "helpdesk",
        version: 2,
        ended: false,
        own: true,
        advisory: true,
      },
      {
        type: "change",
        position: "41",
        at: Date.UTC(2026, 10, 6, 9, 0),
        kind: "grant",
        id: id(3),
        version: null,
        ended: true,
        own: false,
        advisory: true,
      },
    ],
    page: { next_token: "" },
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
