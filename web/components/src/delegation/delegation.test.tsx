import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import {
  BLOCKS,
  DAY_MS,
  type Draft,
  DelegationSheet,
  TERMS,
  type Viewer,
  budgetView,
  capacityOptions,
  classify,
  endingHint,
  exclusionText,
  giveOnce,
  giveRequest,
  heldActions,
  jitOptions,
  mayOpen,
  newDraft,
  preview,
  roleLine,
  rootText,
  validityAllowed,
} from "./index.js";

const NOW = 1_800_000_000_000;

const viewer: Viewer = {
  holds: ["shop.refund", "shop.order.read", "shop.price.set"],
  ceilings: [{ action: "shop.refund", amount: 200_000, unit: "TRY", financial: false }],
  agency: { self: true, orgs: [] },
};

function agentDraft(): Draft {
  return {
    ...newDraft("template", { name: "Shop assistant", kind: "agent" }, ["shop.refund"], NOW),
    capacity: "on_your_behalf",
  };
}

describe("S1 Delegation model", () => {
  // X10, OP-153 m.3 (x), §8.17.5.1
  it("starts with passing on off, no capacity and an agent's end in 30 days", () => {
    const d = newDraft("editor", { name: "Shop assistant", kind: "agent" }, ["shop.refund"], NOW);
    expect(d.canPassOn).toBe(false);
    expect(d.capacity).toBeNull();
    expect(d.valid).toEqual({ kind: "until", atMs: NOW + 30 * DAY_MS });
    expect(preview(d, viewer, NOW).blockers).toContain("Choose in what capacity they act");
    expect(validityAllowed("agent", { kind: "until_revoked", explicit: true })).toBe(false);
    expect(validityAllowed("human", { kind: "until_revoked", explicit: true })).toBe(true);
    const far = { ...agentDraft(), valid: { kind: "until" as const, atMs: NOW + 400 * DAY_MS } };
    expect(giveRequest(far, viewer, NOW, false)).toBeNull();
    const human = newDraft("editor", { name: "Bob", kind: "human" }, ["shop.refund"], NOW);
    expect(human.valid).toBeNull();
  });

  // §8.17.5.1, X9
  it("shows the nine mandatory blocks in order and the typed reading of a phrase", () => {
    const d: Draft = {
      ...agentDraft(),
      source: "natural_language",
      limits: [{ action: "shop.refund", amount: 50_000, unit: "TRY", financial: false }],
      interpretations: [{ phrase: "small purchases", typed: "each purchase ≤ 500 TRY" }],
    };
    const p = preview(d, viewer, NOW);
    expect(p.blocks.map((b) => b.block)).toEqual([...BLOCKS]);
    expect(BLOCKS).toEqual([
      "to",
      "can_do",
      "acting_as",
      "can_pass_on",
      "limits",
      "requires",
      "valid",
      "not_included",
      "interpretation",
    ]);
    expect(p.blocks.find((b) => b.block === "interpretation")?.lines).toEqual([
      '"small purchases" → each purchase ≤ 500 TRY',
    ]);
    const req = giveRequest(d, viewer, NOW, false);
    expect(req?.action).toBe("grant.issue");
    expect(req?.draft.limits[0]?.amount).toBe(50_000);
  });

  // X10, §8.17.5.1
  it("always says what is not included", () => {
    const lines =
      preview(agentDraft(), viewer, NOW).blocks.find((b) => b.block === "not_included")?.lines ??
      [];
    expect(lines).toContain("Protected actions");
    expect(lines).toContain("Actions added later");
    expect(lines).toContain("Everything else you hold: shop.order.read, shop.price.set");
  });

  // §8.17.5.1
  it("marks what the viewer could not give and refuses to commit it", () => {
    const d: Draft = {
      ...agentDraft(),
      limits: [{ action: "shop.refund", amount: 500_000, unit: "TRY", financial: false }],
    };
    const p = preview(d, viewer, NOW);
    expect(p.blockers).toContain("You can approve up to 2,000 TRY; you can't give 5,000 TRY");
    expect(giveRequest(d, viewer, NOW, false)).toBeNull();
  });

  // X10, §8.17.5.1
  it("derives the capacity choices from the viewer's agency", () => {
    expect(capacityOptions({ ...viewer, agency: { self: false, orgs: ["Acme"] } })).toEqual([
      "on_behalf_of_org",
    ]);
    expect(capacityOptions(viewer)).toContain("on_your_behalf");
  });

  // X8, §8.17.5.2, §9.6, R8
  it("computes the just-in-time options and give-once from the viewer-scoped explain", () => {
    const blockers = [
      { reasonClass: "no_grant", resolvableByViewer: true, text: "No delegation" },
      { reasonClass: "budget", resolvableByViewer: false, text: "Acme's monthly budget" },
    ];
    expect(jitOptions(blockers)).toEqual(["give_once", "give_similar", "decline"]);
    expect(
      jitOptions([{ reasonClass: "approval_pending", resolvableByViewer: false, text: "x" }]),
    ).toEqual(["approve_request", "decline"]);
    const once = giveOnce(blockers, NOW);
    expect(once).toEqual({
      count: 1,
      untilMs: NOW + 3_600_000,
      stillBlockedBy: ["Acme's monthly budget"],
    });
    expect(giveOnce(blockers, NOW, 10 * DAY_MS)?.untilMs).toBe(NOW + DAY_MS);
    expect(giveOnce(blockers.slice(1), NOW)).toBeNull();
    expect(new Set(Object.values(TERMS)).size).toBe(3);
  });

  // X15, §8.17.5.6
  it("shows the narrowest remaining budget and money on its own line", () => {
    const v = budgetView([
      {
        remaining: 900,
        unit: "TRY",
        resetsAtMs: NOW + DAY_MS,
        countedResultUnknown: 1,
        financial: false,
      },
      { remaining: 400, unit: "TRY", resetsAtMs: null, countedResultUnknown: 0, financial: false },
      { remaining: 5_000, unit: "TRY", resetsAtMs: null, countedResultUnknown: 0, financial: true },
    ]);
    expect(v?.remaining).toBe(400);
    expect(v?.countedResultUnknown).toBe(1);
    expect(v?.financial?.remaining).toBe(5_000);
    expect(v?.exhausted).toBe(false);
  });

  // X16, §8.17.5.7, §8.17.5.9, §8.17.7.7, XI-19
  it("offers turn off for a role, give back for a direct grant, and never renews by itself", () => {
    expect(heldActions({ kind: "role", role: "Finance Approver", org: "Acme" }, false)).toEqual([
      "turn_off_for_me",
      "ask_to_exclude",
    ]);
    expect(heldActions({ kind: "direct" }, false)).toEqual(["give_back"]);
    expect(heldActions({ kind: "given_by_me" }, false)).toEqual(["narrow", "renew"]);
    expect(heldActions({ kind: "given_by_me" }, true)).toEqual(["create_again"]);
    expect(endingHint(NOW + 3 * DAY_MS, 12, NOW)).toBe("Ends in 3 days — used 12 times this week");
    expect(endingHint(NOW + 3 * DAY_MS, 0, NOW)).toBeNull();
  });

  // §8.17.7.5, X11, XI-4
  it("narrows without consent and treats any widening as an expansion", () => {
    const before: Draft = {
      ...agentDraft(),
      limits: [{ action: "shop.refund", amount: 50_000, unit: "TRY", financial: false }],
    };
    const narrower: Draft = {
      ...before,
      limits: before.limits.map((l) => ({ ...l, amount: 10_000 })),
    };
    expect(classify(before, narrower)).toBe("narrow");
    expect(classify(narrower, before)).toBe("widen");
    expect(classify(before, { ...before, limits: [] })).toBe("widen");
    expect(classify(before, { ...before, canPassOn: true })).toBe("widen");
  });

  // §8.8, §8.11, §8.17.7.6, §8.17.5.7
  it("says root, role and exclusion in words, never owner", () => {
    expect(rootText({ name: "Acme board", threshold: 2, of: 3 })).toBe("Root: Acme board, 2 of 3");
    expect(roleLine("Finance Approver v4", "everyone HR lists in Finance", 14)).toBe(
      "Give Finance Approver v4 to: everyone HR lists in Finance — currently 14",
    );
    expect(exclusionText("Acme", Date.UTC(2026, 9, 7))).toBe(
      "Acme excluded you from this role on 7 Oct",
    );
    expect(rootText({ name: "Acme board", threshold: 2, of: 3 }).toLowerCase()).not.toContain(
      "owner",
    );
  });
});

describe("DelegationSheet", () => {
  // XI-7, IA-1, §8.17.5.1
  it("opens only when the viewer started it or from Needs Attention", () => {
    expect(mayOpen("requester")).toBe(false);
    const props = {
      draft: agentDraft(),
      viewer,
      nowMs: NOW,
      onGive: () => undefined,
      onCancel: () => undefined,
    };
    expect(renderToStaticMarkup(<DelegationSheet {...props} openedBy="requester" />)).toBe("");
    expect(
      renderToStaticMarkup(<DelegationSheet {...props} openedBy="needs_attention" />),
    ).toContain("Give access");
  });

  // X27, §8.17.4.3, §9.9, §2.2.2 #2
  it("is a Connect sheet for an app with no scope list and no allow words", () => {
    const html = renderToStaticMarkup(
      <DelegationSheet
        draft={agentDraft()}
        viewer={viewer}
        nowMs={NOW}
        openedBy="user"
        app="Shop"
        onGive={() => undefined}
        onCancel={() => undefined}
      />,
    );
    expect(html).toContain("Connect Shop");
    expect(html).toContain("Not included");
    expect(html).not.toMatch(/\b(Allow|Authorize|scope)/i);
    const done = renderToStaticMarkup(
      <DelegationSheet
        draft={agentDraft()}
        viewer={viewer}
        nowMs={NOW}
        openedBy="user"
        app="Shop"
        created
        onGive={() => undefined}
        onCancel={() => undefined}
      />,
    );
    expect(done).toContain("Delegation created");
  });
});
