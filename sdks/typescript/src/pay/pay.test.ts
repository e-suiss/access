// OP-156 m.3 (u), (v), XI-14, §8.17.5.11, R8, X8, INV-20, E26
import { describe, expect, it } from "vitest";

import {
  budgetMoney,
  merchantsOf,
  oneTimeOf,
  payLimitOf,
  saveCardOf,
  type DescribedIntent,
} from "./index.js";

const payment: DescribedIntent = {
  digest: "ZA",
  action: { namespace: "pay", name: "initiate", major: "1" },
  params: { amount: "30000 try" },
  opaque: [],
  recipient: "TQ",
  purpose: { code: "order-1182" },
  validity: { from: "1000", until: "601000" },
};

describe("pay", () => {
  // XI-14, E21, F9
  it("reads Pay's own limit and nothing that is not one", () => {
    expect(
      payLimitOf({ currency: "TRY", limit_minor: 500_000, period: "day", held_minor: 12_000 }),
    ).toEqual({
      limit: { currency: "TRY", minor: 500_000 },
      period: "day",
      held: { currency: "TRY", minor: 12_000 },
    });
    for (const bad of [
      { currency: "try", limit_minor: 1, period: "day" },
      { currency: "TRY", limit_minor: -1, period: "day" },
      { currency: "TRY", limit_minor: 1, period: "week" },
      { currency: "TRY", limit_minor: 1, period: "day", remaining: 3 },
      null,
      [],
    ]) {
      expect(payLimitOf(bad)).toBeUndefined();
    }
  });

  // §8.17.5.11, R8, X8, INV-20
  it("is a one-time payment only with an exact amount, recipient and purpose, and never a Grant", () => {
    expect(oneTimeOf(payment)).toEqual({
      amount: { currency: "TRY", minor: 30_000 },
      recipient: "TQ",
      purpose: "order-1182",
      until: 601_000,
    });
    expect(
      oneTimeOf({ ...payment, action: { namespace: "access", name: "grant_issue", major: "1" } }),
    ).toBe("authority_change");
    expect(oneTimeOf({ ...payment, opaque: ["payload"] })).toBe("authority_change");
    expect(oneTimeOf({ ...payment, params: {} })).toBe("no_amount");
    expect(oneTimeOf({ ...payment, params: { amount: "300" } })).toBe("no_amount");
    expect(oneTimeOf({ ...payment, recipient: null })).toBe("no_recipient");
    expect(oneTimeOf({ ...payment, purpose: null })).toBe("no_purpose");
    expect(oneTimeOf({ ...payment, validity: { from: "0", until: "86400001" } })).toBe("too_long");
  });

  // §8.17.5.11, §8.17.7.2, E26
  it("lists the merchants given a pay Grant and nothing about their own business", () => {
    const merchants = merchantsOf([
      {
        type: "holding",
        grant: "g-shop",
        groups: ["shared_from_you"],
        holder: { party: "shop" },
        actions: [{ namespace: "pay", name: "initiate" }],
        budget: [{ dimension: { amount: "try" }, capacity: 50_000, window: "transaction" }],
        validity: { until: 1_800_000_000_000 },
        agent: { operator: "shop" },
      },
      {
        type: "holding",
        grant: "g-work",
        groups: ["shared_from_you"],
        holder: { party: "colleague" },
        actions: [{ namespace: "work", name: "approve" }],
      },
      {
        type: "holding",
        grant: "g-mine",
        groups: ["your_authority"],
        holder: { party: "me" },
        actions: [{ namespace: "pay", name: "initiate" }],
      },
    ]);
    expect(merchants).toEqual([
      {
        grant: "g-shop",
        merchant: "shop",
        budget: [{ dimension: { amount: "try" }, capacity: 50_000, window: "transaction" }],
        validUntil: 1_800_000_000_000,
        agent: true,
      },
    ]);
    expect(budgetMoney(merchants[0]?.budget[0])).toEqual({ currency: "TRY", minor: 50_000 });
    expect(budgetMoney({ dimension: "count", capacity: 3 })).toBeUndefined();
  });
});

describe("save my card", () => {
  const authority = {
    authority: {
      actions: { exact: [{ namespace: "pay", name: "initiate", major: 1, schema: "cw" }] },
      resource: { namespace: "access.party", prefix: ["c", "instrument"] },
      params: { amount: { range: { min: 0, max: 50_000, unit: "try" } } },
      recipient: { party: "shop" },
      purpose: [{ code: "orders" }],
    },
    constraints: {
      validity: { from: 0, until: 1_798_675_200_000 },
      budget: [{ dimension: { amount: "try" }, capacity: 200_000, window: "total" }],
    },
    delegation: {},
    requirements: [],
  };
  // §8.17.5.11, §7.9.9.3, OP-156 m.24 (b)
  it("reads the merchant Grant's per-order limit, end and purpose, and nothing else", () => {
    expect(saveCardOf(authority, "shop")).toEqual({
      perOrder: { currency: "TRY", minor: 50_000 },
      total: { currency: "TRY", minor: 200_000 },
      until: 1_798_675_200_000,
      purposes: ["orders"],
    });
    expect(saveCardOf(authority, "other")).toBe("not_to_merchant");
    const work = structuredClone(authority);
    work.authority.actions.exact = [{ namespace: "work", name: "approve", major: 1, schema: "cw" }];
    expect(saveCardOf(work, "shop")).toBe("not_payment");
    expect(saveCardOf({ ...authority, delegation: { depth: 1 } }, "shop")).toBe("passes_on");
    const open = structuredClone(authority);
    open.authority.params = {} as typeof open.authority.params;
    expect(saveCardOf(open, "shop")).toBe("no_per_order_limit");
    const forever = structuredClone(authority);
    forever.constraints.validity.until = Number.MAX_VALUE;
    expect(saveCardOf(forever, "shop")).toBe("no_end");
  });
});
