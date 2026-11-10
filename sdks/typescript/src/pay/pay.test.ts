// OP-156 m.3 (u), (v), XI-14, §8.17.5.11, R8, X8, INV-20, E26
import { describe, expect, it } from "vitest";

import { budgetMoney, merchantsOf, oneTimeOf, payLimitOf, type DescribedIntent } from "./index.js";

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
