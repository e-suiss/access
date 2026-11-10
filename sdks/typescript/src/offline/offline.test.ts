// OP-156 m.3 (v), §8.17.5.8, §8.13, CI-9, INV-24
import { describe, expect, it } from "vitest";

import { reportFrom, reportOf, stateAt } from "./index.js";

describe("offline", () => {
  it("reads the slice counter and ends the window at its declared end", () => {
    const report = reportOf({
      since: 1_000,
      until: 5_000,
      voids_left: 3,
      amount_left: { currency: "TRY", minor: 200_000 },
    });
    expect(report).toEqual({
      since: 1_000,
      until: 5_000,
      voidsLeft: 3,
      amountLeft: { currency: "TRY", minor: 200_000 },
    });
    expect(stateAt(report, 4_999).kind).toBe("offline");
    expect(stateAt(report, 5_000).kind).toBe("ended");
    expect(stateAt(undefined, 4_000).kind).toBe("online");
  });

  it("never reads an unknown window as one", () => {
    expect(reportOf({ since: 5, until: 1 })).toBeUndefined();
    expect(reportOf({ since: 1 })).toBeUndefined();
    expect(reportOf({ since: 1, until: 2, voids_left: -1 })).toBeUndefined();
    expect(
      reportOf({ since: 1, until: 2, amount_left: { currency: "try", minor: 1 } }),
    ).toBeUndefined();
  });
});

describe("offline report from the PAP and profile", () => {
  // §8.17.5.8, Ek B 5161: the same derivation as the real-path POS test
  it("caps each slice by the profile and reads a spent slice as zero", () => {
    const slices = [
      { budgetTerm: "count-term", amount: 2, unit: "count" },
      { budgetTerm: "eur-term", amount: 10_000, unit: "eur" },
    ];
    const sliceMax = { count: 5, eur: 20_000 };
    expect(
      reportFrom({
        since: 1,
        horizon: 9,
        slices,
        unused: { "count-term": 1, "eur-term": 6_000 },
        sliceMax,
      }),
    ).toEqual({ since: 1, until: 9, voidsLeft: 1, amountLeft: { currency: "EUR", minor: 6_000 } });
    expect(
      reportFrom({ since: 1, horizon: 9, slices, unused: {}, sliceMax: { count: 5, eur: 1 } }),
    ).toEqual({ since: 1, until: 9, voidsLeft: 0, amountLeft: { currency: "EUR", minor: 0 } });
  });
});
