// OP-156 m.3 (v), §8.17.5.8, §8.13, CI-9, INV-24
import { describe, expect, it } from "vitest";

import { reportOf, stateAt } from "./index.js";

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
