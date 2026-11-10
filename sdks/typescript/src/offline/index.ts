// OP-156 m.3 (u), (v), §8.17.5.8, §8.13, CI-9, INV-24: a till's offline window as its Verifier
// Profile and offline slice declare it. The window is a promise of the domain's issuance, kept
// only if the till follows its declared profile (UNDER DECLARED CAPABILITY); after it ends the
// till must go online, and nothing reads as "allowed offline".

import type { Money } from "../pay/index.js";

/** What the till reports: when it went offline, and its offline slice. */
export interface OfflineReport {
  /** When it lost Access, Unix ms. */
  readonly since: number;
  /** The end of the slice's validity, Unix ms. */
  readonly until: number;
  /** Voids left in the slice. */
  readonly voidsLeft?: number;
  /** Money left in the slice. */
  readonly amountLeft?: Money;
}

/** Where the till stands. */
export type OfflineState =
  | { readonly kind: "online" }
  | { readonly kind: "offline"; readonly report: OfflineReport }
  | { readonly kind: "ended"; readonly report: OfflineReport };

function count(n: unknown): n is number {
  return typeof n === "number" && Number.isSafeInteger(n) && n >= 0;
}

/**
 * The till's report from its slice counter `{since, until, voids_left?, amount_left?: {currency,
 * minor}}`, or `undefined` when it is not one (an unknown window is never shown as one).
 */
export function reportOf(v: unknown): OfflineReport | undefined {
  if (typeof v !== "object" || v === null) return undefined;
  const r = v as Readonly<Record<string, unknown>>;
  const { since, until, voids_left: voids, amount_left: amount } = r;
  if (!count(since) || !count(until) || until < since) return undefined;
  if (voids !== undefined && !count(voids)) return undefined;
  let left: Money | undefined;
  if (amount !== undefined) {
    const a = amount as Readonly<Record<string, unknown>>;
    if (typeof a["currency"] !== "string" || !/^[A-Z]{3}$/.test(a["currency"])) return undefined;
    if (!count(a["minor"])) return undefined;
    left = { currency: a["currency"], minor: a["minor"] };
  }
  return {
    since,
    until,
    ...(voids === undefined ? {} : { voidsLeft: voids }),
    ...(left === undefined ? {} : { amountLeft: left }),
  };
}

/** Where a till with `report` (none when it is online) stands at `now`. */
export function stateAt(report: OfflineReport | undefined, now: number): OfflineState {
  if (report === undefined) return { kind: "online" };
  return now < report.until ? { kind: "offline", report } : { kind: "ended", report };
}
