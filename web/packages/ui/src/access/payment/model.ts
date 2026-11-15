// OP-156 m.3 (u), (v), XI-14, E21, F9, §8.11, §8.17.5.11
/** The payment surfaces' model: amounts in minor units, Pay's limit as Pay stated it, and the
 * limit rows of a merchant's Grant. Each limit is its owner's own row; none is computed from
 * another (XI-14). */

/** An amount in a currency's minor unit. */
export interface Money {
  readonly currency: string;
  readonly minor: number;
}

/** Pay's financial limit or hold, as `@esuiss/access` `pay.payLimitOf` reads it. */
export interface PayLimit {
  readonly limit: Money;
  readonly period: "transaction" | "day" | "month";
  readonly held?: Money;
}

/** A text key with its values. */
export interface Line {
  readonly text: string;
  readonly args?: Readonly<Record<string, string>>;
}

/** The amount as the viewer reads it, in the currency's own minor-unit digits (ISO 4217). */
export function money(m: Money, locale: string): string {
  try {
    const f = new Intl.NumberFormat(locale, { style: "currency", currency: m.currency });
    const digits = f.resolvedOptions().maximumFractionDigits ?? 2;
    return f.format(m.minor / 10 ** digits);
  } catch {
    return `${String(m.minor)} ${m.currency}`;
  }
}

/** One limit row and its owner (XI-14). */
export interface LimitRow {
  readonly owner: "access" | "pay";
  readonly line: Line;
}

/** The authority limit line of a budget term as Access recorded it
 * (`{dimension: {amount: unit} | "count", capacity, window}`); `undefined` for any other. */
export function authorityLine(term: unknown, locale: string): Line | undefined {
  if (typeof term !== "object" || term === null) return undefined;
  const t = term as Readonly<Record<string, unknown>>;
  const d = t["dimension"];
  const capacity = t["capacity"];
  if (typeof capacity !== "number" || !Number.isSafeInteger(capacity) || capacity < 0) {
    return undefined;
  }
  if (d === "count") return { text: "limit.count", args: { capacity: String(capacity) } };
  const unit =
    typeof d === "object" && d !== null ? (d as Readonly<Record<string, unknown>>)["amount"] : null;
  if (typeof unit !== "string" || !/^[A-Za-z]{3}$/.test(unit)) return undefined;
  const limit = money({ currency: unit.toUpperCase(), minor: capacity }, locale);
  return { text: "limit.authority", args: { limit } };
}

/**
 * The limit rows of one Grant (XI-14): first Access's authority limits as Access recorded them,
 * then Pay's financial limits as Pay stated them. Nothing is added up, compared or carried from
 * one owner's figure to the other's; a Grant without Pay's statement has no financial row.
 */
export function limitRows(
  authority: readonly unknown[],
  financial: readonly PayLimit[],
  locale: string,
  period: (p: PayLimit["period"]) => string,
): LimitRow[] {
  const rows: LimitRow[] = [];
  for (const term of authority) {
    const line = authorityLine(term, locale);
    if (line !== undefined) rows.push({ owner: "access", line });
  }
  for (const f of financial) {
    const limit = `${money(f.limit, locale)} / ${period(f.period)}`;
    rows.push({ owner: "pay", line: { text: "limit.financial", args: { limit } } });
    if (f.held !== undefined) {
      const amount = money(f.held, locale);
      rows.push({ owner: "pay", line: { text: "limit.held", args: { amount } } });
    }
  }
  return rows;
}
