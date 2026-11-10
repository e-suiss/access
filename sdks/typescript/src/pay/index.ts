// OP-156 m.3 (u), (v), §8.11, §8.17.5.11, §7.9.9, XI-14, E21, F9, R8, X8, INV-20
// What a payment surface reads and checks before it shows anything: Pay's own `pay-limit`
// statement (`product-seam.cddl`), the one-time payment an intent the Kernel decoded asks for, and
// the merchants that hold a Grant to charge the viewer. Nothing here signs, decides or adds one
// owner's figure to another's.

/** An amount in a currency's minor unit. */
export interface Money {
  /** ISO 4217, upper case. */
  readonly currency: string;
  readonly minor: number;
}

/** Pay's financial limit or hold (XI-14): a fact of Pay's, apart from authority. */
export interface PayLimit {
  readonly limit: Money;
  readonly period: "transaction" | "day" | "month";
  /** What Pay holds against it. */
  readonly held?: Money;
}

function currencyOk(c: unknown): c is string {
  return typeof c === "string" && /^[A-Z]{3}$/.test(c);
}

function minorOk(n: unknown): n is number {
  return typeof n === "number" && Number.isSafeInteger(n) && n >= 0;
}

/** Pay's `pay-limit` body, or `undefined` when it is not one. */
export function payLimitOf(body: unknown): PayLimit | undefined {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return undefined;
  const b = body as Readonly<Record<string, unknown>>;
  const allowed = ["currency", "limit_minor", "period", "held_minor"];
  if (Object.keys(b).some((k) => !allowed.includes(k))) return undefined;
  const { currency, limit_minor: limit, period, held_minor: held } = b;
  if (!currencyOk(currency) || !minorOk(limit)) return undefined;
  if (period !== "transaction" && period !== "day" && period !== "month") return undefined;
  if (held !== undefined && !minorOk(held)) return undefined;
  return {
    limit: { currency, minor: limit },
    period,
    ...(held === undefined ? {} : { held: { currency, minor: held } }),
  };
}

/** The intent as the Kernel's `describeIntent` decodes it. */
export interface DescribedIntent {
  readonly digest: string;
  readonly action: { readonly namespace: string; readonly name: string; readonly major: string };
  readonly params: Readonly<Record<string, string>>;
  readonly opaque?: readonly string[];
  readonly recipient?: string | null;
  readonly purpose?: {
    readonly code?: string;
    readonly work?: string;
    readonly aim?: string;
  } | null;
  readonly validity: { readonly from: string; readonly until: string };
}

/** "Pay 300 TRY to M, once": exactly what the decoded bytes say. */
export interface OneTime {
  readonly amount: Money;
  /** The recipient Party, base64url. */
  readonly recipient: string;
  readonly purpose: string;
  readonly until: number;
}

/** Why an intent is not a one-time payment. */
export type NotOneTime =
  "authority_change" | "no_amount" | "no_recipient" | "no_purpose" | "too_long";

/** The longest a one-time payment's intent may be valid for: a day (OP-153 m.3 (x)). */
export const ONCE_MAX_MS = 86_400_000;

function amountOf(text: string | undefined): Money | undefined {
  const m = /^(\d{1,15}) ([A-Za-z]{3})$/.exec(text ?? "");
  if (m === null) return undefined;
  const [, value = "", unit = ""] = m;
  return { currency: unit.toUpperCase(), minor: Number(value) };
}

/**
 * A one-time payment, or why it is not one (§8.17.5.11, R8, X8, INV-20): the customer's own
 * Exercise of a payment action with an exact amount, a recipient and a purpose, valid for at
 * most a day. An intent that would change authority (a core action, or one carrying a meta
 * payload) is never a one-time payment: approving it would leave the merchant a Grant.
 */
export function oneTimeOf(i: DescribedIntent): OneTime | NotOneTime {
  if (i.action.namespace === "access" || (i.opaque ?? []).includes("payload")) {
    return "authority_change";
  }
  const amount = amountOf(i.params["amount"]);
  if (amount === undefined) return "no_amount";
  const recipient = i.recipient ?? undefined;
  if (recipient === undefined || recipient === "") return "no_recipient";
  const purpose = i.purpose?.code;
  if (purpose === undefined || purpose === "") return "no_purpose";
  const from = Number(i.validity.from);
  const until = Number(i.validity.until);
  if (!Number.isSafeInteger(from) || !Number.isSafeInteger(until) || until - from > ONCE_MAX_MS) {
    return "too_long";
  }
  return { amount, recipient, purpose, until };
}

/** A holding a merchant holds over the viewer's payment authority (S2, §8.17.7.2). */
export interface MerchantHolding {
  readonly grant: string;
  readonly merchant: string;
  /** The authority limits as Access recorded them. */
  readonly budget: readonly unknown[];
  readonly validUntil?: number;
  /** The holder is an agent: shown as "AI agent · acting for M" (X30). */
  readonly agent: boolean;
}

function obj(v: unknown): Readonly<Record<string, unknown>> {
  return typeof v === "object" && v !== null && !Array.isArray(v)
    ? (v as Readonly<Record<string, unknown>>)
    : {};
}

/**
 * The merchants that can charge the viewer: holdings shared from the viewer to one Party over at
 * least one `pay` action (`pay.initiate` and the like, OP-156 m.3 (u)). What a merchant decides
 * inside its own business is not among them (E26).
 */
export function merchantsOf(inventory: readonly unknown[]): MerchantHolding[] {
  const out: MerchantHolding[] = [];
  for (const raw of inventory) {
    const v = obj(raw);
    const groups = Array.isArray(v["groups"]) ? (v["groups"] as unknown[]) : [];
    const merchant = obj(v["holder"])["party"];
    const grant = v["grant"];
    const pays = (Array.isArray(v["actions"]) ? (v["actions"] as unknown[]) : []).some(
      (a) => obj(a)["namespace"] === "pay",
    );
    if (
      v["type"] !== "holding" ||
      !groups.includes("shared_from_you") ||
      typeof merchant !== "string" ||
      typeof grant !== "string" ||
      !pays
    ) {
      continue;
    }
    const until = obj(v["validity"])["until"];
    out.push({
      grant,
      merchant,
      budget: Array.isArray(v["budget"]) ? (v["budget"] as unknown[]) : [],
      ...(typeof until === "number" ? { validUntil: until } : {}),
      agent: v["agent"] !== undefined && v["agent"] !== null,
    });
  }
  return out;
}

/** The money of an authority budget term `{dimension: {amount: unit}, capacity}`, if it is one. */
export function budgetMoney(term: unknown): Money | undefined {
  const t = obj(term);
  const unit = obj(t["dimension"])["amount"];
  const capacity = t["capacity"];
  if (typeof unit !== "string" || !/^[A-Za-z]{3}$/.test(unit) || !minorOk(capacity)) {
    return undefined;
  }
  return { currency: unit.toUpperCase(), minor: capacity };
}
