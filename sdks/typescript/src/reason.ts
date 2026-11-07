// §9.6, P15

/** The closed set of blocker classes; there is no unknown class. */
export const CLASSES = [
  "no-covering-authority",
  "outside-instance-limits",
  "restricted",
  "budget-exhausted",
  "ended",
  "capacity-mismatch",
  "source-not-accepted",
  "schema-not-accepted",
  "nonce-closed",
  "foreign-status-unavailable",
] as const;

export type ReasonClass = (typeof CLASSES)[number];

/** The subcodes this SDK knows; any other is read as its parent class (P15). */
const SUBCODES: Readonly<Record<string, ReasonClass>> = {
  "ended/expired": "ended",
  "ended/revoked": "ended",
  "ended/lapsed": "ended",
  "nonce-closed/pre-recovery": "nonce-closed",
  "budget-exhausted/release-exceeds-draw": "budget-exhausted",
};

export interface Reason {
  readonly class: ReasonClass;
  /** The subcode when this SDK knows it; `undefined` when none was sent or it is unknown. */
  readonly subcode?: string;
}

function isClass(text: string): text is ReasonClass {
  return (CLASSES as readonly string[]).includes(text);
}

/** One reason; an unknown class throws `unknown-class`. */
export function reason(classText: string, subcode?: string): Reason {
  if (!isClass(classText)) throw new Error("unknown-class");
  if (subcode === undefined) return { class: classText };
  const known =
    SUBCODES[subcode] === classText ||
    (classText === "restricted" && /^restricted\/policy:.+$/.test(subcode));
  return known ? { class: classText, subcode } : { class: classText };
}

/** The reasons of a decision body (`context.blockers`); a malformed body throws `malformed`. */
export function reasons(body: unknown): Reason[] {
  if (typeof body !== "object" || body === null) throw new Error("malformed");
  const context = (body as { context?: unknown }).context;
  if (context === undefined) return [];
  if (typeof context !== "object" || context === null) throw new Error("malformed");
  const blockers = (context as { blockers?: unknown }).blockers;
  if (blockers === undefined) return [];
  if (!Array.isArray(blockers)) throw new Error("malformed");
  return blockers.map((b: unknown) => {
    if (typeof b !== "object" || b === null) throw new Error("malformed");
    const { class: c, subcode } = b as { class?: unknown; subcode?: unknown };
    if (typeof c !== "string") throw new Error("malformed");
    if (subcode !== undefined && typeof subcode !== "string") throw new Error("malformed");
    return reason(c, subcode);
  });
}
