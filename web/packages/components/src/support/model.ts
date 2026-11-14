// OP-157 m.3 (f), §8.16, TN-137, X37, XI-7, XI-17
/** Support access as people read it: the person's "Give access" sheet, the operator's banner and
 * the Activity line of a support Grant. It decides nothing and signs nothing; the person's own
 * device signs the exact `grant.issue` the request drafted. There is no impersonation. */
import { mayOpen, type Opener } from "../delegation/model.js";

export { mayOpen, type Opener };

type Catalogue = Readonly<Record<string, string>> | undefined;

/** A support request as the person reads it on their own page. */
export interface Request {
  /** The support organization, attacker-controlled text. */
  readonly organization: string;
  /** The case as the case system shows it. */
  readonly case: string;
  /** What it allows ("view your account settings"). */
  readonly what: string;
  readonly minutes: number;
  /** Whether it can only read (TN-137 (4)). */
  readonly readOnly: boolean;
}

/** What the operator sees while acting with support access (X37). */
export interface Banner {
  /** The person, as the operator knows them. */
  readonly person: string;
  readonly case: string;
  readonly readOnly: boolean;
  /** When it ends, as the operator reads it. */
  readonly ends: string;
}

/** One Activity row of a support Grant, attributed to the operator (§8.16, XI-17). */
export interface Attributed {
  readonly operator: string;
  readonly organization: string;
}

/** `key`'s text from `catalogue`, else English, with `args` placed as plain text (TN-131). */
export function say(
  en: Readonly<Record<string, string>>,
  key: string,
  catalogue: Catalogue,
  args: Readonly<Record<string, string>> = {},
): string {
  let out = catalogue?.[key] ?? en[key] ?? key;
  for (const [name, value] of Object.entries(args)) {
    out = out.replaceAll(`{ $${name} }`, value);
  }
  return out;
}

/** The sheet's title: "Give *Acme Support* access"; the verb is never "Approve" (§8.16). */
export function titleArgs(r: Request): Readonly<Record<string, string>> {
  return { organization: r.organization };
}

/** The sheet's one line of terms (OP-157 m.3 (f)). */
export function termsArgs(r: Request): Readonly<Record<string, string>> {
  return { what: r.what, case: r.case, minutes: String(r.minutes) };
}

/** The banner's arguments; the mode word comes from `readOnly`. */
export function bannerArgs(b: Banner, mode: string): Readonly<Record<string, string>> {
  return { person: b.person, case: b.case, mode, time: b.ends };
}

/** Whether a banner names everything it must: a support view never shows without it (X37). */
export function complete(b: Banner | undefined): b is Banner {
  return b !== undefined && b.person !== "" && b.case !== "" && b.ends !== "";
}
