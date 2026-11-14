// OP-153 m.3 (s), m.9 (c), TN-105, TN-108, X35, XI-25: Access's message catalogs in the
// browser, by the same rules as the server (identity_ui::domain::locale). The Fluent subset
// Access writes: comments, `key = text` messages, indented continuation lines and `{ $name }`
// placeables. Selectors, terms and attributes are refused, so a catalog carries no logic. No
// dependency: this reads only the subset.

/** The language every chain ends in. */
export const DEFAULT_LANGUAGE = "en";

/** One parsed Fluent file: key to pattern. */
export type Messages = ReadonlyMap<string, string>;

/** A realm's overrides of unprotected keys, by lower-case locale (`idp.realm.locale_overrides`). */
export type Overrides = ReadonlyMap<string, Messages>;

/** Why a catalog or an override is refused. */
export class FluentError extends Error {
  constructor(
    readonly kind: "syntax" | "duplicate" | "protected" | "unknown" | "locale",
    readonly detail: string,
  ) {
    super(`${kind}: ${detail}`);
  }
}

function keyOk(key: string): boolean {
  return /^[a-z][a-z0-9_-]*$/.test(key);
}

/** Parses a file of the supported Fluent subset. */
export function parse(source: string): Map<string, string> {
  const out = new Map<string, string>();
  let current: string | undefined;
  source.split(/\r?\n/).forEach((line, n) => {
    const number = String(n + 1);
    if (line.trim() === "" || line.startsWith("#")) {
      current = undefined;
      return;
    }
    if (line.startsWith(" ")) {
      if (current === undefined) throw new FluentError("syntax", number);
      const text = line.trim();
      if (/^[[*.}]/.test(text)) throw new FluentError("syntax", number);
      const prior = out.get(current) ?? "";
      out.set(current, prior === "" ? text : `${prior} ${text}`);
      return;
    }
    const at = line.indexOf("=");
    if (at < 0) throw new FluentError("syntax", number);
    const key = line.slice(0, at).trim();
    const value = line.slice(at + 1);
    if (!keyOk(key) || value.includes("->")) throw new FluentError("syntax", number);
    if (out.has(key)) throw new FluentError("duplicate", key);
    out.set(key, value.trim());
    current = key;
  });
  return out;
}

/** The keys of `protected-messages.toml`: every quoted entry of its `keys` list. */
export function parseProtected(toml: string): Set<string> {
  const out = new Set<string>();
  for (const raw of toml.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line.startsWith('"')) continue;
    const end = line.indexOf('"', 1);
    if (end > 1) out.add(line.slice(1, end));
  }
  return out;
}

/** A BCP 47 tag and its language, lower case: `tr-TR` is `["tr-tr", "tr"]`. */
export function tag(locale: string): readonly [string, string] {
  if (
    locale.length < 2 ||
    locale.length > 35 ||
    locale.startsWith("-") ||
    !/^[A-Za-z0-9-]+$/.test(locale)
  ) {
    throw new FluentError("locale", locale);
  }
  const full = locale.toLowerCase();
  return [full, full.split("-")[0] ?? DEFAULT_LANGUAGE];
}

function safeTag(locale: string): readonly [string, string] {
  try {
    return tag(locale);
  } catch {
    return [DEFAULT_LANGUAGE, DEFAULT_LANGUAGE];
  }
}

/** The Fluent key of a wire id: `.` becomes `-`. */
export function keyOf(id: string): string {
  return id.replaceAll(".", "-");
}

/** The wire id of a Fluent key: `-` becomes `.`. */
export function idOf(key: string): string {
  return key.replaceAll("-", ".");
}

/** Access's catalogs and its protected keys, with the five-step fallback chain. */
export class Catalogs {
  private readonly access: Map<string, Map<string, string>>;
  private readonly protectedKeys: ReadonlySet<string>;

  /**
   * `sources` is each locale's Fluent files (`login`, `account`, `hub`, `mail`); `protectedKeys`
   * the keys no realm may replace. A key defined twice in one locale is refused.
   */
  constructor(
    sources: Readonly<Record<string, readonly string[]>>,
    protectedKeys: Iterable<string>,
  ) {
    this.access = new Map();
    for (const [locale, files] of Object.entries(sources)) {
      const into = new Map<string, string>();
      for (const file of files) {
        for (const [k, v] of parse(file)) {
          if (into.has(k)) throw new FluentError("duplicate", k);
          into.set(k, v);
        }
      }
      this.access.set(locale.toLowerCase(), into);
    }
    this.protectedKeys = new Set(protectedKeys);
  }

  /** Access's catalog of `locale`. */
  catalog(locale: string): Messages | undefined {
    return this.access.get(locale);
  }

  /** Whether a realm may not override `key` (X35). */
  isProtected(key: string): boolean {
    return this.protectedKeys.has(key);
  }

  /** Checks a realm's overrides: known keys only, never a protected one (X35). */
  check(overrides: Overrides): void {
    const en = this.access.get(DEFAULT_LANGUAGE);
    for (const [locale, messages] of overrides) {
      tag(locale);
      for (const k of messages.keys()) {
        if (this.isProtected(k)) throw new FluentError("protected", k);
        if (en?.has(k) !== true) throw new FluentError("unknown", k);
      }
    }
  }

  /**
   * The pattern of `key` for `locale`: realm (locale) → realm (language) → Access (locale) →
   * Access (language) → `en`. A protected key skips the realm's layers; a malformed tag reads
   * as `en`.
   */
  pattern(key: string, locale: string, realm?: Overrides): string | undefined {
    const [full, language] = safeTag(locale);
    const r = this.isProtected(key) ? undefined : realm;
    const layers = [
      r?.get(full),
      r?.get(language),
      this.access.get(full),
      this.access.get(language),
      this.access.get(DEFAULT_LANGUAGE),
    ];
    for (const m of layers) {
      const v = m?.get(key);
      if (v !== undefined) return v;
    }
    return undefined;
  }

  /** The text of `key` for `locale` with `args` placed as plain text (TN-131). */
  format(
    key: string,
    locale: string,
    realm?: Overrides,
    args: Readonly<Record<string, string>> = {},
  ): string | undefined {
    let text = this.pattern(key, locale, realm);
    if (text === undefined) return undefined;
    for (const [name, value] of Object.entries(args)) {
      text = text.replaceAll(`{ $${name} }`, value);
    }
    return text;
  }

  /**
   * Every key of `en` resolved for `locale`, by wire id (`.`), for a component's `catalogue`
   * prop.
   */
  catalogue(locale: string, realm?: Overrides): Readonly<Record<string, string>> {
    const out: Record<string, string> = {};
    for (const k of this.access.get(DEFAULT_LANGUAGE)?.keys() ?? []) {
      const v = this.pattern(k, locale, realm);
      if (v !== undefined) out[idOf(k)] = v;
    }
    return out;
  }
}
