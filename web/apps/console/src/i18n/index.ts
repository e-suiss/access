import { en, type Key } from "./en.js";
import { tr } from "./tr.js";

export type { Key };

const catalogs: Record<string, Record<Key, string>> = { en, tr };

function pick(): Record<Key, string> {
  const lang = navigator.language.slice(0, 2).toLowerCase();
  return catalogs[lang] ?? en;
}

const strings = pick();

export const locale: string = strings === tr ? "tr" : "en";

/** The string for `key`, with `{name}` placeholders filled as plain text (TN-131). */
export function t(key: Key, values: Readonly<Record<string, string>> = {}): string {
  return strings[key].replace(/\{(\w+)\}/g, (whole, name: string) => values[name] ?? whole);
}
