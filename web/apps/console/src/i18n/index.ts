import { en, type Key } from "./en.js";

export type { Key };

// OP-159 m.46 (e): only the viewer's own catalog is loaded; English is the fallback
const lang = navigator.language.slice(0, 2).toLowerCase();

const strings: Readonly<Record<Key, string>> = lang === "tr" ? (await import("./tr.js")).tr : en;

export const locale: string = lang === "tr" ? "tr" : "en";

/** The string for `key`, with `{name}` placeholders filled as plain text (TN-131). */
export function t(key: Key, values: Readonly<Record<string, string>> = {}): string {
  return strings[key].replace(/\{(\w+)\}/g, (whole, name: string) => values[name] ?? whole);
}
