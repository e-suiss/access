// OP-153 m.3 (s), TN-108: the hosted pages' texts are Access's Fluent catalogs, resolved by the
// five-step chain; `ui_locales` wins over the browser's languages; `ar-XB` is the right-to-left
// pseudo-locale that draws the English texts mirrored. The runtime is the shared one of
// web/components, taken from its source so the login bundle carries no React components of it.
import { Catalogs, keyOf, parseProtected } from "../../components/src/fluent.js";

import enLogin from "../../../locales/en/login.ftl?raw";
import trLogin from "../../../locales/tr/login.ftl?raw";
import protectedToml from "../../../conformance/catalog/protected-messages.toml?raw";
import type { Text } from "./contract.js";

const catalogs = new Catalogs({ en: [enLogin], tr: [trLogin] }, parseProtected(protectedToml));

const LANGUAGES = ["en", "tr"];

/** The right-to-left pseudo-locale (OP-153 m.3 (s)). */
export const PSEUDO_RTL = "ar-XB";

const RTL_LANGUAGES = new Set(["ar", "he", "fa", "ur"]);

function supported(tag: string): boolean {
  if (tag === PSEUDO_RTL) return true;
  return LANGUAGES.includes(tag.toLowerCase().split("-")[0] ?? "");
}

/** The viewer's locale: the first supported `ui_locales` entry, else the browser's. */
export function choose(search: string, languages: readonly string[]): string {
  const asked = new URLSearchParams(search).get("ui_locales");
  const wanted = [...(asked === null ? [] : asked.split(" ")), ...languages];
  return wanted.find((l) => /^[A-Za-z0-9-]{2,35}$/.test(l) && supported(l)) ?? "en";
}

export const locale = choose(window.location.search, navigator.languages);

/** Writing direction of `tag`. */
export function direction(tag: string): "rtl" | "ltr" {
  if (tag === PSEUDO_RTL) return "rtl";
  return RTL_LANGUAGES.has(tag.toLowerCase().split("-")[0] ?? "") ? "rtl" : "ltr";
}

/** Sets `lang` and `dir` on the document (TN-108). */
export function applyDocument(): void {
  document.documentElement.lang = locale;
  document.documentElement.dir = direction(locale);
}

/** The text of wire id `id` with `args` placed as plain text; the id itself when no catalog has it. */
export function t(id: string, args?: Readonly<Record<string, string>>): string {
  return catalogs.format(keyOf(id), locale, undefined, args) ?? id;
}

/** The text of `id` when a catalog has it. */
export function maybe(id: string, args?: Readonly<Record<string, string>>): string | undefined {
  return catalogs.format(keyOf(id), locale, undefined, args);
}

/** A server text: the catalog's for its id in the viewer's locale, else the server's own words. */
export function text(value: Text): string {
  return catalogs.format(keyOf(value.id), locale) ?? value.text;
}

/** A time as the viewer reads it. */
export function when(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(locale === PSEUDO_RTL ? "en" : locale, {
    dateStyle: "long",
    timeStyle: "short",
  });
}
