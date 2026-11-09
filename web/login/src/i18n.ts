// OP-153 m.3 (s), TN-108: the hosted pages' texts are Access's Fluent catalogs, resolved by the
// five-step chain; `ui_locales` wins over the browser's languages; `ar-XB` is the right-to-left
// pseudo-locale that draws the English texts mirrored. The runtime is the shared one of
// web/components, taken from its source so the login bundle carries no React components of it.
// The realm's own texts for unprotected keys (`idp.realm.locale_overrides`) are read once before
// the first render and come first in the chain; a protected key never takes one (X35, m.22 (k)).
import { Catalogs, keyOf, type Overrides, parseProtected } from "../../components/src/fluent.js";

import enLogin from "../../../locales/en/login.ftl?raw";
import trLogin from "../../../locales/tr/login.ftl?raw";
import protectedToml from "../../../conformance/catalog/protected-messages.toml?raw";
import type { Text } from "./contract.js";
import { getJson } from "./http.js";

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

/** The path of the realm's text overrides. */
export const messagesPath = "/v1/login/messages";

let realm: Overrides | undefined;

/** The realm's overrides from their JSON, `{locale: {key: text}}`: strings only, each checked. */
export function overridesOf(json: unknown): Overrides | undefined {
  if (typeof json !== "object" || json === null) return undefined;
  const out = new Map<string, Map<string, string>>();
  for (const [tag, texts] of Object.entries(json as Record<string, unknown>)) {
    if (typeof texts !== "object" || texts === null) continue;
    const kept = new Map<string, string>();
    for (const [k, v] of Object.entries(texts as Record<string, unknown>)) {
      if (typeof v === "string" && !catalogs.isProtected(k)) kept.set(k, v);
    }
    out.set(tag.toLowerCase(), kept);
  }
  try {
    catalogs.check(out);
  } catch {
    return undefined;
  }
  return out;
}

/** Reads the realm's overrides; without an answer the pages use Access's own texts. */
export async function loadOverrides(): Promise<void> {
  const a = await getJson<{ overrides?: unknown }>(messagesPath);
  realm = a.ok ? overridesOf(a.body.overrides) : undefined;
}

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
  return catalogs.format(keyOf(id), locale, realm, args) ?? id;
}

/** The text of `id` when a catalog has it. */
export function maybe(id: string, args?: Readonly<Record<string, string>>): string | undefined {
  return catalogs.format(keyOf(id), locale, realm, args);
}

/** A server text: the catalog's for its id in the viewer's locale, else the server's own words. */
export function text(value: Text): string {
  return catalogs.format(keyOf(value.id), locale, realm) ?? value.text;
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
