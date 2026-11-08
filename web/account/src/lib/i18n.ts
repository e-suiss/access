// OP-153 m.3 (s), m.9 (c): the account pages' texts are Access's Fluent catalogs, resolved by the
// five-step chain; a key no catalog has shows as itself, never as an invented text.
import { Catalogs, keyOf, parseProtected } from "@suiss/access-react";

import enAccount from "../../../../locales/en/account.ftl?raw";
import enHub from "../../../../locales/en/hub.ftl?raw";
import enLogin from "../../../../locales/en/login.ftl?raw";
import trAccount from "../../../../locales/tr/account.ftl?raw";
import trHub from "../../../../locales/tr/hub.ftl?raw";
import trLogin from "../../../../locales/tr/login.ftl?raw";
import protectedToml from "../../../../conformance/catalog/protected-messages.toml?raw";

const catalogs = new Catalogs(
  { en: [enLogin, enAccount, enHub], tr: [trLogin, trAccount, trHub] },
  parseProtected(protectedToml),
);

const LANGUAGES = ["en", "tr"];

/** The right-to-left pseudo-locale (OP-153 m.3 (s), TN-108). */
export const PSEUDO_RTL = "ar-XB";

function choose(): string {
  const asked = new URLSearchParams(location.search).get("ui_locales");
  for (const l of [...(asked === null ? [] : asked.split(" ")), ...navigator.languages]) {
    if (l === PSEUDO_RTL) return l;
    const language = l.toLowerCase().split("-")[0] ?? "";
    if (/^[A-Za-z0-9-]{2,35}$/.test(l) && LANGUAGES.includes(language)) return l;
  }
  return "en";
}

/** The viewer's locale. */
export const locale = choose();

// TN-108
document.documentElement.lang = locale;
document.documentElement.dir = locale === PSEUDO_RTL ? "rtl" : "ltr";

/** The text of wire id `id` (`hub.title`), with `args` placed as plain text. */
export function t(id: string, args?: Readonly<Record<string, string>>): string {
  return catalogs.format(keyOf(id), locale, undefined, args) ?? id;
}

/** The flat catalogue the shared components take. */
export const catalogue = catalogs.catalogue(locale);

/** A time as the viewer reads it. */
export function at(ms: number): string {
  return new Date(ms).toLocaleString(locale);
}
