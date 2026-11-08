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

function choose(): string {
  for (const l of navigator.languages) {
    const language = l.toLowerCase().split("-")[0] ?? "";
    if (LANGUAGES.includes(language)) return l;
  }
  return "en";
}

/** The viewer's locale. */
export const locale = choose();

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
