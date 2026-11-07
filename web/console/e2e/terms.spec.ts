import { en } from "../src/i18n/en.js";
import { tr } from "../src/i18n/tr.js";

import { BASE, open } from "./data.js";
import { expect, test } from "./fixtures.js";

// X24, XI-13, §8.10, §8.11, OP-151 m.3 (r): words a user of Access never reads. The same list as
// xtask's `forbidden-ui-terms`, plus the honest-status words of §8.10 and §8.17.7.5.
const FORBIDDEN = [
  /\bmandates?\b/i,
  /\bpaus(e|ed|ing)\b/i,
  /\btransfer(s|red)?\b/i,
  /\bverified\b/i,
  /\btrusted\b/i,
  /\bforever\b/i,
  /\bundo\b/i,
  /\bfull access\b/i,
  /\bfail[ -]open\b/i,
  /\btest mode\b/i,
  /\blog ?in as\b/i,
  /\bimpersonat/i,
  /\bstopped\b/i,
  /\bbypass/i,
  /\ball permissions\b/i,
  /\bincludes future actions\b/i,
];

const FORBIDDEN_TR = [
  /devret/i,
  /duraklat/i,
  /sonsuza/i,
  /doğrulanmış/i,
  /güvenilir/i,
  /tam erişim/i,
  /test modu/i,
  /olarak giriş yap/i,
];

function offending(text: string, list: readonly RegExp[]): string[] {
  return list.filter((r) => r.test(text)).map(String);
}

// Ek B 3338, 3339, 3340: every built string, in both languages
test("no catalog string uses a forbidden term", () => {
  for (const [key, value] of Object.entries(en)) {
    expect(offending(value, FORBIDDEN), key).toEqual([]);
  }
  for (const [key, value] of Object.entries(tr)) {
    expect(offending(value, [...FORBIDDEN, ...FORBIDDEN_TR]), key).toEqual([]);
  }
});

// §12.4.3: both languages carry the same keys
test("the Turkish catalog has every English key", () => {
  expect(Object.keys(tr).sort()).toEqual(Object.keys(en).sort());
});

const SCREENS = [
  "admin/roles",
  "admin/people",
  "admin/sources",
  "admin/restrictions",
  "admin/protected",
  "admin/offboarding",
  "admin/domain",
  "admin/changes",
  "admin/sign-in",
  "developer/schemas",
  "developer/integrations",
  "developer/lab",
  "developer/logs",
  "audit/records",
  "audit/replay",
  "audit/revocation",
  "audit/unknown",
  "audit/export",
];

// Ek B 3338–3340, §8.17.7.5, §8.10: no rendered screen uses a forbidden term, offers "Undo" or
// a single control that stops everything
test("no rendered screen uses a forbidden term or a stop-all control", async ({
  page,
  context,
  bff,
}) => {
  await bff.signIn(context, BASE);
  await open(page, bff, "/console/admin/roles");
  for (const s of SCREENS) {
    await page.evaluate((p) => {
      history.pushState(null, "", p);
      dispatchEvent(new PopStateEvent("popstate"));
    }, `/console/${s}`);
    await expect(page.locator("[aria-busy=true]")).toHaveCount(0);
    const text = await page.locator("body").innerText();
    expect(offending(text, FORBIDDEN), s).toEqual([]);
    await expect(page.getByRole("button", { name: /\b(stop|undo)\b/i })).toHaveCount(0);
  }
});
