// OP-153 m.3 (s), m.9 (c), TN-105, TN-108, X35, XI-25
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { Catalogs, FluentError, idOf, keyOf, parse, parseProtected, tag } from "./fluent.js";

const root = join(import.meta.dirname, "..", "..", "..");

function sources(): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const locale of readdirSync(join(root, "locales"))) {
    out[locale] = readdirSync(join(root, "locales", locale))
      .filter((f) => f.endsWith(".ftl"))
      .sort()
      .map((f) => readFileSync(join(root, "locales", locale, f), "utf8"));
  }
  return out;
}

function catalogs(): Catalogs {
  const protectedKeys = parseProtected(
    readFileSync(join(root, "conformance", "catalog", "protected-messages.toml"), "utf8"),
  );
  return new Catalogs(sources(), protectedKeys);
}

describe("fluent", () => {
  // TN-108
  it("reads Access's catalogs, every locale with the keys of en", () => {
    const c = catalogs();
    const en = c.catalog("en");
    const tr = c.catalog("tr");
    expect(en?.size).toBeGreaterThan(100);
    expect([...(tr?.keys() ?? [])].sort()).toEqual([...(en?.keys() ?? [])].sort());
    expect(c.format("outcome-submitted", "en")).toBe("Submitted");
  });

  // OP-153 m.3 (s)
  it("runs realm locale, realm language, Access locale, Access language, en", () => {
    const c = catalogs();
    const k = "why-past";
    const realm = new Map([
      ["tr-tr", new Map([[k, "Gönderildi (TR)"]])],
      ["tr", new Map([[k, "Gönderildi (dil)"]])],
    ]);
    c.check(realm);
    expect(c.pattern(k, "tr-TR", realm)).toBe("Gönderildi (TR)");
    expect(c.pattern(k, "tr-CY", realm)).toBe("Gönderildi (dil)");
    expect(c.pattern(k, "tr-CY")).toBe(c.catalog("tr")?.get(k));
    expect(c.pattern(k, "de-DE")).toBe("As decided at that time");
    expect(c.pattern(k, "not a tag")).toBe("As decided at that time");
    expect(c.pattern("no-such-key", "en")).toBeUndefined();
  });

  // X35, XI-25
  it("never lets a realm replace a protected key", () => {
    const c = catalogs();
    const k = "login-failed";
    expect(c.isProtected(k)).toBe(true);
    const realm = new Map([["en", new Map([[k, "Another text."]])]]);
    expect(() => {
      c.check(realm);
    }).toThrow(FluentError);
    expect(c.pattern(k, "en", realm)).toBe(c.catalog("en")?.get(k));
    expect(() => {
      c.check(new Map([["en", new Map([["made-up", "x"]])]]));
    }).toThrow(/unknown/);
  });

  // TN-105
  it("refuses Fluent logic", () => {
    expect(() => parse("a = { $n ->\n  [one] x\n *[other] y\n}")).toThrow(FluentError);
    expect(() => parse("-term = x")).toThrow(FluentError);
    expect(() => parse("a = x\n    .attr = y")).toThrow(FluentError);
    expect(() => parse("a = x\na = y")).toThrow(/duplicate/);
    const m = parse("# c\na = one\n  two\n\nb = { $n } left");
    expect(m.get("a")).toBe("one two");
    expect(m.get("b")).toBe("{ $n } left");
  });

  // TN-131
  it("places arguments as plain text", () => {
    const c = new Catalogs({ en: ["greet = Hi { $name }, { $name }"] }, []);
    expect(c.format("greet", "en", undefined, { name: "<b>x</b>" })).toBe("Hi <b>x</b>, <b>x</b>");
  });

  it("maps wire ids and Fluent keys both ways", () => {
    expect(keyOf("ladder.requested")).toBe("ladder-requested");
    expect(idOf("ladder-requested")).toBe("ladder.requested");
    expect(tag("tr-TR")).toEqual(["tr-tr", "tr"]);
    expect(() => tag("-x")).toThrow(FluentError);
    const c = catalogs();
    expect(c.catalogue("tr")["outcome.submitted"]).toBe(c.catalog("tr")?.get("outcome-submitted"));
  });
});
