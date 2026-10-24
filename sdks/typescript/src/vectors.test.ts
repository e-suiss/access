// OP-116 m.6
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

import { beforeAll, describe, expect, it } from "vitest";

import { type Kernel, loadKernel } from "./index.js";

interface Case {
  readonly id: string;
  readonly [field: string]: unknown;
}

interface Vectors {
  readonly fuel?: number;
  readonly typ?: string;
  readonly content_type?: string;
  readonly allowed?: readonly number[];
  readonly keys?: Readonly<Record<string, string>>;
  readonly cases: readonly Case[];
}

interface MerkleVectors {
  readonly leaves: readonly string[];
  readonly roots: readonly { readonly size: number; readonly root: string }[];
  readonly inclusion: readonly {
    readonly index: number;
    readonly size: number;
    readonly path: readonly string[];
  }[];
  readonly consistency: readonly {
    readonly first: number;
    readonly second: number;
    readonly path: readonly string[];
  }[];
}

async function vectors<T = Vectors>(name: string): Promise<T> {
  const url = new URL(`../../../conformance/vectors/core/1/${name}`, import.meta.url);
  return JSON.parse(await readFile(url, "utf8")) as T;
}

function field(c: Case, name: string): string {
  const v = c[name];
  if (typeof v !== "string") throw new TypeError(`${c.id}: ${name} is not a string`);
  return v;
}

function hex(s: string): Uint8Array {
  return Uint8Array.from(Buffer.from(s, "hex"));
}

function toHex(b: Uint8Array): string {
  return Buffer.from(b).toString("hex");
}

function b64url(s: string): Uint8Array {
  return Uint8Array.from(Buffer.from(s, "base64url"));
}

function concat(parts: readonly Uint8Array[]): Uint8Array {
  return Uint8Array.from(parts.flatMap((p) => [...p]));
}

function head(major: number, n: number): Uint8Array {
  const m = major << 5;
  if (n < 24) return Uint8Array.of(m | n);
  if (n < 0x100) return Uint8Array.of(m | 24, n);
  if (n < 0x10000) return Uint8Array.of(m | 25, n >> 8, n & 0xff);
  throw new RangeError("length out of range for this test encoder");
}

const bstr = (b: Uint8Array): Uint8Array => concat([head(2, b.length), b]);
const tstr = (s: string): Uint8Array => {
  const b = new TextEncoder().encode(s);
  return concat([head(3, b.length), b]);
};
const negint = (n: number): Uint8Array => head(1, -1 - n);

function compare(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d !== 0) return d;
  }
  return a.length - b.length;
}

function cborMap(entries: readonly (readonly [Uint8Array, Uint8Array])[]): Uint8Array {
  const sorted = [...entries].sort((x, y) => compare(x[0], y[0]));
  return concat([head(5, sorted.length), ...sorted.flat()]);
}

function cborSet(items: readonly Uint8Array[]): Uint8Array {
  return concat([head(4, items.length), ...[...items].sort(compare)]);
}

function keySet(
  keys: readonly (readonly [Uint8Array, Uint8Array])[],
  allowed: readonly number[],
): Uint8Array {
  return cborMap([
    [tstr("keys"), cborMap(keys.map(([kid, key]) => [bstr(kid), key] as const))],
    [tstr("allowed"), cborSet(allowed.map(negint))],
  ]);
}

type Outcome<T> = { readonly ok: T } | { readonly error: string };

function outcome<T>(f: () => T): Outcome<T> {
  try {
    return { ok: f() };
  } catch (e: unknown) {
    if (e instanceof Error) return { error: e.message };
    throw e;
  }
}

let k: Kernel;

beforeAll(async () => {
  k = await loadKernel(
    await readFile(new URL("../wasm/access_kernel_wasm_bg.wasm", import.meta.url)),
  );
});

describe("Kernel vectors through the Wasm binding", () => {
  it("decision.json", async () => {
    const v = await vectors("decision.json");
    const fuel = BigInt(v.fuel ?? 0);
    for (const c of v.cases) {
      const got = outcome(() => toHex(k.evaluate(hex(field(c, "input")), fuel)));
      const want =
        "decision" in c ? { ok: field(c, "decision") } : { error: field(c, "rejection") };
      expect(got, c.id).toEqual(want);
    }
    expect(v.cases).toHaveLength(20);
  });

  it("cve-regressions.json", async () => {
    const v = await vectors("cve-regressions.json");
    const fuel = BigInt(v.fuel ?? 0);
    for (const c of v.cases) {
      if (c["operation"] === "combinator.evaluate") {
        expect(toHex(k.evaluate(hex(field(c, "input")), fuel)), c.id).toBe(field(c, "decision"));
      } else {
        const within = k.childWithinParent(
          hex(field(c, "child")),
          hex(field(c, "parent")),
          hex(field(c, "holder")),
          Uint8Array.of(0xa0),
        );
        expect(within, c.id).toBe(c["within"]);
      }
    }
    expect(v.cases).toHaveLength(19);
  });

  it("cose.json", async () => {
    const v = await vectors("cose.json");
    const keys = keySet(
      Object.entries(v.keys ?? {}).map(([kid, key]) => [hex(kid), hex(key)] as const),
      v.allowed ?? [],
    );
    for (const c of v.cases) {
      const got = outcome(() =>
        toHex(k.verifyCoseSign1(hex(field(c, "sign1")), keys, v.content_type ?? "")),
      );
      const want =
        "error" in c
          ? { error: field(c, "error") }
          : {
              ok: toHex(
                cborMap([
                  [tstr("kid"), bstr(hex(field(c, "kid")))],
                  [tstr("payload"), bstr(hex(field(c, "payload")))],
                ]),
              ),
            };
      expect(got, c.id).toEqual(want);
    }
    expect(v.cases).toHaveLength(15);
  });

  it("key-scope.json", async () => {
    const v = await vectors("key-scope.json");
    for (const c of v.cases) {
      const got = outcome(() =>
        toHex(
          k.operationalKey(
            hex(field(c, "metadata")),
            hex(field(c, "domain")),
            hex(field(c, "excerpt")),
            field(c, "usage"),
            BigInt(c["iat"] as number),
          ),
        ),
      );
      const want = "error" in c ? { error: field(c, "error") } : { ok: field(c, "key") };
      expect(got, c.id).toEqual(want);
    }
    expect(v.cases).toHaveLength(22);
  });

  it("jose-attack-classes.json", async () => {
    const v = await vectors("jose-attack-classes.json");
    const keys = keySet(
      Object.entries(v.keys ?? {}).map(([kid, key]) => {
        const raw = b64url(key);
        return [
          b64url(kid),
          cborMap([[tstr(raw.length === 32 ? "ed25519" : "p256"), bstr(raw)]]),
        ] as const;
      }),
      [-19, -7],
    );
    for (const c of v.cases) {
      const got = outcome(() =>
        k.verifyJwsCompact(
          field(c, "token"),
          keys,
          v.typ ?? "",
          "https://access.example",
          "pep:shop",
          1_500_000n,
          60_000n,
        ),
      );
      expect("ok" in got ? "accept" : `reject: ${got.error}`, c.id).toBe(field(c, "expect"));
    }
    expect(v.cases).toHaveLength(27);
  });

  it("merkle.json", async () => {
    const v = await vectors<MerkleVectors>("merkle.json");
    const roots = new Map(v.roots.map((r) => [r.size, hex(r.root)]));
    const root = (n: number): Uint8Array => roots.get(n) ?? new Uint8Array();
    const path = (p: readonly string[]): Uint8Array => concat(p.map(hex));
    for (const c of v.inclusion) {
      const leaf = createHash("sha256")
        .update(concat([Uint8Array.of(0), hex(v.leaves[c.index] ?? "")]))
        .digest();
      const ok = k.verifyInclusion(
        BigInt(c.index),
        BigInt(c.size),
        leaf,
        path(c.path),
        root(c.size),
      );
      expect(ok, `${c.index.toString()}/${c.size.toString()}`).toBe(true);
    }
    for (const c of v.consistency) {
      const ok = k.verifyConsistency(
        BigInt(c.first),
        BigInt(c.second),
        root(c.first),
        root(c.second),
        path(c.path),
      );
      expect(ok, `${c.first.toString()}/${c.second.toString()}`).toBe(true);
    }
    expect([v.inclusion.length, v.consistency.length]).toEqual([36, 36]);
    expect(
      outcome(() => k.verifyInclusion(0n, 1n, new Uint8Array(31), new Uint8Array(), root(1))),
    ).toEqual({
      error: "input",
    });
  });

  it("rejects fuel above the ceiling and malformed arguments", async () => {
    const v = await vectors("decision.json");
    const input = hex(field(v.cases[0] ?? { id: "none" }, "input"));
    expect("ok" in outcome(() => k.evaluate(input, 1_000_000n))).toBe(true);
    expect(outcome(() => k.evaluate(input, 1_000_001n))).toEqual({ error: "input" });
    expect(outcome(() => k.evaluate(input, 0n))).toEqual({ error: "fuel" });
    const empty = Uint8Array.of(0xa0);
    expect(outcome(() => k.intentDigest(empty))).toEqual({ error: "input" });
    expect(outcome(() => k.verifyMetadata(empty, empty))).toEqual({ error: "input" });
    expect(
      outcome(() => {
        k.checkValidity(empty, 0n, "pep:shop", [], undefined, true);
      }),
    ).toEqual({
      error: "input",
    });
    expect(
      outcome(() =>
        k.verifySdJwt(
          "x",
          keySet(
            [
              [
                new Uint8Array(32).fill(1),
                cborMap([
                  [tstr("ed25519"), bstr(b64url("6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw"))],
                ]),
              ],
            ],
            [-19],
          ),
          "t",
          "a",
          "n",
          0n,
          0n,
        ),
      ),
    ).toEqual({ error: "not an SD-JWT presentation" });
  });
});
