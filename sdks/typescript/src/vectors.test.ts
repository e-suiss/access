// OP-116 m.6
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { deflateSync } from "node:zlib";

import { beforeAll, describe, expect, it } from "vitest";

import { type Kernel, MAX_STATUS_LIST_BYTES, inflateStatusList, loadKernel } from "./index.js";

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

interface ClaimContext {
  readonly issuer: string;
  readonly audience: string;
  readonly now: number;
  readonly skew_ms: number;
}

interface SdJwtContext {
  readonly typ: string;
  readonly audience: string;
  readonly nonce: string;
  readonly now: number;
  readonly skew_ms: number;
}

function joseEntries(v: Vectors): (readonly [Uint8Array, Uint8Array])[] {
  return Object.entries(v.keys ?? {}).map(([kid, key]) => {
    const raw = b64url(key);
    return [
      b64url(kid),
      cborMap([[tstr(raw.length === 32 ? "ed25519" : "p256"), bstr(raw)]]),
    ] as const;
  });
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
    for (const c of v.cases) {
      const fuel = BigInt((c["fuel"] as number | undefined) ?? v.fuel ?? 0);
      const got = outcome(() => toHex(k.evaluate(hex(field(c, "input")), fuel)));
      const want =
        "decision" in c ? { ok: field(c, "decision") } : { error: field(c, "rejection") };
      expect(got, c.id).toEqual(want);
    }
    expect(v.cases).toHaveLength(175);
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
    expect(v.cases).toHaveLength(38);
  });

  it("adversarial.json", async () => {
    const v = await vectors("adversarial.json");
    const fuel = BigInt(v.fuel ?? 0);
    for (const c of v.cases) {
      if (c["operation"] === "combinator.evaluate") {
        const got = outcome(() => toHex(k.evaluate(hex(field(c, "input")), fuel)));
        const want =
          "decision" in c ? { ok: field(c, "decision") } : { error: field(c, "rejection") };
        expect(got, c.id).toEqual(want);
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
    expect(v.cases).toHaveLength(23);
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
    expect(v.cases).toHaveLength(17);
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
    expect(v.cases).toHaveLength(29);
  });

  it("jose-attack-classes.json", async () => {
    const v = await vectors("jose-attack-classes.json");
    const entries = Object.entries(v.keys ?? {}).map(([kid, key]) => {
      const raw = b64url(key);
      return [
        b64url(kid),
        cborMap([[tstr(raw.length === 32 ? "ed25519" : "p256"), bstr(raw)]]),
      ] as const;
    });
    for (const c of v.cases) {
      const allowed = (c["allowed"] as readonly number[] | undefined) ?? v.allowed ?? [];
      const got = outcome(() =>
        k.verifyJwsCompact(
          field(c, "token"),
          keySet(entries, allowed),
          v.typ ?? "",
          "https://access.example",
          "pep:shop",
          1_500_000n,
          60_000n,
        ),
      );
      expect("ok" in got ? "accept" : `reject: ${got.error}`, c.id).toBe(field(c, "expect"));
    }
    expect(v.cases).toHaveLength(38);
  });

  // OP-122 m.7
  it("jwt-claims.json", async () => {
    const v = await vectors("jwt-claims.json");
    const keys = keySet(joseEntries(v), v.allowed ?? []);
    const base = (v as unknown as { claims: ClaimContext }).claims;
    for (const c of v.cases) {
      const ctx = (c["claims"] as ClaimContext | undefined) ?? base;
      const got = outcome(() =>
        k.verifyJwsCompact(
          field(c, "token"),
          keys,
          v.typ ?? "",
          ctx.issuer,
          ctx.audience,
          BigInt(ctx.now),
          BigInt(ctx.skew_ms),
        ),
      );
      expect("ok" in got ? "accept" : `reject: ${got.error}`, c.id).toBe(field(c, "expect"));
    }
    expect(v.cases).toHaveLength(24);
  });

  // OP-122 m.7
  it("sd-jwt.json", async () => {
    const v = await vectors("sd-jwt.json");
    const keys = keySet(joseEntries(v), v.allowed ?? []);
    const ctx = (v as unknown as { context: SdJwtContext }).context;
    for (const c of v.cases) {
      const got = outcome(() =>
        k.verifySdJwt(
          field(c, "presentation"),
          keys,
          ctx.typ,
          ctx.audience,
          ctx.nonce,
          BigInt(ctx.now),
          BigInt(ctx.skew_ms),
        ),
      );
      const want = "claims" in c ? { ok: c["claims"] } : { error: field(c, "error") };
      expect("ok" in got ? { ok: JSON.parse(got.ok) as unknown } : got, c.id).toEqual(want);
    }
    expect(v.cases).toHaveLength(27);
  });

  // OP-118 m.4, OP-122 m.6
  it("validity.json", async () => {
    const url = new URL("../../../conformance/vectors/core/1/validity.json", import.meta.url);
    const text = (await readFile(url, "utf8")).replace(/: (\d{16,})/g, ': "$1"');
    const v = JSON.parse(text) as Vectors;
    const doc = v as unknown as {
      contract: string;
      audience: string;
      online: boolean;
      skew_ms: number;
    };
    const num = (c: Case, name: string): bigint => BigInt(c[name] as number | string);
    for (const c of v.cases) {
      const contract = hex((c["contract"] as string | undefined) ?? doc.contract);
      const online = (c["online"] as boolean | undefined) ?? doc.online;
      const refresh = c["last_refresh"] === undefined ? undefined : num(c, "last_refresh");
      const got = outcome(() => {
        k.checkValidity(
          contract,
          num(c, "now"),
          doc.audience,
          [],
          refresh,
          online,
          BigInt(doc.skew_ms),
          num(c, "iat"),
          num(c, "horizon_cap_ms"),
        );
        return true;
      });
      const want = "error" in c ? { error: field(c, "error") } : { ok: true };
      expect(got, c.id).toEqual(want);
    }
    expect(v.cases).toHaveLength(26);
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
        k.checkValidity(empty, 0n, "pep:shop", [], undefined, true, 60_000n, 0n, 0n);
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

async function exchange<T = Vectors>(name: string): Promise<T> {
  const url = new URL(`../../../conformance/vectors/exchange/1/${name}`, import.meta.url);
  return JSON.parse(await readFile(url, "utf8")) as T;
}

interface Head {
  readonly metadata?: string;
  readonly catalog?: string;
  readonly origin?: string;
  readonly log?: string;
  readonly cosigners?: readonly string[];
}

function uint(c: Case, name: string): bigint {
  return BigInt(c[name] as number);
}

function cbor(b: Uint8Array): unknown {
  let at = 0;
  const byte = (): number => b[at++] ?? 0;
  const arg = (info: number): number => {
    if (info < 24) return info;
    let n = 0;
    for (let i = 0; i < 1 << (info - 24); i++) n = n * 256 + byte();
    return n;
  };
  const item = (): unknown => {
    const first = byte();
    const n = arg(first & 31);
    switch (first >> 5) {
      case 0:
        return n;
      case 2: {
        const out = b.slice(at, at + n);
        at += n;
        return toHex(out);
      }
      case 3: {
        const out = new TextDecoder().decode(b.slice(at, at + n));
        at += n;
        return out;
      }
      case 4:
        return Array.from({ length: n }, item);
      case 5:
        return Object.fromEntries(Array.from({ length: n }, () => [item(), item()]));
      default:
        throw new TypeError("unexpected CBOR in this test decoder");
    }
  };
  return item();
}

// SA-T10: the Wasm verifier answers every offline verifier vector as the Rust Kernel does.
describe("Offline verifier vectors through the Wasm binding", () => {
  // L2-PAP-3
  it("pap.json", async () => {
    const v = await vectors<Vectors & Head>("pap.json");
    for (const c of v.cases) {
      const got = outcome(() =>
        toHex(
          k.verifyPap(
            hex(v.metadata ?? ""),
            hex(field(c, "sign1")),
            hex(field(c, "excerpt")),
            hex(field(c, "presentation")),
            hex(field(c, "domain")),
            hex(field(c, "intent")),
            field(c, "audience"),
            hex(field(c, "nonce")),
            uint(c, "now"),
            hex(v.catalog ?? ""),
            hex(field(c, "satisfied")),
            hex(field(c, "remaining")),
            c["fresh"] as boolean,
            c["understood"] as string[],
            c["last_refresh"] === undefined ? undefined : uint(c, "last_refresh"),
            c["online"] as boolean,
            uint(c, "skew_ms"),
            uint(c, "horizon_cap_ms"),
          ),
        ),
      );
      const want = "pap" in c ? { ok: field(c, "pap") } : { error: field(c, "error") };
      expect(got, c.id).toEqual(want);
    }
    expect(v.cases.length).toBeGreaterThan(20);
  });

  // L2-RCP-3
  it("receipt.json", async () => {
    const v = await vectors<Vectors & Head>("receipt.json");
    for (const c of v.cases) {
      const got = outcome(() =>
        toHex(
          k.verifyReceipt(
            hex(v.metadata ?? ""),
            hex(field(c, "sign1")),
            hex(field(c, "excerpt")),
            hex(field(c, "domain")),
            field(c, "audience"),
            hex(field(c, "intent")),
            uint(c, "now"),
          ),
        ),
      );
      const want = "receipt" in c ? { ok: field(c, "receipt") } : { error: field(c, "error") };
      expect(got, c.id).toEqual(want);
    }
  });

  // L2-RPT-1 to L2-RPT-3, U4
  it("report.json", async () => {
    const v = await vectors("report.json");
    for (const c of v.cases) {
      const got = outcome(() => cbor(k.verifyReport(hex(field(c, "report")))));
      if ("error" in c) {
        expect(got, c.id).toEqual({ error: field(c, "error") });
        continue;
      }
      expect(got, c.id).toEqual({
        ok: { head: field(c, "head"), next_seq: c["next_seq"], drawn: c["drawn"] },
      });
    }
  });

  // L2-STL-2, L2-STL-3, OP-150 m.6 (d)
  it("status-list.json", async () => {
    const v = await vectors("status-list.json");
    for (const c of v.cases) {
      const list = hex(field(c, "list"));
      const inflated = await inflateStatusList(Uint8Array.from(deflateSync(list)));
      expect(toHex(inflated), c.id).toBe(toHex(list));
      const got = outcome(() =>
        k.statusLookup(hex(field(c, "token")), inflated, hex(field(c, "reference"))),
      );
      const want = "invalid" in c ? { ok: c["invalid"] } : { error: field(c, "error") };
      expect(got, c.id).toEqual(want);
    }
    await expect(inflateStatusList(Uint8Array.of(0x78, 0x9c, 1, 2, 3))).rejects.toThrow(
      "status-compression",
    );
    const bomb = Uint8Array.from(deflateSync(new Uint8Array(MAX_STATUS_LIST_BYTES + 1)));
    await expect(inflateStatusList(bomb)).rejects.toThrow("status-compression");
  });

  // L2-CKP-1 to L2-CKP-4
  it("checkpoint.json", async () => {
    const v = await exchange<Vectors & Head>("checkpoint.json");
    for (const c of v.cases) {
      const got = outcome(() =>
        cbor(
          k.verifyCheckpoint(field(c, "note"), v.origin ?? "", v.log ?? "", [
            ...(v.cosigners ?? []),
          ]),
        ),
      );
      if ("error" in c) {
        expect(got, c.id).toEqual({ error: field(c, "error") });
        continue;
      }
      expect(got, c.id).toEqual({
        ok: {
          size: c["size"],
          root: toHex(Uint8Array.from(Buffer.from(field(c, "root"), "base64"))),
          extensions: c["extensions"],
          cosigned: c["cosigned"],
        },
      });
    }
  });
});
