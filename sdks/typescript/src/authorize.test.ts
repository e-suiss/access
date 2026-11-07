// §9.5, L2-RCP-3, X21, TI-9, MD-8
import { readFile } from "node:fs/promises";

import { beforeAll, describe, expect, it } from "vitest";

import { authorize, type DecisionAsk, statusValid } from "./authorize.js";
import { type Kernel, inflateStatusList, loadKernel } from "./index.js";

interface ReceiptCase {
  readonly id: string;
  readonly sign1?: string;
  readonly excerpt?: string;
  readonly domain?: string;
  readonly audience?: string;
  readonly intent?: string;
  readonly now?: string;
  readonly receipt?: string;
}

const hex = (s: string): Uint8Array => Uint8Array.from(Buffer.from(s, "hex"));
const b64 = (s: string): string => Buffer.from(s, "hex").toString("base64url");

let k: Kernel;
let metadata: Uint8Array;
let valid: Required<ReceiptCase>;

beforeAll(async () => {
  k = await loadKernel(
    await readFile(new URL("../wasm/access_kernel_wasm_bg.wasm", import.meta.url)),
  );
  const v = JSON.parse(
    await readFile(
      new URL("../../../conformance/vectors/core/1/receipt.json", import.meta.url),
      "utf8",
    ),
  ) as { metadata: string; cases: readonly ReceiptCase[] };
  metadata = hex(v.metadata);
  valid = v.cases.find((c) => c.id === "valid") as Required<ReceiptCase>;
});

/** The `exercise` digest inside the receipt payload: text "exercise" then a 32-byte digest. */
function exerciseOf(receiptHex: string): Uint8Array {
  const m = /686578657263697365(822f5820[0-9a-f]{64})/.exec(receiptHex);
  if (m?.[1] === undefined) throw new Error("no exercise");
  return hex(m[1]);
}

function ask(over: Partial<DecisionAsk> = {}): DecisionAsk {
  return {
    url: "https://adp.example/access/v1/evaluation",
    body: { context: {} },
    metadata,
    domain: hex(valid.domain),
    audience: valid.audience,
    intent: hex(valid.intent),
    nonce: new Uint8Array(16),
    continued: exerciseOf(valid.receipt),
    now: BigInt(valid.now),
    ...over,
  };
}

function answer(status: number, body: unknown): typeof fetch {
  return () =>
    Promise.resolve(
      new Response(typeof body === "string" ? body : JSON.stringify(body), { status }),
    );
}

const allow = (): unknown => ({
  decision: true,
  context: { receipt: { sign1: b64(valid.sign1), excerpt: b64(valid.excerpt) } },
});

describe("authorize", () => {
  it("authorizes a verified ALLOW for this intent, audience and Exercise", async () => {
    const got = await authorize(k, answer(200, allow()), ask());
    expect(got.allowed).toBe(true);
    if (got.allowed) expect(got.receipt).toEqual(hex(valid.receipt));
  });

  it("denies every fault and never allows", async () => {
    const cases: [typeof fetch, Partial<DecisionAsk>, string][] = [
      [answer(200, allow()), { now: undefined }, "clock"],
      [() => Promise.reject(new TypeError("network")), {}, "unavailable"],
      [answer(503, allow()), {}, "status"],
      [answer(200, "not json"), {}, "malformed"],
      [answer(200, { decision: true, context: {} }), {}, "receipt-missing"],
      [answer(200, allow()), { audience: "other.example" }, "receipt-audience"],
      [answer(200, allow()), { continued: new Uint8Array() }, "receipt-exercise"],
      [answer(200, allow()), { contentPosition: 1n << 60n }, "content-position"],
    ];
    for (const [f, over, code] of cases) {
      const got = await authorize(k, f, ask(over));
      expect(got.allowed, code).toBe(false);
      if (!got.allowed) expect(got.code).toBe(code);
    }
  });

  // P15: a refusal carries its reasons, an unknown subcode read as its class
  it("returns a refusal with its reasons", async () => {
    const deny = {
      decision: false,
      context: { outcome: "deny", blockers: [{ class: "ended", subcode: "ended/unheard-of" }] },
    };
    const got = await authorize(k, answer(200, deny), ask());
    expect(got).toEqual({
      allowed: false,
      class: "decision",
      code: "refused",
      reasons: [{ class: "ended" }],
    });
    const unknownClass = { decision: false, context: { blockers: [{ class: "new" }] } };
    const u = await authorize(k, answer(200, unknownClass), ask());
    expect(u).toMatchObject({ allowed: false, class: "unknown" });
  });

  // L2-STL-3: a list that cannot be read is invalid, never valid
  it("treats an unreadable status list as invalid", async () => {
    expect(
      await statusValid(
        k,
        new Uint8Array(),
        new Uint8Array([1, 2]),
        new Uint8Array(),
        inflateStatusList,
      ),
    ).toBe(false);
  });
});
