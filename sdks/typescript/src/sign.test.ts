import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

import { loadKernel } from "./index.js";

async function kernel() {
  const bytes = await readFile(new URL("../wasm/access_kernel_wasm_bg.wasm", import.meta.url));
  return loadKernel(bytes);
}

function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

// OP-151 m.3 (e), X11: the Kernel encodes what a browser key signs and decodes what it shows
describe("AIS signing helpers", () => {
  it("encode a statement the Kernel decodes back and assemble a COSE_Sign1", async () => {
    const k = await kernel();
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
      "sign",
      "verify",
    ]);
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    const [x, y] = [raw.slice(1, 33), raw.slice(33, 65)];
    const kid = k.thumbprintP256(x, y);
    expect(kid).toHaveLength(32);
    expect(k.coseKeyP256(x, y).length).toBeGreaterThan(64);
    const basis = k.exerciseBasis("public", new Uint8Array(16).fill(1));
    const statement = k.aisStatement(
      new Uint8Array(32).fill(3),
      new Uint8Array(16).fill(9),
      new Uint8Array(32).fill(4),
      "check",
      "access-console",
      new Uint8Array(),
      basis,
      1_500n,
      new Uint8Array(),
    );
    const shown = JSON.parse(k.describeStatement(statement)) as Record<string, unknown>;
    expect(shown["mode"]).toBe("check");
    expect(shown["iat"]).toBe("1500");
    expect(shown["intent"]).toBe(b64url(new Uint8Array(32).fill(4)));
    const protectedHeader = k.aisProtected(-9, kid);
    const tbs = k.coseToBeSigned(protectedHeader, statement);
    const signature = new Uint8Array(
      await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        pair.privateKey,
        Uint8Array.from(tbs),
      ),
    );
    const sign1 = k.coseSign1(protectedHeader, statement, signature);
    expect(sign1[0]).toBe(0xd2);
  });

  it("refuse malformed input with a stable name", async () => {
    const k = await kernel();
    expect(() => k.aisProtected(-7, new Uint8Array(32))).toThrow("algorithm not allowed");
    expect(() => k.describeStatement(new Uint8Array([0]))).toThrow("input");
    expect(() => k.exerciseBasis("holding", new Uint8Array(16))).toThrow("input");
    expect(() => k.exerciseBasis("anchor", new Uint8Array(16), new Uint8Array(16), 7n)).toThrow(
      "input",
    );
  });

  // OP-152 m.9 (d), IA-5: a delegated admin signs on its own holding
  it("encode a holding basis the statement shows with its episode", async () => {
    const k = await kernel();
    const basis = k.exerciseBasis(
      "holding",
      new Uint8Array(16).fill(1),
      new Uint8Array(16).fill(2),
      7n,
    );
    const statement = k.aisStatement(
      new Uint8Array(32).fill(3),
      new Uint8Array(16).fill(9),
      new Uint8Array(32).fill(4),
      "commit",
      "access-console",
      new Uint8Array(),
      basis,
      1_500n,
      new Uint8Array(),
    );
    const shown = JSON.parse(k.describeStatement(statement)) as {
      basis: { holding?: { grant: string; holder: string; since: string } };
    };
    expect(shown.basis.holding).toEqual({
      grant: b64url(new Uint8Array(16).fill(1)),
      holder: b64url(new Uint8Array(16).fill(2)),
      since: "7",
    });
  });
});
