// OQ-MD4, OP-150 m.1 (c): Kernel calls through the wasm-bindgen package on Node.
// Usage: node scripts/bench_ffi.mjs <wasm-bindgen out dir> <inputs.json> [iterations]
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const [dir, inputsPath, itersArg] = process.argv.slice(2);
const iters = Number(itersArg ?? 2000);
const kernel = await import(pathToFileURL(join(dir, "access_kernel_wasm.js")).href);
await kernel.default({ module_or_path: readFileSync(join(dir, "access_kernel_wasm_bg.wasm")) });
const inputs = JSON.parse(readFileSync(inputsPath, "utf8"));
const bytes = (hex) => Uint8Array.from(Buffer.from(hex, "hex"));

function time(call) {
  for (let i = 0; i < iters; i++) call();
  const start = process.hrtime.bigint();
  for (let i = 0; i < iters; i++) call();
  return Number(process.hrtime.bigint() - start) / iters;
}

function report(op, ns) {
  console.log(JSON.stringify({ runtime: "node", op, ns_per_call: Math.round(ns), iters }));
}

const evaluate = inputs.evaluate;
const input = bytes(evaluate.input);
const fuel = BigInt(evaluate.fuel);
report(
  "evaluate",
  time(() => kernel.evaluate(input, fuel)),
);

const cose = inputs.verify_cose_sign1;
const sign1 = bytes(cose.sign1);
const keySet = bytes(cose.key_set);
report(
  "verify_cose_sign1",
  time(() => kernel.verifyCoseSign1(sign1, keySet, cose.content_type)),
);
