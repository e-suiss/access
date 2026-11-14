// Test-side deterministic CBOR (RFC 8949 §4.2.1) for the intent envelopes the mock BFF drafts.
// The account pages never write CBOR; the Kernel in the browser decodes what this produces and
// refuses anything that is not canonical.

export type Cbor = number | string | Uint8Array | readonly Cbor[] | { readonly [k: string]: Cbor };

function head(major: number, n: number): number[] {
  const m = major << 5;
  if (n < 24) return [m | n];
  if (n < 0x100) return [m | 24, n];
  if (n < 0x10000) return [m | 25, n >> 8, n & 0xff];
  if (n < 0x1_0000_0000)
    return [m | 26, (n >>> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];
  const hi = Math.floor(n / 0x1_0000_0000);
  const lo = n >>> 0;
  return [
    m | 27,
    (hi >>> 24) & 0xff,
    (hi >> 16) & 0xff,
    (hi >> 8) & 0xff,
    hi & 0xff,
    (lo >>> 24) & 0xff,
    (lo >> 16) & 0xff,
    (lo >> 8) & 0xff,
    lo & 0xff,
  ];
}

function compare(a: Uint8Array, b: Uint8Array): number {
  if (a.length !== b.length) return a.length - b.length;
  for (let i = 0; i < a.length; i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

export function encode(v: Cbor): Uint8Array {
  if (typeof v === "number") {
    return Uint8Array.from(v >= 0 ? head(0, v) : head(1, -1 - v));
  }
  if (typeof v === "string") {
    const b = new TextEncoder().encode(v);
    return Uint8Array.from([...head(3, b.length), ...b]);
  }
  if (v instanceof Uint8Array) return Uint8Array.from([...head(2, v.length), ...v]);
  if (Array.isArray(v)) {
    const items = (v as readonly Cbor[]).map(encode);
    return Uint8Array.from([...head(4, items.length), ...items.flatMap((i) => [...i])]);
  }
  const entries = Object.entries(v as Record<string, Cbor>)
    .map(([k, x]) => [encode(k), encode(x)] as const)
    .sort((a, b) => compare(a[0], b[0]));
  return Uint8Array.from([
    ...head(5, entries.length),
    ...entries.flatMap(([k, x]) => [...k, ...x]),
  ]);
}
