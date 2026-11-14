// OP-149 m.26 (b), §10.2.2: a code of the bootstrap test user's authenticator app, from the seed
// the bootstrap wrote (RFC 6238: HMAC-SHA-1, six digits, 30-second steps).
import { createHmac } from "node:crypto";

const STEP_S = 30;
const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32(text: string): Buffer {
  const out: number[] = [];
  let bits = 0;
  let value = 0;
  for (const c of text.replace(/=+$/, "").toUpperCase()) {
    const v = BASE32.indexOf(c);
    if (v < 0) throw new Error("ACCESS_LIVE_TEST_TOTP_SEED is not base32");
    value = (value << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >> bits) & 0xff);
    }
  }
  return Buffer.from(out);
}

/** RFC 6238 over RFC 4226: the code of `step`. */
export function totp(seed: string, step: number): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const mac = createHmac("sha1", base32(seed)).update(counter).digest();
  const offset = (mac.at(-1) ?? 0) & 0x0f;
  const binary = mac.readUInt32BE(offset) & 0x7fffffff;
  return String(binary % 1_000_000).padStart(6, "0");
}

/**
 * TN-59: the realm accepts each step once, and only a later one after it, so a sign-in waits for
 * the next step to begin and answers with its code.
 */
export async function nextStep(): Promise<number> {
  const now = Date.now();
  const step = Math.floor(now / 1000 / STEP_S) + 1;
  await new Promise((resolve) => setTimeout(resolve, step * STEP_S * 1000 - now));
  return step;
}
