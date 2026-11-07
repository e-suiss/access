// TN-110, PI-7, OP-151 m.11 (a): the console never encodes an intent itself (no CBOR in
// TypeScript). It asks for a draft, the Kernel decodes the drafted bytes, and the draft is used
// only when what was decoded is exactly what was asked for.
import { loadKernel } from "@esuiss/access";

import { fromB64url, json } from "./api.js";
import { type DecodedIntent, decodedIntent, NotSigned } from "./instance.js";

/** An action and its resources, as a screen asks for them. */
export interface Wanted {
  readonly action: { readonly namespace: string; readonly name: string; readonly major: number };
  readonly resources: readonly { readonly namespace: string; readonly path: readonly string[] }[];
  readonly params?: Readonly<Record<string, unknown>>;
}

/** A drafted intent: its ADP wire form, its canonical bytes and the Kernel's decoding of them. */
export interface Drafted {
  readonly intent: unknown;
  readonly envelope: Uint8Array;
  readonly decoded: DecodedIntent;
}

interface Draft {
  readonly intent: unknown;
  readonly envelope: string;
}

/** Whether the Kernel's decoding names exactly the action and resources of `w`. */
export function matches(w: Wanted, d: DecodedIntent): boolean {
  if (
    d.action.namespace !== w.action.namespace ||
    d.action.name !== w.action.name ||
    d.action.major !== String(w.action.major) ||
    d.resources.length !== w.resources.length
  ) {
    return false;
  }
  return w.resources.every((r, i) => {
    const got = d.resources[i];
    return (
      got?.namespace === r.namespace &&
      got.path.length === r.path.length &&
      got.path.every((p, j) => p === r.path[j])
    );
  });
}

/**
 * Drafts `w` through the BFF (`POST /console/api/intents`) and checks the drafted bytes with
 * the Kernel; a draft that decodes to anything else is refused before it is signed or sent.
 */
export async function draft(w: Wanted, mode: "check" | "commit"): Promise<Drafted> {
  const d = await json<Draft>("/intents", { method: "POST", body: { ...w, mode } });
  const k = await loadKernel();
  const envelope = fromB64url(d.envelope);
  const decoded = decodedIntent(k, envelope);
  if (!matches(w, decoded)) throw new NotSigned("mismatch");
  return { intent: d.intent, envelope, decoded };
}
