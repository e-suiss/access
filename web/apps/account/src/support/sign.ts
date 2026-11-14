// OP-157 m.3 (f), XI-3, X11: the person's device signs exactly the Exercise Access drafted for
// their own request: the Kernel decodes the bytes for the signature screen, nothing is signed
// until the person presses Sign, and the route commits it with the person's own assertion.
import { loadKernel } from "@esuiss/access";

import { b64url, fromB64url } from "../lib/api.js";
import {
  type Confirm,
  decodedIntent,
  decodedStatement,
  type Instance,
  nonce,
  NotSigned,
  sign,
} from "../lib/instance.js";

/** An Exercise Access drafted for this person's device. */
export interface Drafted {
  readonly payload: string;
  readonly intent: string;
  readonly basis: { readonly anchor: string };
  /** The PEP the statement names: the route commits as this one. */
  readonly pep: string;
}

/** The body the route takes. */
export interface Signed {
  readonly nonce: string;
  readonly intent: string;
  readonly payload: string;
  readonly basis: { readonly anchor: string };
  readonly ais: string;
}

/** Shows the Kernel's decoding of `d`, signs on the person's Sign and returns the body. */
export async function signDraft(instance: Instance, confirm: Confirm, d: Drafted): Promise<Signed> {
  const k = await loadKernel();
  const envelope = fromB64url(d.intent);
  const decoded = decodedIntent(k, envelope);
  const n = nonce();
  const statement = k.aisStatement(
    instance.domain,
    n,
    k.intentDigest(envelope),
    "commit",
    d.pep,
    new Uint8Array(),
    k.exerciseBasis("anchor", fromB64url(d.basis.anchor)),
    BigInt(Date.now()),
    new Uint8Array(),
  );
  const shown = decodedStatement(k, statement);
  if (shown.intent !== decoded.digest) throw new NotSigned("mismatch");
  if (!(await confirm({ statement: shown, intents: [decoded] }))) {
    throw new NotSigned("cancelled");
  }
  return {
    nonce: b64url(n),
    intent: d.intent,
    payload: d.payload,
    basis: d.basis,
    ais: await sign(instance.key, k, instance.kid, statement),
  };
}
