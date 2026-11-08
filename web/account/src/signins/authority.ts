// §8.5 S10, X36, OP-149 m.6, OP-153 m.3 (y): the authority half of "End this sign-in". The other
// device's Instance is terminated by an `instance_terminate` this browser's own device key signs
// after the signature screen shows the Kernel's decoding; Access forwards it as PEP.
import { loadKernel } from "@esuiss/access";

import { draft } from "../lib/adp.js";
import { b64url, call, fromB64url, frontend, json, type SessionInfo } from "../lib/api.js";
import {
  type Confirm,
  decodedStatement,
  find,
  type Instance,
  nonce,
  NotSigned,
  sign,
} from "../lib/instance.js";

/** This browser's device Instance, when it has one for the signed-in account. */
export async function ownInstance(): Promise<Instance | undefined> {
  const s = await json<SessionInfo>(call("/session"));
  return find(s.realm, s.account, s.instance);
}

function iso(ms: string): string {
  return new Date(Number(ms)).toISOString();
}

/** Terminates the Instance `target` (base64url id) with `instance`'s key. */
export async function terminate(
  instance: Instance,
  confirm: Confirm,
  target: string,
): Promise<void> {
  const k = await loadKernel();
  const d = await draft(
    instance,
    {
      action: { namespace: "access", name: "instance_terminate", major: 1 },
      resources: [{ namespace: "access.instance", path: [target] }],
    },
    "commit",
  );
  const n = nonce();
  const statement = k.aisStatement(
    instance.domain,
    n,
    k.intentDigest(d.envelope),
    "commit",
    instance.pep,
    new Uint8Array(),
    k.exerciseBasis("anchor", fromB64url(instance.party)),
    BigInt(Date.now()),
    new Uint8Array(),
  );
  const shown = decodedStatement(k, statement);
  if (shown.intent !== d.decoded.digest) throw new NotSigned("mismatch");
  if (!(await confirm({ statement: shown, intents: [d.decoded] }))) {
    throw new NotSigned("cancelled");
  }
  await json(
    frontend(`/v1/me/instances/${encodeURIComponent(target)}`, {
      method: "DELETE",
      body: {
        nonce: b64url(n),
        basis: instance.party,
        valid_from: iso(d.decoded.validity.from),
        valid_until: iso(d.decoded.validity.until),
        ais: await sign(instance.key, k, instance.kid, statement),
      },
    }),
  );
}
