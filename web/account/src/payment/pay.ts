// OP-156 m.3 (v), §8.17.5.11, R8, X8, X11, INV-20, XI-3, G39, HL-5: the one-time payment. The
// request comes from the merchant or Pay as the intent's exact bytes; this page shows only what
// the Kernel decodes from them, refuses anything that is not one-time (a core action or a meta
// payload would leave the merchant a Grant), and sends the customer's own commit, signed in this
// browser after the signature screen. It is shown paid only once Access answers with the record.
import { loadKernel, pay } from "@esuiss/access";
import { honesty } from "@suiss/access-react";

import { API, b64url, fromB64url } from "../lib/api.js";
import {
  type Confirm,
  decodedIntent,
  decodedStatement,
  type Instance,
  nonce,
  NotSigned,
  sign,
} from "../lib/instance.js";

/** What the merchant or Pay hands the page: the intent's bytes and its ADP wire form. */
export interface PaymentRequest {
  /** The canonical intent envelope, base64url. */
  readonly envelope: string;
  /** The same intent as ADP's wire JSON. */
  readonly intent: Readonly<Record<string, unknown>>;
  /** The customer's payment-instrument Anchor the Exercise rests on. */
  readonly anchor: string;
  /** How the merchant is named to the customer. */
  readonly merchant: string;
}

/** The request in the page's fragment `#request=<base64url JSON>`, never sent to a server. */
export function requestOf(hash: string): PaymentRequest | undefined {
  const raw = new URLSearchParams(hash.replace(/^#/, "")).get("request");
  if (raw === null) return undefined;
  try {
    const v = JSON.parse(new TextDecoder().decode(fromB64url(raw))) as Record<string, unknown>;
    const { envelope, intent, anchor, merchant } = v;
    if (
      typeof envelope !== "string" ||
      typeof anchor !== "string" ||
      typeof merchant !== "string" ||
      typeof intent !== "object" ||
      intent === null
    ) {
      return undefined;
    }
    return { envelope, intent: intent as Record<string, unknown>, anchor, merchant };
  } catch {
    return undefined;
  }
}

/** The decoded request: a one-time payment, or why it is not one. */
export async function decode(r: PaymentRequest): Promise<pay.OneTime | pay.NotOneTime> {
  const k = await loadKernel();
  try {
    const described = JSON.parse(k.describeIntent(fromB64url(r.envelope))) as pay.DescribedIntent;
    const wired = r.intent["action"] as Record<string, unknown> | undefined;
    if (
      wired?.["namespace"] !== described.action.namespace ||
      wired["name"] !== described.action.name
    ) {
      return "authority_change";
    }
    return pay.oneTimeOf(described);
  } catch {
    return "no_amount";
  }
}

/** A payment on its way: what is shown and what may be done next (§8.13). */
export interface Paying {
  readonly attempt: honesty.Attempt;
  readonly shown: honesty.Shown;
  readonly retry: () => Promise<Paying>;
}

function csrf(): string {
  for (const part of document.cookie.split(";")) {
    const [name, value] = part.trim().split("=", 2);
    if (name === "__Host-access-account-csrf" && value !== undefined) return value;
  }
  return "";
}

/** Signs and sends the customer's own commit of `r` (never a `grant.issue`). */
export async function payOnce(
  instance: Instance,
  confirm: Confirm,
  r: PaymentRequest,
  timeoutMs = 15_000,
): Promise<Paying> {
  const once = await decode(r);
  if (typeof once === "string") throw new NotSigned("mismatch");
  const k = await loadKernel();
  const envelope = fromB64url(r.envelope);
  const intent = decodedIntent(k, envelope);
  const n = nonce();
  const statement = k.aisStatement(
    instance.domain,
    n,
    k.intentDigest(envelope),
    "commit",
    instance.pep,
    new Uint8Array(),
    k.exerciseBasis("anchor", fromB64url(r.anchor)),
    BigInt(Date.now()),
    new Uint8Array(),
  );
  const shown = decodedStatement(k, statement);
  if (shown.intent !== intent.digest) throw new NotSigned("mismatch");
  if (!(await confirm({ statement: shown, intents: [intent] }))) throw new NotSigned("cancelled");
  const resource = intent.resources[0];
  const body = {
    subject: { type: "access_party", id: instance.party },
    action: { name: intent.action.name },
    resource: { type: resource?.namespace ?? "", id: (resource?.path ?? []).join("/") },
    context: {
      domain: b64url(instance.domain),
      mode: "commit",
      nonce: b64url(n),
      intent: r.intent,
      basis: { anchor: r.anchor },
      capacity: "own",
      ais: await sign(instance.key, k, instance.kid, statement),
    },
  };
  const send = async (): Promise<Paying> => {
    const timer = new AbortController();
    const stop = setTimeout(() => {
      timer.abort();
    }, timeoutMs);
    let attempt: honesty.Attempt;
    try {
      const res = await fetch(`${API}/proxy/adp/evaluation`, {
        method: "POST",
        headers: {
          accept: "application/json",
          "content-type": "application/json",
          "x-csrf-token": csrf(),
        },
        body: JSON.stringify(body),
        credentials: "same-origin",
        cache: "no-store",
        signal: timer.signal,
      });
      const answer: unknown = await res.json().catch(() => ({}));
      attempt = {
        sent: "sent",
        path: "direct",
        answer: honesty.answerOf(res.status, answer),
        timedOut: false,
        validUntil: once.until,
      };
    } catch {
      attempt = {
        sent: "sent",
        path: "direct",
        answer: { kind: "nothing" },
        timedOut: true,
        validUntil: once.until,
      };
    } finally {
      clearTimeout(stop);
    }
    return { attempt, shown: honesty.shown(attempt), retry: send };
  };
  return send();
}
