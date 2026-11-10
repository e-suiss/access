// OP-153 m.3 (w), m.8 (a), (b), TN-110, PI-7, XI-3: the hub's reads and its one write. Every read
// is the viewer's own `check`, signed in this browser; the BFF forwards nothing without it. The
// write is a `commit` the viewer signs after the signature screen; the page shows it done only
// once Access answers with the recorded Exercise.
import { loadKernel } from "@esuiss/access";
import { honesty } from "@suiss/access-react";

import { API, b64url, call, fromB64url, json, Problem } from "./api.js";
import {
  type Confirm,
  type DecodedIntent,
  decodedIntent,
  decodedStatement,
  type Instance,
  nonce,
  NotSigned,
  readProof,
  sign,
} from "./instance.js";

/** An action and its resources, as a screen asks for them. */
export interface Wanted {
  readonly action: { readonly namespace: string; readonly name: string; readonly major: number };
  readonly resources?: readonly { readonly namespace: string; readonly path: readonly string[] }[];
  readonly payload?: Readonly<Record<string, unknown>>;
}

interface Draft {
  readonly intent: {
    readonly resources: readonly { readonly namespace: string; readonly path: readonly string[] }[];
  };
  readonly envelope: string;
  readonly payload?: string;
  readonly basis?: { readonly anchor: string };
}

interface Drafted {
  readonly draft: Draft;
  readonly envelope: Uint8Array;
  readonly decoded: DecodedIntent;
}

/** Drafts `w` (a read with a read proof) and checks the drafted bytes with the Kernel. */
export async function draft(
  instance: Instance,
  w: Wanted,
  mode: "check" | "commit",
): Promise<Drafted> {
  const d = await json<Draft>(
    call("/intents", {
      method: "POST",
      body: { ...w, mode },
      headers: { "x-access-ais": await readProof(instance, "POST", `${API}/intents`) },
    }),
  );
  const k = await loadKernel();
  const envelope = fromB64url(d.envelope);
  const decoded = decodedIntent(k, envelope);
  const wantedResources = w.resources ?? d.intent.resources;
  const same =
    decoded.action.namespace === w.action.namespace &&
    decoded.action.name === w.action.name &&
    decoded.resources.length === wantedResources.length &&
    decoded.resources.every(
      (r, i) =>
        r.namespace === wantedResources[i]?.namespace &&
        r.path.join("/") === wantedResources[i].path.join("/"),
    );
  if (!same) throw new NotSigned("mismatch");
  return { draft: d, envelope, decoded };
}

async function checkContext(instance: Instance, w: Wanted): Promise<Record<string, unknown>> {
  const k = await loadKernel();
  const d = await draft(instance, w, "check");
  const n = nonce();
  const statement = k.aisStatement(
    instance.domain,
    n,
    k.intentDigest(d.envelope),
    "check",
    instance.pep,
    new Uint8Array(),
    instance.basis,
    BigInt(Date.now()),
    new Uint8Array(),
  );
  return {
    domain: b64url(instance.domain),
    mode: "check",
    nonce: b64url(n),
    intent: d.draft.intent,
    basis: { public: instance.publicBasis },
    capacity: "own",
    ais: await sign(instance.key, k, instance.kid, statement),
  };
}

/** The hub's search kinds (OP-153 m.8 (a), (b)). */
export type HubKind = "inventory" | "activity" | "changes" | "revocation-impact";

export interface SearchAnswer {
  readonly results: readonly Readonly<Record<string, unknown>>[];
}

/** One search page of `kind`, read as the viewer. */
export async function search(
  instance: Instance,
  kind: HubKind,
  query: Readonly<Record<string, unknown>>,
): Promise<SearchAnswer> {
  const context = await checkContext(instance, {
    action: { namespace: "access", name: "read", major: 1 },
    resources: [{ namespace: "access.search", path: [kind] }],
  });
  return json<SearchAnswer>(
    call(`/proxy/adp/search/${kind}`, { method: "POST", body: { context: { ...context, query } } }),
  );
}

/** An explanation as ADP answers it. */
export interface Explained {
  readonly decision?: boolean;
  readonly context?: Readonly<Record<string, unknown>>;
}

/** Why the viewer may do `w` now: advisory, never recorded (E-1, S5). */
export async function explain(
  instance: Instance,
  w: Required<Pick<Wanted, "action" | "resources">>,
): Promise<Explained> {
  const context = await checkContext(instance, w);
  const first = w.resources[0];
  return json<Explained>(
    call("/proxy/adp/explain", {
      method: "POST",
      body: {
        subject: { type: "access_party", id: instance.party },
        action: { name: w.action.name },
        resource: { type: first?.namespace ?? "", id: (first?.path ?? []).join("/") },
        context,
      },
    }),
  );
}

/** A revoke on its way: what the page shows and what it may do next (§8.13). */
export interface Revoking {
  readonly attempt: honesty.Attempt;
  readonly shown: honesty.Shown;
  readonly exercise?: string;
  readonly position?: number;
  /** Sends the same signed request again (HL-5, TI-8). */
  readonly retry: () => Promise<Revoking>;
}

/** How long the page waits for Access before it says "Not confirmed — checking". */
export const ANSWER_TIMEOUT_MS = 15_000;

/**
 * Revokes `grant` (S4, TN-110): drafts `grant_revoke`, shows the Kernel's decoding on the
 * signature screen, signs, and sends the commit. The answer decides what is shown; a lost answer
 * is "Not confirmed — checking", and the retry sends the same nonce.
 */
export async function revoke(
  instance: Instance,
  confirm: Confirm,
  grant: string,
  timeoutMs: number = ANSWER_TIMEOUT_MS,
): Promise<Revoking> {
  return commitMeta(instance, confirm, "grant_revoke", { grant_revoke: { grant } }, timeoutMs);
}

/**
 * Commits the meta write `name` with `payload` (TN-110, OP-156 m.3 (v)): drafts it, shows the
 * Kernel's decoding on the signature screen, signs on the draft's basis and sends the commit.
 * The answer decides what is shown, as for a revoke.
 */
export async function commitMeta(
  instance: Instance,
  confirm: Confirm,
  name: string,
  payload: Readonly<Record<string, unknown>>,
  timeoutMs: number = ANSWER_TIMEOUT_MS,
): Promise<Revoking> {
  const k = await loadKernel();
  const d = await draft(
    instance,
    { action: { namespace: "access", name, major: 1 }, payload },
    "commit",
  );
  const anchor = d.draft.basis?.anchor;
  if (anchor === undefined || d.draft.payload === undefined) throw new NotSigned("mismatch");
  const n = nonce();
  const statement = k.aisStatement(
    instance.domain,
    n,
    k.intentDigest(d.envelope),
    "commit",
    instance.pep,
    new Uint8Array(),
    k.exerciseBasis("anchor", fromB64url(anchor)),
    BigInt(Date.now()),
    new Uint8Array(),
  );
  const shown = decodedStatement(k, statement);
  if (shown.intent !== d.decoded.digest) throw new NotSigned("mismatch");
  if (!(await confirm({ statement: shown, intents: [d.decoded] }))) {
    throw new NotSigned("cancelled");
  }
  const resource = d.draft.intent.resources[0];
  const body = {
    subject: { type: "access_party", id: instance.party },
    action: { name },
    resource: { type: resource?.namespace ?? "", id: (resource?.path ?? []).join("/") },
    context: {
      domain: b64url(instance.domain),
      mode: "commit",
      nonce: b64url(n),
      intent: d.draft.intent,
      payload: d.draft.payload,
      basis: { anchor },
      capacity: "own",
      ais: await sign(instance.key, k, instance.kid, statement),
    },
  };
  const validUntil = Number(d.decoded.validity.until);
  const send = async (): Promise<Revoking> => {
    const timer = new AbortController();
    const stop = setTimeout(() => {
      timer.abort();
    }, timeoutMs);
    let attempt: honesty.Attempt;
    let exercise: string | undefined;
    let position: number | undefined;
    try {
      const r = await fetch(`${API}/proxy/adp/evaluation`, {
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
      const answer: unknown = await r.json().catch(() => ({}));
      attempt = {
        sent: "sent",
        path: "direct",
        answer: honesty.answerOf(r.status, answer),
        timedOut: false,
        validUntil,
      };
      const c = (answer as { context?: { exercise?: unknown; position?: unknown } }).context;
      if (typeof c?.exercise === "string") exercise = c.exercise;
      if (typeof c?.position === "number") position = c.position;
    } catch {
      attempt = {
        sent: "sent",
        path: "direct",
        answer: { kind: "nothing" },
        timedOut: true,
        validUntil,
      };
    } finally {
      clearTimeout(stop);
    }
    return {
      attempt,
      shown: honesty.shown(attempt),
      ...(exercise === undefined ? {} : { exercise }),
      ...(position === undefined ? {} : { position }),
      retry: send,
    };
  };
  return send();
}

function csrf(): string {
  for (const part of document.cookie.split(";")) {
    const [name, value] = part.trim().split("=", 2);
    if (name === "__Host-access-account-csrf" && value !== undefined) return value;
  }
  return "";
}

export { Problem };
