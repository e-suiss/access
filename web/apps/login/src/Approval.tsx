// §11.6, P58, EI-18, OP-154 m.3 (k), AS-M14, AG-6, AG-5: the consent screen of a client the environment
// did not register is the hosted Approval Surface. It shows the hostnames always and the client's
// name only as its own claim; approving is the person's own `grant.issue`, signed by their device
// Instance after the screen showed the Kernel's decoding. It never says Allow and never grants by
// itself: the record is kept only for the allowed Exercise.

import { Button } from "@access/ui/components/button";
import { loadKernel } from "@esuiss/access";
import { useEffect, useRef, useState } from "react";
import * as v from "valibot";

import { LOGIN, under } from "./base.js";
import { follow, postJson, returnTo } from "./http.js";
import { t } from "./i18n.js";
import {
  account,
  b64url,
  type Decoded,
  decode,
  find,
  fromB64url,
  Holding,
  type Instance,
  NotSigned,
  register,
  Session,
  sign,
} from "./instance.js";
import {
  facts,
  inlineLink,
  note,
  outcome,
  Panel,
  primary,
  problem,
  quiet,
  stack,
  Title,
  warning,
} from "./Layout.js";

// OP-159 m.46 (f)
const Draft = v.looseObject({
  domain: v.string(),
  intent: v.looseObject({
    resources: v.array(v.looseObject({ namespace: v.string(), path: v.array(v.string()) })),
  }),
  envelope: v.string(),
  payload: v.string(),
  basis: Holding,
});

type Draft = Readonly<v.InferOutput<typeof Draft>>;

/** What the consent screen shows (`POST /v1/login/approval/preview`). */
const ApprovalPreview = v.looseObject({
  client_id: v.string(),
  client_host: v.string(),
  client_says: v.string(),
  redirect_hosts: v.array(v.string()),
  loopback_only: v.boolean(),
  new_app: v.boolean(),
  visual_changed: v.boolean(),
  resource: v.string(),
  scopes: v.array(v.string()),
  csrf: v.string(),
  draft: v.nullable(Draft),
});

export type ApprovalPreview = Readonly<v.InferOutput<typeof ApprovalPreview>>;

const Redirect = v.looseObject({ redirect_to: v.string() });

const Evaluation = v.looseObject({
  decision: v.exactOptional(v.boolean()),
  context: v.exactOptional(v.looseObject({ exercise: v.exactOptional(v.string()) })),
});

type State =
  | { readonly phase: "loading" }
  | { readonly phase: "ready"; readonly preview: ApprovalPreview }
  | { readonly phase: "confirm"; readonly preview: ApprovalPreview; readonly decoded: Decoded }
  | { readonly phase: "sign_in" }
  | { readonly phase: "declined" }
  | { readonly phase: "failed" };

/** How long "You chose not to continue" stays before the app gets its answer. */
export const DECLINE_PAUSE_MS = 1500;

async function csrfPost<S extends v.GenericSchema>(
  path: string,
  csrf: string,
  body: unknown,
  schema: S,
): Promise<v.InferOutput<S>> {
  const r = await fetch(under(path), {
    method: "POST",
    credentials: "same-origin",
    cache: "no-store",
    redirect: "error",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
      "x-csrf-token": csrf,
    },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new NotSigned(String(r.status));
  const read = v.safeParse(schema, await r.json());
  if (!read.success) throw new NotSigned("malformed");
  return read.output;
}

/** Commits the drafted `grant.issue` with the device Instance; the allowed Exercise. */
async function commit(
  session: Session,
  instance: Instance,
  draft: Draft,
  shown: Decoded,
): Promise<string> {
  const k = await loadKernel();
  const envelope = fromB64url(draft.envelope);
  const decoded = decode(k, envelope, draft.domain);
  if (decoded.action !== shown.action || decoded.action !== "access.grant_issue") {
    throw new NotSigned("mismatch");
  }
  const h = draft.basis.holding;
  const nonce = crypto.getRandomValues(new Uint8Array(16));
  const statement = k.aisStatement(
    fromB64url(draft.domain),
    nonce,
    k.intentDigest(envelope),
    "commit",
    session.pep,
    new Uint8Array(),
    k.exerciseBasis("holding", fromB64url(h.grant), fromB64url(h.holder), BigInt(h.since)),
    BigInt(Date.now()),
    new Uint8Array(),
  );
  const resource = draft.intent.resources[0];
  const answer = await account("/proxy/adp/evaluation", Evaluation, {
    subject: { type: "access_party", id: h.holder },
    action: { name: "grant_issue" },
    resource: { type: resource?.namespace ?? "", id: (resource?.path ?? []).join("/") },
    context: {
      domain: draft.domain,
      mode: "commit",
      nonce: b64url(nonce),
      intent: draft.intent,
      payload: draft.payload,
      basis: draft.basis,
      capacity: "own",
      ais: await sign(instance.key, k, instance.kid, statement),
    },
  });
  const exercise = answer.context?.exercise;
  if (answer.decision !== true || exercise === undefined) throw new NotSigned("refused");
  return exercise;
}

export function Approval() {
  const back = returnTo();
  const [state, setState] = useState<State>(
    back === null ? { phase: "failed" } : { phase: "loading" },
  );
  const [busy, setBusy] = useState(false);
  const title = useRef<HTMLHeadingElement>(null);
  const confirmed = useRef<((ok: boolean) => void) | null>(null);

  useEffect(() => {
    if (back === null) return;
    void postJson("/v1/login/approval/preview", { return_to: back }, ApprovalPreview).then((a) => {
      if (a.ok) setState({ phase: "ready", preview: a.body });
      else if (a.status === 401) setState({ phase: "sign_in" });
      else setState({ phase: "failed" });
    });
  }, [back]);

  useEffect(() => {
    if (state.phase !== "loading") title.current?.focus();
  }, [state.phase]);

  const approve = async (preview: ApprovalPreview) => {
    const draft = preview.draft;
    if (back === null || draft === null) return;
    setBusy(true);
    try {
      const k = await loadKernel();
      const shown = decode(k, fromB64url(draft.envelope), draft.domain);
      const ask = (d: Decoded) =>
        new Promise<boolean>((resolve) => {
          confirmed.current = resolve;
          setState({ phase: "confirm", preview, decoded: d });
          setBusy(false);
        });
      const session = await account("/session", Session);
      const instance = (await find(session)) ?? (await register(session, ask));
      if (!(await ask(shown))) throw new NotSigned("cancelled");
      setBusy(true);
      const exercise = await commit(session, instance, draft, shown);
      const r = await csrfPost(
        "/v1/login/approval",
        preview.csrf,
        { return_to: back, domain: draft.domain, exercise },
        Redirect,
      );
      follow(r.redirect_to);
    } catch {
      setState({ phase: "failed" });
    } finally {
      setBusy(false);
    }
  };

  // X-L8
  const decline = async (preview: ApprovalPreview) => {
    if (back === null) return;
    setBusy(true);
    try {
      const r = await csrfPost(
        "/v1/login/approval/decline",
        preview.csrf,
        { return_to: back },
        Redirect,
      );
      setState({ phase: "declined" });
      window.setTimeout(() => {
        follow(r.redirect_to);
      }, DECLINE_PAUSE_MS);
    } catch {
      setState({ phase: "failed" });
    } finally {
      setBusy(false);
    }
  };

  const preview = state.phase === "ready" || state.phase === "confirm" ? state.preview : null;
  return (
    <Panel aria-busy={state.phase === "loading" || busy}>
      <section aria-labelledby="approval-heading" data-kind="approval" className={stack}>
        <Title id="approval-heading" ref={title}>
          {preview === null
            ? t("consent.title")
            : t("consent.agent_title", { client: preview.client_host })}
        </Title>
        {state.phase === "loading" && (
          <p role="status" className={note}>
            {t("page.loading")}
          </p>
        )}
        {preview !== null && (
          <>
            <p data-testid="client-says">
              {t("consent.client_says", { name: preview.client_says })}
            </p>
            <p data-testid="resource">{t("consent.resource", { resource: preview.resource })}</p>
            <ul
              aria-label={t("consent.redirect_host", { host: "" })}
              className="list-disc space-y-1 ps-5"
            >
              {preview.redirect_hosts.map((h) => (
                <li key={h} data-testid="redirect-host">
                  {t("consent.redirect_host", { host: h })}
                </li>
              ))}
            </ul>
            {preview.loopback_only && (
              <p role="alert" className={warning} data-testid="loopback">
                {t("consent.loopback")}
              </p>
            )}
            {preview.visual_changed && (
              <p role="alert" className={warning} data-testid="visual-changed">
                {t("consent.visual_changed")}
              </p>
            )}
            {preview.new_app && (
              <p className={warning} data-testid="new-app">
                {t("consent.new_app")}
              </p>
            )}
          </>
        )}
        {state.phase === "ready" && (
          <div className="flex flex-col gap-2">
            <Button
              {...primary}
              disabled={busy || state.preview.draft === null}
              onClick={() => void approve(state.preview)}
            >
              {t("action.approve_access")}
            </Button>
            <Button {...quiet} disabled={busy} onClick={() => void decline(state.preview)}>
              {t("action.decline_access")}
            </Button>
          </div>
        )}
        {state.phase === "confirm" && (
          <div
            role="dialog"
            aria-labelledby="sign-heading"
            data-testid="signature"
            className="flex flex-col gap-3 rounded-xl border p-4"
          >
            <h2 id="sign-heading" className="text-lg font-semibold">
              {t("action.approve_access")}
            </h2>
            <dl className={facts}>
              <dt>{state.decoded.action}</dt>
              <dd>{state.decoded.until}</dd>
            </dl>
            <div className="flex flex-col gap-2">
              <Button
                {...primary}
                onClick={() => {
                  confirmed.current?.(true);
                }}
              >
                {t("action.approve_access")}
              </Button>
              <Button
                {...quiet}
                onClick={() => {
                  confirmed.current?.(false);
                }}
              >
                {t("action.decline_access")}
              </Button>
            </div>
          </div>
        )}
        {state.phase === "sign_in" && (
          <p role="alert">
            <a className={inlineLink} href={LOGIN}>
              {t("action.sign_in")}
            </a>
          </p>
        )}
        {state.phase === "declined" && (
          <p role="status" className={outcome} data-testid="declined">
            {t("page.access_denied")}
          </p>
        )}
        {state.phase === "failed" && (
          <p role="alert" className={problem}>
            {t("error.access_owner")}
          </p>
        )}
      </section>
    </Panel>
  );
}
