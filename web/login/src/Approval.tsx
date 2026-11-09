// §11.6, P58, EI-18, OP-154 m.3 (k), AS-M14, AG-6, AG-5: the consent screen of a client the realm
// did not register is the hosted Approval Surface. It shows the hostnames always and the client's
// name only as its own claim; approving is the person's own `grant.issue`, signed by their device
// Instance after the screen showed the Kernel's decoding. It never says Allow and never grants by
// itself: the record is kept only for the allowed Exercise.
import { useEffect, useRef, useState } from "react";

import { loadKernel } from "@esuiss/access";

import { LOGIN, under } from "./base.js";
import { follow, postJson, returnTo } from "./http.js";
import {
  account,
  b64url,
  type Decoded,
  decode,
  find,
  fromB64url,
  type Instance,
  NotSigned,
  register,
  type Session,
  sign,
} from "./device.js";
import { t } from "./i18n.js";

interface Draft {
  readonly domain: string;
  readonly intent: {
    readonly resources: readonly { readonly namespace: string; readonly path: readonly string[] }[];
  };
  readonly envelope: string;
  readonly payload: string;
  readonly basis: {
    readonly holding: { readonly grant: string; readonly holder: string; readonly since: number };
  };
}

/** What the consent screen shows (`POST /v1/login/approval/preview`). */
export interface ApprovalPreview {
  readonly client_id: string;
  readonly client_host: string;
  readonly client_says: string;
  readonly redirect_hosts: readonly string[];
  readonly loopback_only: boolean;
  readonly new_app: boolean;
  readonly visual_changed: boolean;
  readonly resource: string;
  readonly scopes: readonly string[];
  readonly csrf: string;
  readonly draft: Draft | null;
}

interface Redirect {
  readonly redirect_to: string;
}

type State =
  | { readonly phase: "loading" }
  | { readonly phase: "ready"; readonly preview: ApprovalPreview }
  | { readonly phase: "confirm"; readonly preview: ApprovalPreview; readonly decoded: Decoded }
  | { readonly phase: "sign_in" }
  | { readonly phase: "declined" }
  | { readonly phase: "failed" };

/** How long "You chose not to continue" stays before the app gets its answer. */
export const DECLINE_PAUSE_MS = 1500;

async function csrfPost<T>(path: string, csrf: string, body: unknown) {
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
  return (await r.json()) as T;
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
  const answer = await account<{ decision?: boolean; context?: { exercise?: string } }>(
    "/proxy/adp/evaluation",
    {
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
    },
  );
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
    void postJson<ApprovalPreview>("/v1/login/approval/preview", { return_to: back }).then((a) => {
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
      const session = await account<Session>("/session");
      const instance = (await find(session)) ?? (await register(session, ask));
      if (!(await ask(shown))) throw new NotSigned("cancelled");
      setBusy(true);
      const exercise = await commit(session, instance, draft, shown);
      const r = await csrfPost<Redirect>("/v1/login/approval", preview.csrf, {
        return_to: back,
        domain: draft.domain,
        exercise,
      });
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
      const r = await csrfPost<Redirect>("/v1/login/approval/decline", preview.csrf, {
        return_to: back,
      });
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
    <div className="card" aria-busy={state.phase === "loading" || busy}>
      <section aria-labelledby="approval-heading" data-kind="approval">
        <h1 id="approval-heading" ref={title} tabIndex={-1}>
          {preview === null
            ? t("consent.title")
            : t("consent.agent_title", { client: preview.client_host })}
        </h1>
        {state.phase === "loading" && <p role="status">{t("page.loading")}</p>}
        {preview !== null && (
          <>
            <p data-testid="client-says">
              {t("consent.client_says", { name: preview.client_says })}
            </p>
            <p data-testid="resource">{t("consent.resource", { resource: preview.resource })}</p>
            <ul aria-label={t("consent.redirect_host", { host: "" })}>
              {preview.redirect_hosts.map((h) => (
                <li key={h} data-testid="redirect-host">
                  {t("consent.redirect_host", { host: h })}
                </li>
              ))}
            </ul>
            {preview.loopback_only && (
              <p role="alert" className="warning" data-testid="loopback">
                {t("consent.loopback")}
              </p>
            )}
            {preview.visual_changed && (
              <p role="alert" className="warning" data-testid="visual-changed">
                {t("consent.visual_changed")}
              </p>
            )}
            {preview.new_app && (
              <p className="warning" data-testid="new-app">
                {t("consent.new_app")}
              </p>
            )}
          </>
        )}
        {state.phase === "ready" && (
          <>
            <button
              type="button"
              className="primary"
              disabled={busy || state.preview.draft === null}
              onClick={() => void approve(state.preview)}
            >
              {t("action.approve_access")}
            </button>
            <button
              type="button"
              className="secondary"
              disabled={busy}
              onClick={() => void decline(state.preview)}
            >
              {t("action.decline_access")}
            </button>
          </>
        )}
        {state.phase === "confirm" && (
          <div role="dialog" aria-labelledby="sign-heading" data-testid="signature">
            <h2 id="sign-heading">{t("action.approve_access")}</h2>
            <dl>
              <dt>{state.decoded.action}</dt>
              <dd>{state.decoded.until}</dd>
            </dl>
            <button
              type="button"
              className="primary"
              onClick={() => {
                confirmed.current?.(true);
              }}
            >
              {t("action.approve_access")}
            </button>
            <button
              type="button"
              className="secondary"
              onClick={() => {
                confirmed.current?.(false);
              }}
            >
              {t("action.decline_access")}
            </button>
          </div>
        )}
        {state.phase === "sign_in" && (
          <p role="alert">
            <a href={LOGIN}>{t("action.sign_in")}</a>
          </p>
        )}
        {state.phase === "declined" && (
          <p role="status" data-testid="declined">
            {t("page.access_denied")}
          </p>
        )}
        {state.phase === "failed" && <p role="alert">{t("error.access_owner")}</p>}
      </section>
    </div>
  );
}
