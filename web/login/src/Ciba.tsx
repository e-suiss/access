// OP-155 m.3 (l), IDP-14, §9.14.5 k.2, §10.5.3: the CIBA approval page of the hosted Approval
// Surface. A client asked to reach the person; the page names the client and its binding message,
// which the person compares with the client's screen and which binds nothing. Approving is the
// person's AAS: their device Instance signs the drafted `approve` contribution after the screen
// showed the Kernel's decoding, the hosted approval shows the decision point's render and takes
// one passkey assertion over H(AAS), and only then is the request answered.
import { useEffect, useRef, useState } from "react";

import { loadKernel } from "@esuiss/access";

import { LOGIN, under } from "./base.js";
import { type JsonAnswer, postJson } from "./http.js";
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
} from "./instance.js";
import type { PasskeyOptions } from "./contract.js";
import { getPasskey } from "./passkey.js";
import { t } from "./i18n.js";

interface Holding {
  readonly holding: { readonly grant: string; readonly holder: string; readonly since: number };
}

/** What a CIBA request asks (`POST /v1/ciba/preview`). */
export interface CibaPreview {
  readonly client: string;
  readonly binding_message: string | null;
  readonly scopes: readonly string[];
  readonly expires_at: number;
  readonly request: unknown;
  readonly redirect_uri: string;
  readonly contribution_basis: Holding | null;
  readonly domain: string;
  readonly contribution: {
    readonly class: string;
    readonly envelope: string;
    readonly valid_from: number;
    readonly valid_until: number;
  };
  readonly csrf: string;
}

interface RenderField {
  readonly name: string;
  readonly text: string;
  readonly material: boolean;
}

interface Started {
  readonly flow: string;
  readonly render: { readonly fields: readonly RenderField[] };
  readonly options: PasskeyOptions;
}

type State =
  | { readonly phase: "loading" }
  | { readonly phase: "ready"; readonly preview: CibaPreview }
  | { readonly phase: "confirm"; readonly preview: CibaPreview; readonly decoded: Decoded }
  | { readonly phase: "render"; readonly preview: CibaPreview; readonly started: Started }
  | { readonly phase: "sign_in" }
  | { readonly phase: "unknown" }
  | { readonly phase: "expired" }
  | { readonly phase: "approved"; readonly client: string }
  | { readonly phase: "denied" }
  | { readonly phase: "failed" };

/** The request the page answers, from the invitation's link. */
export function requestOf(search: string): string | null {
  const r = new URLSearchParams(search).get("request");
  return r !== null && /^[A-Za-z0-9_-]{1,64}$/.test(r) ? r : null;
}

async function answer(preview: CibaPreview, request: string, approval: string | null) {
  const r = await fetch(under("/v1/ciba/approval"), {
    method: "POST",
    credentials: "same-origin",
    cache: "no-store",
    redirect: "error",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
      "x-csrf-token": preview.csrf,
    },
    body: JSON.stringify(
      approval === null ? { request, approve: false } : { request, approve: true, approval },
    ),
  });
  if (!r.ok) throw new NotSigned(String(r.status));
}

function must<T>(a: JsonAnswer<T>): T {
  if (!a.ok) throw new NotSigned(a.code);
  return a.body;
}

/** The device-signed `approve` contribution over the drafted intent, pushed with the request. */
async function contribution(
  session: Session,
  instance: Instance,
  preview: CibaPreview,
  basis: Holding,
): Promise<unknown> {
  const k = await loadKernel();
  const envelope = fromB64url(preview.contribution.envelope);
  const h = basis.holding;
  const nonce = crypto.getRandomValues(new Uint8Array(16));
  const statement = k.aisStatement(
    fromB64url(preview.domain),
    nonce,
    k.intentDigest(envelope),
    "commit",
    session.pep,
    new Uint8Array(),
    k.exerciseBasis("holding", fromB64url(h.grant), fromB64url(h.holder), BigInt(h.since)),
    BigInt(Date.now()),
    new Uint8Array(),
  );
  return {
    nonce: b64url(nonce),
    class: preview.contribution.class,
    basis: h,
    valid_from: new Date(preview.contribution.valid_from).toISOString(),
    valid_until: new Date(preview.contribution.valid_until).toISOString(),
    ais: await sign(instance.key, k, instance.kid, statement),
  };
}

export function Ciba() {
  const request = requestOf(window.location.search);
  const [state, setState] = useState<State>(
    request === null ? { phase: "unknown" } : { phase: "loading" },
  );
  const [busy, setBusy] = useState(false);
  const title = useRef<HTMLHeadingElement>(null);
  const confirmed = useRef<((ok: boolean) => void) | null>(null);
  const pushed = useRef<{ uri: string; state: string } | null>(null);

  useEffect(() => {
    if (request === null) return;
    void postJson<CibaPreview>("/v1/ciba/preview", { request }).then((a) => {
      if (a.ok) setState({ phase: "ready", preview: a.body });
      else if (a.status === 401) setState({ phase: "sign_in" });
      else if (a.status === 410) setState({ phase: "expired" });
      else if (a.status === 404) setState({ phase: "unknown" });
      else setState({ phase: "failed" });
    });
  }, [request]);

  useEffect(() => {
    if (state.phase !== "loading") title.current?.focus();
  }, [state.phase]);

  const approve = async (preview: CibaPreview) => {
    const basis = preview.contribution_basis;
    if (request === null || basis === null) return;
    setBusy(true);
    try {
      const k = await loadKernel();
      const shown = decode(k, fromB64url(preview.contribution.envelope), preview.domain);
      if (shown.action !== "access.contribute") throw new NotSigned("mismatch");
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
      const signed = await contribution(session, instance, preview, basis);
      const push = must(
        await postJson<{ request_uri: string }>("/v1/approve/requests", {
          request: preview.request,
          contribution: signed,
        }),
      );
      const flowState = b64url(crypto.getRandomValues(new Uint8Array(8)));
      const started = must(
        await postJson<Started>("/v1/approve/flows", {
          request: push.request_uri,
          redirect_uri: preview.redirect_uri,
          state: flowState,
        }),
      );
      // OP-157 m.3 (l)
      if (typeof started.flow !== "string") throw new NotSigned("not approvable");
      pushed.current = { uri: push.request_uri, state: flowState };
      setState({ phase: "render", preview, started });
    } catch {
      setState({ phase: "failed" });
    } finally {
      setBusy(false);
    }
  };

  // §9.14.1 A steps 3 and 4
  const assert = async (preview: CibaPreview, started: Started) => {
    const p = pushed.current;
    if (request === null || p === null) return;
    setBusy(true);
    try {
      const credential = await getPasskey(started.options, undefined, new AbortController().signal);
      if (credential === null) throw new NotSigned("cancelled");
      must(
        await postJson(`/v1/approve/flows/${started.flow}`, {
          credential,
          redirect_uri: preview.redirect_uri,
          state: p.state,
        }),
      );
      await answer(preview, request, p.uri);
      setState({ phase: "approved", client: preview.client });
    } catch {
      setState({ phase: "failed" });
    } finally {
      setBusy(false);
    }
  };

  const decline = async (preview: CibaPreview) => {
    if (request === null) return;
    setBusy(true);
    try {
      await answer(preview, request, null);
      setState({ phase: "denied" });
    } catch {
      setState({ phase: "failed" });
    } finally {
      setBusy(false);
    }
  };

  const preview =
    state.phase === "ready" || state.phase === "confirm" || state.phase === "render"
      ? state.preview
      : null;
  return (
    <div className="card" aria-busy={state.phase === "loading" || busy}>
      <section aria-labelledby="ciba-heading" data-kind="ciba">
        <h1 id="ciba-heading" ref={title} tabIndex={-1}>
          {t("ciba.title", { client: preview?.client ?? "" })}
        </h1>
        {state.phase === "loading" && <p role="status">{t("page.loading")}</p>}
        {typeof preview?.binding_message === "string" && (
          <p data-testid="binding-message">
            {t("ciba.binding_message", {
              client: preview.client,
              code: preview.binding_message,
            })}
          </p>
        )}
        {state.phase === "ready" && (
          <>
            <button
              type="button"
              className="primary"
              disabled={busy || state.preview.contribution_basis === null}
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
        {state.phase === "render" && (
          <>
            <dl data-testid="render">
              {state.started.render.fields.map((f) => (
                <div key={f.name} data-material={f.material}>
                  <dt>{f.name}</dt>
                  <dd>{f.text}</dd>
                </div>
              ))}
            </dl>
            <button
              type="button"
              className="primary"
              disabled={busy}
              onClick={() => void assert(state.preview, state.started)}
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
        {state.phase === "approved" && (
          <p role="status" data-testid="approved">
            {t("ciba.approved", { client: state.client })}
          </p>
        )}
        {state.phase === "denied" && (
          <p role="status" data-testid="denied">
            {t("ciba.denied")}
          </p>
        )}
        {state.phase === "expired" && (
          <p role="alert" data-testid="expired">
            {t("ciba.expired")}
          </p>
        )}
        {state.phase === "sign_in" && (
          <p role="alert">
            <a href={LOGIN}>{t("action.sign_in")}</a>
          </p>
        )}
        {(state.phase === "unknown" || state.phase === "failed") && (
          <p role="alert">{t("error.access_owner")}</p>
        )}
      </section>
    </div>
  );
}
