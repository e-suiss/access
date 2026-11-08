// OP-153 m.3 (z), §8.8, X27: "Share with *App*" lists the identity claims a third-party app asks
// for; it never says Allow or Authorize and never grants authority (that is RAR, S1).
import { useEffect, useRef, useState } from "react";

import { LOGIN } from "./base.js";
import { follow, postJson } from "./http.js";
import { maybe, t } from "./i18n.js";

interface Preview {
  readonly client_id: string;
  readonly app: string;
  readonly claims: readonly string[];
}

interface Redirect {
  readonly redirect_to: string;
}

type State =
  | { readonly phase: "loading" }
  | { readonly phase: "ready"; readonly preview: Preview }
  | { readonly phase: "sign_in" }
  | { readonly phase: "declined" }
  | { readonly phase: "failed" };

/** How long "You chose not to continue" stays before the app gets its answer. */
export const DECLINE_PAUSE_MS = 1500;

/** The request to return to: on this origin only. */
export function sameOrigin(value: string | null): string | null {
  if (value === null) return null;
  try {
    const url = new URL(value, window.location.origin);
    return url.origin === window.location.origin ? url.href : null;
  } catch {
    return null;
  }
}

function claimLabel(claim: string): string {
  return maybe(`claim.${claim}`) ?? claim;
}

export function Consent() {
  const returnTo = sameOrigin(new URL(window.location.href).searchParams.get("return_to"));
  const [state, setState] = useState<State>(
    returnTo === null ? { phase: "failed" } : { phase: "loading" },
  );
  const [busy, setBusy] = useState(false);
  const title = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    if (returnTo === null) return;
    void postJson<Preview>("/v1/account/connected-apps/preview", { return_to: returnTo }).then(
      (a) => {
        if (a.ok) setState({ phase: "ready", preview: a.body });
        else if (a.status === 401) setState({ phase: "sign_in" });
        else setState({ phase: "failed" });
      },
    );
  }, [returnTo]);

  useEffect(() => {
    if (state.phase !== "loading") title.current?.focus();
  }, [state.phase]);

  const share = async () => {
    if (returnTo === null) return;
    setBusy(true);
    const a = await postJson<Redirect>("/v1/account/connected-apps", { return_to: returnTo });
    setBusy(false);
    if (a.ok) follow(a.body.redirect_to);
    else setState({ phase: "failed" });
  };

  // X-L8
  const decline = async () => {
    if (returnTo === null) return;
    setBusy(true);
    const a = await postJson<Redirect>("/v1/account/connected-apps/decline", {
      return_to: returnTo,
    });
    setBusy(false);
    if (!a.ok) {
      setState({ phase: "failed" });
      return;
    }
    setState({ phase: "declined" });
    window.setTimeout(() => {
      follow(a.body.redirect_to);
    }, DECLINE_PAUSE_MS);
  };

  const app = state.phase === "ready" ? state.preview.app : "";
  return (
    <div className="card" aria-busy={state.phase === "loading" || busy}>
      <section aria-labelledby="consent-heading" data-kind="consent">
        <h1 id="consent-heading" ref={title} tabIndex={-1}>
          {state.phase === "ready" ? t("page.consent_title", { app }) : t("consent.title")}
        </h1>
        {state.phase === "loading" && <p role="status">{t("page.loading")}</p>}
        {state.phase === "ready" && (
          <>
            <p id="claims-label">{t("consent.claims")}</p>
            <ul aria-labelledby="claims-label" className="claims">
              {state.preview.claims.map((c) => (
                <li key={c} data-claim={c}>
                  {claimLabel(c)}
                </li>
              ))}
            </ul>
            <p className="info">{t("page.consent_stop")}</p>
            <button type="button" className="primary" disabled={busy} onClick={() => void share()}>
              {t("action.share")}
            </button>
            <button
              type="button"
              className="secondary"
              disabled={busy}
              onClick={() => void decline()}
            >
              {t("action.dont_share")}
            </button>
          </>
        )}
        {state.phase === "declined" && (
          <p role="status" data-testid="declined">
            {t("page.access_denied")}
          </p>
        )}
        {state.phase === "sign_in" && (
          <p role="alert">
            <a href={LOGIN}>{t("action.sign_in")}</a>
          </p>
        )}
        {state.phase === "failed" && <p role="alert">{t("error.access_owner")}</p>}
      </section>
    </div>
  );
}
