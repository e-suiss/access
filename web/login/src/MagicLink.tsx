// §10.2.2, TN-102 rule 6, OP-146 m.14 (h): opening the link consumes nothing; a person confirms
// with a POST, and another browser must say so explicitly. The session goes only to the browser
// that started the sign-in, which is waiting and continues on its own.
import { useEffect, useRef, useState } from "react";

import { postJson } from "./http.js";
import { t } from "./i18n.js";

interface LinkState {
  readonly state: "confirm" | "confirmed" | "needs_confirmation";
  readonly same_device?: boolean;
}

type State =
  | { readonly phase: "loading" }
  | { readonly phase: "confirm"; readonly sameDevice: boolean }
  | { readonly phase: "done"; readonly sameDevice: boolean }
  | { readonly phase: "invalid" }
  | { readonly phase: "failed" };

/** The token rides in the fragment, so it never reaches a server log or a referrer. */
function takeToken(): string | null {
  const token = window.location.hash.replace(/^#/, "");
  if (token !== "") window.history.replaceState(null, "", window.location.pathname);
  return /^[A-Za-z0-9_-]{1,128}$/.test(token) ? token : null;
}

export function MagicLink() {
  const [token] = useState(takeToken);
  const [state, setState] = useState<State>(
    token === null ? { phase: "invalid" } : { phase: "loading" },
  );
  const [busy, setBusy] = useState(false);
  const title = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    if (token === null) return;
    void postJson<LinkState>("/v1/login/link/preview", { token }).then((a) => {
      if (a.ok && a.body.state === "confirm")
        setState({ phase: "confirm", sameDevice: a.body.same_device === true });
      else if (!a.ok && (a.status === 410 || a.status === 400)) setState({ phase: "invalid" });
      else setState({ phase: "failed" });
    });
  }, [token]);

  useEffect(() => {
    if (state.phase !== "loading") title.current?.focus();
  }, [state.phase]);

  const confirm = async (otherDevice: boolean) => {
    if (token === null) return;
    setBusy(true);
    const a = await postJson<LinkState>("/v1/login/link/confirm", {
      token,
      other_device: otherDevice,
    });
    setBusy(false);
    if (!a.ok) {
      setState(a.status === 410 || a.status === 400 ? { phase: "invalid" } : { phase: "failed" });
    } else if (a.body.state === "confirmed") {
      setState({ phase: "done", sameDevice: a.body.same_device === true });
    } else {
      setState({ phase: "confirm", sameDevice: false });
    }
  };

  return (
    <div className="card" aria-busy={state.phase === "loading" || busy}>
      <section aria-labelledby="link-heading" data-kind="magic_link">
        <h1 id="link-heading" ref={title} tabIndex={-1}>
          {t("page.link_title")}
        </h1>
        {state.phase === "loading" && <p role="status">{t("page.loading")}</p>}
        {state.phase === "confirm" && (
          <>
            {!state.sameDevice && <p className="info">{t("page.link_other_device")}</p>}
            <button
              type="button"
              className="primary"
              disabled={busy}
              onClick={() => void confirm(!state.sameDevice)}
            >
              {t("page.link_confirm")}
            </button>
          </>
        )}
        {state.phase === "done" && (
          <p role="status" data-testid="link-done">
            {state.sameDevice ? t("page.link_done_here") : t("page.link_done_elsewhere")}
          </p>
        )}
        {state.phase === "invalid" && <p role="alert">{t("page.link_invalid")}</p>}
        {state.phase === "failed" && <p role="alert">{t("login.unavailable")}</p>}
      </section>
    </div>
  );
}
