// RFC 8628 §3.3, OP-154 m.3 (p), TN-35: the verification page is a trusted surface of its own.
// The person enters the code a device shows, reads which app asks, for what and from where, and
// approves or declines while signed in. Every wrong code reads the same.
import { type SyntheticEvent, useEffect, useRef, useState } from "react";

import { LOGIN, under } from "./base.js";
import { postJson } from "./http.js";
import { t } from "./i18n.js";

interface DevicePreview {
  readonly client: string;
  readonly scopes: readonly string[];
  readonly ip_prefix: string;
  readonly country: string | null;
  readonly csrf: string;
}

type State =
  | { readonly phase: "enter" }
  | { readonly phase: "ready"; readonly code: string; readonly preview: DevicePreview }
  | { readonly phase: "invalid" }
  | { readonly phase: "wait" }
  | { readonly phase: "sign_in" }
  | { readonly phase: "approved" }
  | { readonly phase: "denied" }
  | { readonly phase: "failed" };

export function Device() {
  const initial = new URL(window.location.href).searchParams.get("user_code") ?? "";
  const [code, setCode] = useState(initial);
  const [state, setState] = useState<State>({ phase: "enter" });
  const [busy, setBusy] = useState(false);
  const title = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    title.current?.focus();
  }, [state.phase]);

  const look = async (e: SyntheticEvent) => {
    e.preventDefault();
    setBusy(true);
    const a = await postJson<DevicePreview>("/v1/device/preview", { user_code: code });
    setBusy(false);
    if (a.ok) setState({ phase: "ready", code, preview: a.body });
    else if (a.status === 401) setState({ phase: "sign_in" });
    else if (a.status === 429) setState({ phase: "wait" });
    else if (a.status === 404) setState({ phase: "invalid" });
    else setState({ phase: "failed" });
  };

  const decide = async (ready: Extract<State, { phase: "ready" }>, approve: boolean) => {
    setBusy(true);
    try {
      const r = await fetch(under("/v1/device/approval"), {
        method: "POST",
        credentials: "same-origin",
        cache: "no-store",
        redirect: "error",
        headers: {
          accept: "application/json",
          "content-type": "application/json",
          "x-csrf-token": ready.preview.csrf,
        },
        body: JSON.stringify({ user_code: ready.code, approve }),
      });
      if (r.ok) setState({ phase: approve ? "approved" : "denied" });
      else if (r.status === 404) setState({ phase: "invalid" });
      else setState({ phase: "failed" });
    } catch {
      setState({ phase: "failed" });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card" aria-busy={busy}>
      <section aria-labelledby="device-heading" data-kind="device">
        <h1 id="device-heading" ref={title} tabIndex={-1}>
          {t("device_code.title")}
        </h1>
        {(state.phase === "enter" || state.phase === "invalid" || state.phase === "wait") && (
          <form onSubmit={(e) => void look(e)}>
            <label htmlFor="user-code">{t("label.device_code")}</label>
            <input
              id="user-code"
              name="user_code"
              autoComplete="one-time-code"
              autoCapitalize="characters"
              spellCheck={false}
              value={code}
              aria-invalid={state.phase === "invalid"}
              onChange={(e) => {
                setCode(e.target.value);
              }}
            />
            {state.phase === "invalid" && (
              <p role="alert" data-testid="invalid">
                {t("device_code.invalid")}
              </p>
            )}
            {state.phase === "wait" && (
              <p role="alert" data-testid="wait">
                {t("login.throttled")}
              </p>
            )}
            <button type="submit" className="primary" disabled={busy || code.trim() === ""}>
              {t("action.continue")}
            </button>
          </form>
        )}
        {state.phase === "ready" && (
          <>
            <p data-testid="request">
              {t("device_code.request", {
                client: state.preview.client,
                scope: state.preview.scopes.join(" "),
                prefix: state.preview.ip_prefix,
                country: state.preview.country ?? "?",
              })}
            </p>
            <button
              type="button"
              className="primary"
              disabled={busy}
              onClick={() => void decide(state, true)}
            >
              {t("action.approve_access")}
            </button>
            <button
              type="button"
              className="secondary"
              disabled={busy}
              onClick={() => void decide(state, false)}
            >
              {t("action.decline_access")}
            </button>
          </>
        )}
        {state.phase === "approved" && (
          <p role="status" data-testid="approved">
            {t("device_code.approved")}
          </p>
        )}
        {state.phase === "denied" && (
          <p role="status" data-testid="denied">
            {t("device_code.denied")}
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
