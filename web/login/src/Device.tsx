// RFC 8628 §3.3, OP-154 m.3 (p), TN-35: the verification page is a trusted surface of its own.
// The person enters the code a device shows, reads which app asks, for what and from where, and
// approves or declines while signed in. Every wrong code reads the same. Without an operator's
// IP-range list no country is known, and none is shown (OP-155 m.3 (l)).
import { type SyntheticEvent, useEffect, useRef, useState } from "react";

import { Button } from "@suiss/access-ui/components/ui/button";
import { Field, FieldLabel } from "@suiss/access-ui/components/ui/field";
import { Input } from "@suiss/access-ui/components/ui/input";

import { LOGIN, under } from "./base.js";
import { postJson } from "./http.js";
import { t } from "./i18n.js";
import { inlineLink, outcome, Panel, primary, problem, quiet, stack, Title } from "./Layout.js";

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
    <Panel aria-busy={busy}>
      <section aria-labelledby="device-heading" data-kind="device" className={stack}>
        <Title id="device-heading" ref={title}>
          {t("device_code.title")}
        </Title>
        {(state.phase === "enter" || state.phase === "invalid" || state.phase === "wait") && (
          <form onSubmit={(e) => void look(e)} className={stack}>
            <Field className="gap-2">
              <FieldLabel htmlFor="user-code" className="text-sm">
                {t("label.device_code")}
              </FieldLabel>
              <Input
                id="user-code"
                name="user_code"
                autoComplete="one-time-code"
                autoCapitalize="characters"
                spellCheck={false}
                className="font-mono tracking-widest"
                value={code}
                aria-invalid={state.phase === "invalid"}
                onChange={(e) => {
                  setCode(e.target.value);
                }}
              />
            </Field>
            {state.phase === "invalid" && (
              <p role="alert" className={problem} data-testid="invalid">
                {t("device_code.invalid")}
              </p>
            )}
            {state.phase === "wait" && (
              <p role="alert" className={problem} data-testid="wait">
                {t("login.throttled")}
              </p>
            )}
            <Button type="submit" {...primary} disabled={busy || code.trim() === ""}>
              {t("action.continue")}
            </Button>
          </form>
        )}
        {state.phase === "ready" && (
          <>
            <p data-testid="request">
              {state.preview.country === null
                ? t("device_code.request_prefix", {
                    client: state.preview.client,
                    scope: state.preview.scopes.join(" "),
                    prefix: state.preview.ip_prefix,
                  })
                : t("device_code.request", {
                    client: state.preview.client,
                    scope: state.preview.scopes.join(" "),
                    prefix: state.preview.ip_prefix,
                    country: state.preview.country,
                  })}
            </p>
            <div className="flex flex-col gap-2">
              <Button {...primary} disabled={busy} onPress={() => void decide(state, true)}>
                {t("action.approve_access")}
              </Button>
              <Button {...quiet} disabled={busy} onPress={() => void decide(state, false)}>
                {t("action.decline_access")}
              </Button>
            </div>
          </>
        )}
        {state.phase === "approved" && (
          <p role="status" className={outcome} data-testid="approved">
            {t("device_code.approved")}
          </p>
        )}
        {state.phase === "denied" && (
          <p role="status" className={outcome} data-testid="denied">
            {t("device_code.denied")}
          </p>
        )}
        {state.phase === "sign_in" && (
          <p role="alert">
            <a className={inlineLink} href={LOGIN}>
              {t("action.sign_in")}
            </a>
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
