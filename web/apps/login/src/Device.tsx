// RFC 8628 §3.3, OP-154 m.3 (p), TN-35: the verification page is a trusted surface of its own.
// The person enters the code a device shows, reads which app asks, for what and from where, and
// approves or declines while signed in. Every wrong code reads the same. Without an operator's
// IP-range list no country is known, and none is shown (OP-155 m.3 (l)).

import { Button } from "@access/ui/components/button";
import { Field, FieldLabel } from "@access/ui/components/field";
import { Input } from "@access/ui/components/input";
import { type SyntheticEvent, useEffect, useRef, useState } from "react";
import * as v from "valibot";

import { LOGIN, under } from "./base.js";
import { postJson } from "./http.js";
import { locale, maybe, t } from "./i18n.js";
import { inlineLink, outcome, Panel, primary, problem, quiet, stack, Title } from "./Layout.js";

// OP-159 m.46 (f)
const DevicePreview = v.looseObject({
  client: v.string(),
  scopes: v.array(v.string()),
  ip_prefix: v.string(),
  country: v.nullable(v.string()),
  account: v.optional(v.nullable(v.string()), null),
  csrf: v.string(),
});

type DevicePreview = Readonly<v.InferOutput<typeof DevicePreview>>;

/** TN-160: the code as shown on a device, upper case without spaces. */
function shown(code: string): string {
  return code.toUpperCase().replace(/\s+/g, "");
}

/** TN-160: a scope in words; an unknown one keeps its name. */
function scopeLabel(scope: string): string {
  return maybe(`scope.${scope}`) ?? scope;
}

/** TN-160: a country's name in the page's language; the code when the browser has none. */
function countryName(code: string): string {
  try {
    return new Intl.DisplayNames([locale], { type: "region" }).of(code) ?? code;
  } catch {
    return code;
  }
}

/** TN-160: the sign-in that comes back to this page with the code. */
function signInHere(code: string): string {
  const back = under(code === "" ? "/device" : `/device?user_code=${encodeURIComponent(code)}`);
  return `${LOGIN}?return_to=${encodeURIComponent(back)}`;
}

type State =
  | { readonly phase: "enter" }
  | { readonly phase: "ready"; readonly code: string; readonly preview: DevicePreview }
  | { readonly phase: "invalid" }
  | { readonly phase: "wait" }
  | { readonly phase: "approved" }
  | { readonly phase: "denied" }
  | { readonly phase: "failed" };

export function Device() {
  const initial = new URL(window.location.href).searchParams.get("user_code") ?? "";
  const [code, setCode] = useState(initial.toUpperCase());
  const [state, setState] = useState<State>({ phase: "enter" });
  const [busy, setBusy] = useState(false);
  const title = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    title.current?.focus();
  }, [state.phase]);

  const look = async (e: SyntheticEvent) => {
    e.preventDefault();
    setBusy(true);
    const a = await postJson("/v1/device/preview", { user_code: shown(code) }, DevicePreview);
    setBusy(false);
    if (a.ok) setState({ phase: "ready", code: shown(code), preview: a.body });
    // TN-160
    else if (a.status === 401) window.location.assign(signInHere(shown(code)));
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
                autoComplete="off"
                autoCapitalize="characters"
                spellCheck={false}
                className="font-mono tracking-widest"
                value={code}
                aria-invalid={state.phase === "invalid"}
                onChange={(e) => {
                  setCode(e.target.value.toUpperCase());
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
            <p data-testid="match">
              {t("device_code.match")}{" "}
              <strong className="font-mono tracking-widest">{state.code}</strong>
            </p>
            <p data-testid="request">{t("device_code.asks", { client: state.preview.client })}</p>
            <ul data-testid="scopes" className="-mt-2 list-disc space-y-1 ps-5">
              {state.preview.scopes.map((s) => (
                <li key={s} data-scope={s}>
                  {scopeLabel(s)}
                </li>
              ))}
            </ul>
            <p data-testid="origin" className="text-sm text-muted-foreground">
              {state.preview.country === null
                ? t("device_code.from_prefix", { prefix: state.preview.ip_prefix })
                : t("device_code.from", {
                    country: countryName(state.preview.country),
                    prefix: state.preview.ip_prefix,
                  })}
            </p>
            <p role="note" className={problem} data-testid="warning">
              {t("device_code.warning")}
            </p>
            {state.preview.account !== null && (
              <p data-testid="account" className="text-sm">
                {t("device_code.account", { account: state.preview.account })}{" "}
                <a className={inlineLink} href={signInHere(state.code)}>
                  {t("device_code.other_account")}
                </a>
              </p>
            )}
            <div className="flex flex-col gap-2">
              <Button {...primary} disabled={busy} onClick={() => void decide(state, true)}>
                {t("action.approve_access")}
              </Button>
              <Button {...quiet} disabled={busy} onClick={() => void decide(state, false)}>
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
        {state.phase === "failed" && (
          <p role="alert" className={problem}>
            {t("error.access_owner")}
          </p>
        )}
      </section>
    </Panel>
  );
}
