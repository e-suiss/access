// OP-159 m.47 (c), (f), TN-89, TN-141: a tenant's founding and an administrator's invitation. The link
// names the invitation; the magic code rides in the address's fragment, which never reaches a
// server, and is dropped from the address once read. The person proves the address with the code,
// chooses a password, and the browser makes its own device key; only the public key is sent. The
// tenant's name is the tenant's text, shown as text (TN-131). Opening the page consumes nothing.

import { Button } from "@access/ui/components/button";
import { Field, FieldLabel } from "@access/ui/components/field";
import { Input } from "@access/ui/components/input";
import { type SyntheticEvent, useEffect, useRef, useState } from "react";
import type * as v from "valibot";

import { ENVIRONMENT, LOGIN } from "./base.js";
import { makeKey } from "./founder.js";
import { Empty, getJson, type JsonAnswer, postJson } from "./http.js";
import { t } from "./i18n.js";
import { link, note, outcome, Panel, primary, problem, stack, Title } from "./Layout.js";

/** What an invitation is, as its page needs it. */
export interface Invited {
  /** The tenant's name. */
  readonly name: string;
  /** A refusal text id when the invitation can no longer be used. */
  readonly closed?: string;
}

/** One kind of invitation: its routes, how its view reads, and its texts. */
export interface Kind<S extends v.GenericSchema> {
  readonly kind: "founding" | "admin_invite";
  /** The path segment after `/login/` and `/v1/`. */
  readonly page: string;
  readonly api: string;
  readonly finish: "complete" | "accept";
  readonly purpose: "founder" | "admin";
  readonly view: S;
  readonly read: (view: v.InferOutput<S>) => Invited;
  /** Refusal texts by problem code. */
  readonly refusals: Readonly<Record<string, string>>;
}

type State =
  | { readonly phase: "loading" }
  | { readonly phase: "address"; readonly name: string }
  | { readonly phase: "password"; readonly name: string; readonly email: string }
  | { readonly phase: "done"; readonly name: string }
  | { readonly phase: "refused"; readonly text: string };

const shared: Readonly<Record<string, string>> = {
  "not-found": "onboarding.not_found",
  "invalid-code": "onboarding.code_failed",
  "invalid-email": "onboarding.code_failed",
  "invalid-password": "onboarding.password_refused",
  "key-invalid": "onboarding.key_failed",
};

const TOKEN = /^[A-Za-z0-9_-]{1,256}$/;

/** The invitation token in `/login/{page}/{token}`. */
export function tokenOf(page: string, path: string): string | null {
  const m = new RegExp(`/login/${page}/([^/]+)/?$`).exec(path);
  const token = m?.[1];
  return token !== undefined && TOKEN.test(token) ? token : null;
}

/** The magic code in the fragment `#code=…`; the fragment is dropped from the address. */
function takeCode(): string {
  const code = new URLSearchParams(window.location.hash.slice(1)).get("code") ?? "";
  if (window.location.hash !== "") {
    window.history.replaceState(null, "", window.location.pathname + window.location.search);
  }
  return /^[A-Za-z0-9_-]{1,64}$/.test(code) ? code : "";
}

const name = "text-lg font-semibold wrap-anywhere";

function refusalOf<S extends v.GenericSchema>(kind: Kind<S>, a: JsonAnswer<unknown>): string {
  if (a.ok) return "error.access_owner";
  if (a.status === 429) return "login.throttled";
  return kind.refusals[a.code] ?? shared[a.code] ?? "error.access_owner";
}

/** Where this environment's keys are filed: its slug, or its host at a host issuer. */
const SLUG = ENVIRONMENT === "" ? window.location.host : ENVIRONMENT.slice("/env/".length);

export function Onboarding<S extends v.GenericSchema>({ kind }: { readonly kind: Kind<S> }) {
  const [token] = useState(() => tokenOf(kind.page, window.location.pathname));
  const [code, setCode] = useState(takeCode);
  const [state, setState] = useState<State>(
    token === null ? { phase: "refused", text: "onboarding.not_found" } : { phase: "loading" },
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const title = useRef<HTMLHeadingElement>(null);
  const base = token === null ? "" : `/v1/${kind.api}/${encodeURIComponent(token)}`;

  const refusal = (a: JsonAnswer<unknown>) => refusalOf(kind, a);

  useEffect(() => {
    if (token === null) return;
    void getJson(`/v1/${kind.api}/${encodeURIComponent(token)}`, kind.view).then((a) => {
      if (!a.ok) {
        setState({ phase: "refused", text: refusalOf(kind, a) });
        return;
      }
      const invited = kind.read(a.body);
      setState(
        invited.closed === undefined
          ? { phase: "address", name: invited.name }
          : { phase: "refused", text: invited.closed },
      );
    });
  }, [token, kind]);

  useEffect(() => {
    if (state.phase !== "loading") title.current?.focus();
  }, [state.phase]);

  const field = (e: SyntheticEvent<HTMLFormElement>, n: string): string => {
    const value = new FormData(e.currentTarget).get(n);
    return typeof value === "string" ? value.trim() : "";
  };

  const verify = async (e: SyntheticEvent<HTMLFormElement>, at: string) => {
    e.preventDefault();
    const email = field(e, "email");
    const typed = code === "" ? field(e, "code") : code;
    if (email === "" || typed === "") return;
    setBusy(true);
    setError(null);
    const a = await postJson(`${base}/verify`, { email, code: typed }, Empty);
    setBusy(false);
    if (a.ok) {
      setCode(typed);
      setState({ phase: "password", name: at, email });
    } else if (a.code === "invalid-code" || a.code === "invalid-email") {
      setError("onboarding.code_failed");
    } else {
      setState({ phase: "refused", text: refusal(a) });
    }
  };

  const finish = async (e: SyntheticEvent<HTMLFormElement>, at: string, email: string) => {
    e.preventDefault();
    const password = new FormData(e.currentTarget).get("new_password");
    if (typeof password !== "string" || password === "") return;
    setBusy(true);
    setError(null);
    let device: string;
    try {
      device = (await makeKey(SLUG, kind.purpose)).cose;
    } catch {
      setBusy(false);
      setError("onboarding.key_failed");
      return;
    }
    const a = await postJson(
      `${base}/${kind.finish}`,
      { email, code, password, device_key: device },
      Empty,
    );
    setBusy(false);
    if (a.ok) setState({ phase: "done", name: at });
    else if (a.code === "invalid-password") setError("onboarding.password_refused");
    else setState({ phase: "refused", text: refusal(a) });
  };

  const known = state.phase === "address" || state.phase === "password" || state.phase === "done";

  return (
    <Panel aria-busy={state.phase === "loading" || busy}>
      <section aria-labelledby="onboarding-heading" data-kind={kind.kind} className={stack}>
        <Title id="onboarding-heading" ref={title}>
          {known ? t(`${kind.kind}.title`, { name: state.name }) : t(`${kind.kind}.heading`)}
        </Title>
        {state.phase === "loading" && (
          <p role="status" className={note}>
            {t("page.loading")}
          </p>
        )}
        {known && (
          <p className={name} data-testid="tenant-name">
            {state.name}
          </p>
        )}
        {error !== null && (
          <p role="alert" className={problem} data-message-id={error}>
            {t(error)}
          </p>
        )}
        {state.phase === "address" && (
          <form
            className={stack}
            onSubmit={(e) => {
              void verify(e, state.name);
            }}
          >
            <p className={note}>{t(`${kind.kind}.intro`)}</p>
            <Field className="gap-2">
              <FieldLabel htmlFor="onboarding-email" className="text-sm">
                {t("label.email")}
              </FieldLabel>
              <Input
                id="onboarding-email"
                name="email"
                type="email"
                autoComplete="email"
                required
                maxLength={320}
                spellCheck={false}
                autoCapitalize="none"
              />
            </Field>
            {code === "" && (
              <Field className="gap-2">
                <FieldLabel htmlFor="onboarding-code" className="text-sm">
                  {t("label.onboarding_code")}
                </FieldLabel>
                <Input
                  id="onboarding-code"
                  name="code"
                  type="text"
                  autoComplete="one-time-code"
                  required
                  maxLength={64}
                  spellCheck={false}
                  autoCapitalize="none"
                  className="font-mono tracking-widest"
                />
              </Field>
            )}
            <Button type="submit" {...primary} disabled={busy}>
              {t("action.continue")}
            </Button>
          </form>
        )}
        {state.phase === "password" && (
          <form
            className={stack}
            onSubmit={(e) => {
              void finish(e, state.name, state.email);
            }}
          >
            <p className={note}>{t(`${kind.kind}.password_intro`, { email: state.email })}</p>
            <Field className="gap-2">
              <FieldLabel htmlFor="onboarding-password" className="text-sm">
                {t("label.new_password")}
              </FieldLabel>
              <Input
                id="onboarding-password"
                name="new_password"
                type="password"
                autoComplete="new-password"
                required
                maxLength={256}
              />
            </Field>
            <p className={note}>{t("onboarding.key_note")}</p>
            <Button type="submit" {...primary} disabled={busy}>
              {t(`action.${kind.kind}_finish`)}
            </Button>
          </form>
        )}
        {state.phase === "done" && (
          <>
            <p role="status" className={outcome} data-testid="onboarding-done">
              {t(`${kind.kind}.done`, { name: state.name })}
            </p>
            <p className={note}>{t("onboarding.second_step")}</p>
            <a className={link} href={LOGIN}>
              {t("action.sign_in")}
            </a>
          </>
        )}
        {state.phase === "refused" && (
          <p role="alert" className={problem} data-message-id={state.text}>
            {t(state.text)}
          </p>
        )}
      </section>
    </Panel>
  );
}
