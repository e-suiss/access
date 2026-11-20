// §12.3.2, TN-54, TN-55, OP-153 m.3 (d), (e): recovery answers the same whether or not an
// account exists, says when the waiting period ends, and claims no more than the server's text
// (X38). The attempt rides in an HttpOnly cookie; the page keeps only the attempt id.

import { Button } from "@access/ui/components/button";
import { Field as FieldBox, FieldLabel, FieldLegend, FieldSet } from "@access/ui/components/field";
import { Input } from "@access/ui/components/input";
import { PasswordInput } from "@access/ui/components/password-input";
import { RadioGroup, RadioGroupItem } from "@access/ui/components/radio-group";
import { type SyntheticEvent, useEffect, useRef, useState } from "react";
import * as v from "valibot";
import { useBranding } from "./Branding.js";
import { LOGIN } from "./base.js";
import { getJson, type JsonAnswer, postJson } from "./http.js";
import { passwordWords, t, when } from "./i18n.js";
import { link, note, Panel, pressable, primary, problem, quiet, stack, Title } from "./Layout.js";

// OP-159 m.46 (f)
/** One attempt as `/v1/recovery` answers it. */
const Attempt = v.looseObject({
  attempt: v.exactOptional(v.string()),
  state: v.exactOptional(v.string()),
  method: v.exactOptional(v.string()),
  text: v.exactOptional(v.string()),
  until: v.exactOptional(v.string()),
  replacement_code: v.exactOptional(v.string()),
  sensitive_actions_after: v.exactOptional(v.string()),
  authenticator_removed: v.exactOptional(v.boolean()),
});

export type Attempt = Readonly<v.InferOutput<typeof Attempt>>;

type Path = "registered_code" | "sent_code";

/** TN-168: what the sign-in page hands the recovery page when "Can't sign in?" is followed. */
export const RECOVER_IDENTIFIER = "access.login.recover";

/** The identifier typed on the sign-in page, read once. */
function handedIdentifier(): string {
  try {
    const typed = window.sessionStorage.getItem(RECOVER_IDENTIFIER);
    window.sessionStorage.removeItem(RECOVER_IDENTIFIER);
    return typed ?? "";
  } catch {
    return "";
  }
}

const identifierLabels = {
  email: "label.identifier",
  email_or_phone: "label.identifier_phone",
  phone: "label.phone",
} as const;

type State =
  | { readonly phase: "start" }
  | { readonly phase: "attempt"; readonly attempt: Attempt }
  | { readonly phase: "failed"; readonly text: string };

const refusals: Readonly<Record<string, string>> = {
  "recovery-throttled": "login.throttled",
};

/** The new secret the environment uses: a password, or a six-digit PIN (TN-157, TN-168). */
type Secret = "password" | "pin";

function problemText(a: JsonAnswer<unknown>): string {
  if (a.ok) return "login.unavailable";
  if (a.status === 429) return "login.throttled";
  return (
    refusals[a.code] ??
    (a.status === 0 || a.status >= 500 ? "login.unavailable" : "page.recovery_refused")
  );
}

const methods = [
  ["registered_code", "page.recovery_registered_code"],
  ["sent_code", "page.recovery_sent_code"],
] as const;

function Field(props: {
  readonly name: string;
  readonly label: string;
  readonly type?: "text" | "password" | "tel";
  readonly autoComplete: string;
  readonly numeric?: boolean;
  readonly code?: boolean;
  readonly maxLength: number;
  readonly defaultValue?: string;
  readonly hint?: string;
  readonly error?: string;
}) {
  const id = `recovery-${props.name}`;
  const hintId = `${id}-hint`;
  const errorId = `${id}-error`;
  const describedBy = [
    props.error === undefined ? "" : errorId,
    props.hint === undefined ? "" : hintId,
  ]
    .filter((x) => x !== "")
    .join(" ");
  const described = describedBy === "" ? {} : { "aria-describedby": describedBy };
  const invalid = props.error === undefined ? {} : { "aria-invalid": true as const };
  return (
    <FieldBox className="gap-2">
      <FieldLabel htmlFor={id} className="text-sm">
        {props.label}
      </FieldLabel>
      {props.type === "password" ? (
        <PasswordInput
          id={id}
          name={props.name}
          autoComplete={props.autoComplete}
          required
          maxLength={props.maxLength}
          spellCheck={false}
          autoCapitalize="none"
          dir="auto"
          words={passwordWords()}
          autoFocus={props.error !== undefined}
          {...(props.numeric === true ? { inputMode: "numeric" as const } : {})}
          {...described}
          {...invalid}
        />
      ) : (
        <Input
          id={id}
          name={props.name}
          type={props.type === "tel" ? "tel" : "text"}
          {...(props.defaultValue === undefined ? {} : { defaultValue: props.defaultValue })}
          autoComplete={props.autoComplete}
          required
          maxLength={props.maxLength}
          spellCheck={false}
          autoCapitalize="none"
          dir="auto"
          {...(props.numeric === true ? { inputMode: "numeric" as const } : {})}
          {...(props.code === true ? { className: "font-mono tracking-widest" } : {})}
        />
      )}
      {props.error !== undefined && (
        <p id={errorId} role="alert" className={problem}>
          {props.error}
        </p>
      )}
      {props.hint !== undefined && (
        <p id={hintId} className={note}>
          {props.hint}
        </p>
      )}
    </FieldBox>
  );
}

function value(event: SyntheticEvent<HTMLFormElement>, name: string): string {
  const v = new FormData(event.currentTarget).get(name);
  return typeof v === "string" ? v : "";
}

export function Recovery() {
  const [state, setState] = useState<State>({ phase: "start" });
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);
  const [handed] = useState(handedIdentifier);
  const [who, setWho] = useState("");
  const [refused, setRefused] = useState<{ readonly text: string; readonly tries: number } | null>(
    null,
  );
  const signIn = useBranding()?.sign_in;
  const secret: Secret = signIn?.secret ?? "password";
  const title = useRef<HTMLHeadingElement>(null);
  const first = useRef(true);
  const phase = state.phase === "attempt" ? (state.attempt.state ?? "") : state.phase;

  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    title.current?.focus();
  }, [phase]);

  const settle = (a: JsonAnswer<Attempt>, keep?: Attempt) => {
    if (a.ok) setState({ phase: "attempt", attempt: { ...keep, ...a.body } });
    else setState({ phase: "failed", text: problemText(a) });
  };

  const run = async (call: () => Promise<JsonAnswer<Attempt>>, keep?: Attempt) => {
    setBusy(true);
    const a = await call();
    setBusy(false);
    settle(a, keep);
  };

  const start = (event: SyntheticEvent<HTMLFormElement>) => {
    event.preventDefault();
    const identifier = value(event, "identifier");
    setWho(identifier.trim());
    const method = value(event, "method") as Path;
    void run(() => postJson("/v1/recovery", { identifier, method }, Attempt));
  };

  // TN-168: a refused new secret stays on the attempt and says why
  const bind = async (attempt: Attempt, newPassword: string) => {
    const id = attempt.attempt ?? "";
    setBusy(true);
    const a = await postJson(
      `/v1/recovery/${encodeURIComponent(id)}`,
      { new_password: newPassword },
      Attempt,
    );
    setBusy(false);
    if (!a.ok && a.code === "password-rejected") {
      setRefused((r) => ({
        text: secret === "pin" ? "page.recovery_pin_rejected" : "page.recovery_password_rejected",
        tries: (r?.tries ?? 0) + 1,
      }));
      return;
    }
    setRefused(null);
    settle(a, attempt);
  };

  const step = (attempt: Attempt, body: Record<string, unknown>) => {
    const id = attempt.attempt ?? "";
    void run(() => postJson(`/v1/recovery/${encodeURIComponent(id)}`, body, Attempt), attempt);
  };

  const refresh = (attempt: Attempt) => {
    const id = attempt.attempt ?? "";
    void run(() => getJson(`/v1/recovery/${encodeURIComponent(id)}`, Attempt), attempt);
  };

  const extend = (attempt: Attempt) => {
    const id = attempt.attempt ?? "";
    void run(
      () => postJson(`/v1/recovery/${encodeURIComponent(id)}/extension`, {}, Attempt),
      attempt,
    );
  };

  return (
    <Panel aria-busy={busy}>
      <section
        aria-labelledby="recovery-heading"
        data-kind="recovery"
        data-state={phase}
        className={stack}
      >
        <Title id="recovery-heading" ref={title}>
          {t("recovery.title")}
        </Title>
        {state.phase === "start" && (
          <form onSubmit={start} className={stack}>
            <Field
              name="identifier"
              label={t(identifierLabels[signIn?.identifier ?? "email"])}
              {...(signIn?.identifier === "phone" ? { type: "tel" as const } : {})}
              autoComplete="username"
              maxLength={320}
              defaultValue={handed}
            />
            <FieldSet className="gap-3">
              <FieldLegend id="recovery-method" variant="label" className="mb-0">
                {t("page.recovery_method")}
              </FieldLegend>
              <RadioGroup
                name="method"
                defaultValue="registered_code"
                aria-labelledby="recovery-method"
              >
                {methods.map(([m, label]) => (
                  <FieldBox key={m} orientation="horizontal">
                    <RadioGroupItem
                      className={pressable}
                      id={`method-${m}`}
                      value={m}
                      aria-labelledby={`method-${m}-label`}
                    />
                    <FieldLabel
                      id={`method-${m}-label`}
                      htmlFor={`method-${m}`}
                      className="min-h-6 text-sm font-normal"
                    >
                      {t(label)}
                    </FieldLabel>
                  </FieldBox>
                ))}
              </RadioGroup>
            </FieldSet>
            <Button type="submit" {...primary} disabled={busy}>
              {t("action.recovery_start")}
            </Button>
            {signIn?.email_code === true && (
              <p className="text-sm">
                <a className={link} href={LOGIN} data-testid="email-code-instead">
                  {t("page.recovery_email_code_instead")}
                </a>
              </p>
            )}
          </form>
        )}
        {state.phase === "attempt" && (
          <AttemptView
            attempt={state.attempt}
            busy={busy}
            sent={sent}
            onSend={() => {
              setSent(true);
              step(state.attempt, { send: "sent_code" });
            }}
            onCode={(code) => {
              step(state.attempt, { code });
            }}
            onContinue={() => {
              step(state.attempt, { resume: true });
            }}
            onRefresh={() => {
              refresh(state.attempt);
            }}
            onExtend={() => {
              extend(state.attempt);
            }}
            secret={secret}
            who={who}
            refused={refused}
            onPassword={(newPassword) => {
              void bind(state.attempt, newPassword);
            }}
          />
        )}
        {state.phase === "failed" && (
          <>
            <p role="alert" className={problem}>
              {t(state.text)}
            </p>
            <Button
              {...quiet}
              onClick={() => {
                setState({ phase: "start" });
              }}
            >
              {t("action.restart")}
            </Button>
          </>
        )}
        <p>
          <a className={link} href={LOGIN}>
            {t("action.have_account")}
          </a>
        </p>
      </section>
    </Panel>
  );
}

function AttemptView(props: {
  readonly attempt: Attempt;
  readonly busy: boolean;
  readonly sent: boolean;
  readonly onSend: () => void;
  readonly onCode: (code: string) => void;
  readonly onContinue: () => void;
  readonly onRefresh: () => void;
  readonly onExtend: () => void;
  readonly onPassword: (newPassword: string) => void;
  readonly secret: Secret;
  readonly who: string;
  readonly refused: { readonly text: string; readonly tries: number } | null;
}) {
  const a = props.attempt;
  const pin = props.secret === "pin";
  const textId = a.text ?? "recovery.requested";
  const proving = a.state === "requested" || a.state === "throttled";
  const sentCode = a.method === "sent_code";
  const contact = a.method === "recovery_contact";
  return (
    <>
      <div role="status" className="flex flex-col gap-2">
        <p data-message-id={textId}>{t(textId)}</p>
        {a.until !== undefined && (a.state === "cooling_down" || a.state === "rebind_open") && (
          <p className={note} data-testid="until">
            {t("page.recovery_until", { date: when(a.until) })}
          </p>
        )}
        {a.sensitive_actions_after !== undefined && (
          <p className={note} data-testid="sensitive-after">
            {t("page.recovery_sensitive_after", { date: when(a.sensitive_actions_after) })}
          </p>
        )}
        {a.sensitive_actions_after !== undefined && a.authenticator_removed === true && (
          <p className={note} data-testid="authenticator-removed">
            {t("page.recovery_authenticator_removed", {
              date: when(a.sensitive_actions_after),
            })}
          </p>
        )}
      </div>
      {proving && sentCode && !props.sent && (
        <Button {...primary} disabled={props.busy} onClick={props.onSend}>
          {t("page.recovery_send_code")}
        </Button>
      )}
      {proving && (!sentCode || props.sent) && (
        <form
          className={stack}
          onSubmit={(e) => {
            e.preventDefault();
            props.onCode(value(e, "code"));
          }}
        >
          <Field
            name="code"
            label={sentCode ? t("label.email_code") : t("label.recovery_code")}
            autoComplete="one-time-code"
            numeric={sentCode}
            code
            maxLength={64}
          />
          <Button type="submit" {...primary} disabled={props.busy}>
            {t("action.verify")}
          </Button>
        </form>
      )}
      {proving && contact && (
        <Button {...quiet} disabled={props.busy} onClick={props.onExtend}>
          {t("page.recovery_extend")}
        </Button>
      )}
      {a.state === "cooling_down" && (
        <Button {...primary} disabled={props.busy} onClick={props.onContinue}>
          {t("page.recovery_continue")}
        </Button>
      )}
      {(a.state === "evidence_met" || a.state === "cooling_down") && (
        <Button {...quiet} disabled={props.busy} onClick={props.onRefresh}>
          {t("page.recovery_refresh")}
        </Button>
      )}
      {a.state === "rebind_open" && (
        <form
          key={props.refused?.tries ?? 0}
          className={stack}
          onSubmit={(e) => {
            e.preventDefault();
            props.onPassword(value(e, "new_password"));
          }}
        >
          {props.who !== "" && (
            <input
              type="text"
              name="username"
              autoComplete="username"
              value={props.who}
              readOnly
              hidden
            />
          )}
          <Field
            name="new_password"
            label={pin ? t("page.recovery_new_pin") : t("label.new_password")}
            type="password"
            autoComplete="new-password"
            maxLength={pin ? 6 : 128}
            numeric={pin}
            hint={pin ? t("page.recovery_pin_hint") : t("page.recovery_password_hint")}
            {...(props.refused === null ? {} : { error: t(props.refused.text) })}
          />
          <Button type="submit" {...primary} disabled={props.busy}>
            {t("action.continue")}
          </Button>
        </form>
      )}
      {a.replacement_code !== undefined && (
        <div className="flex flex-col gap-2 rounded-lg bg-muted px-4 py-3">
          <p className="text-sm">{t("page.recovery_replacement_code")}</p>
          <p>
            <code
              dir="ltr"
              className="font-mono text-lg tracking-wider"
              data-testid="replacement-code"
            >
              {a.replacement_code}
            </code>
          </p>
        </div>
      )}
    </>
  );
}
