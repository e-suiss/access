// §12.3.2, TN-54, TN-55, OP-153 m.3 (d), (e): recovery answers the same whether or not an
// account exists, says when the waiting period ends, and claims no more than the server's text
// (X38). The attempt rides in an HttpOnly cookie; the page keeps only the attempt id.
import { useEffect, useRef, useState, type SyntheticEvent } from "react";

import { Button } from "@suiss/access-ui/components/ui/button";
import {
  Field as FieldBox,
  FieldLabel,
  FieldLegend,
  FieldSet,
} from "@suiss/access-ui/components/ui/field";
import { Input } from "@suiss/access-ui/components/ui/input";
import { RadioGroup, RadioGroupItem } from "@suiss/access-ui/components/ui/radio-group";

import { LOGIN } from "./base.js";
import { getJson, postJson, type JsonAnswer } from "./http.js";
import { t, when } from "./i18n.js";
import { link, note, Panel, primary, problem, quiet, stack, Title, pressable } from "./Layout.js";

/** One attempt as `/v1/recovery` answers it. */
export interface Attempt {
  readonly attempt?: string;
  readonly state?: string;
  readonly method?: string;
  readonly text?: string;
  readonly until?: string;
  readonly replacement_code?: string;
  readonly sensitive_actions_after?: string;
}

type Path = "registered_code" | "sent_code";

type State =
  | { readonly phase: "start" }
  | { readonly phase: "attempt"; readonly attempt: Attempt }
  | { readonly phase: "failed"; readonly text: string };

const refusals: Readonly<Record<string, string>> = {
  "recovery-throttled": "login.throttled",
};

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
  readonly type?: "text" | "password";
  readonly autoComplete: string;
  readonly numeric?: boolean;
  readonly code?: boolean;
  readonly maxLength: number;
}) {
  const id = `recovery-${props.name}`;
  return (
    <FieldBox className="gap-2">
      <FieldLabel htmlFor={id} className="text-sm">
        {props.label}
      </FieldLabel>
      <Input
        id={id}
        name={props.name}
        type={props.type ?? "text"}
        autoComplete={props.autoComplete}
        required
        maxLength={props.maxLength}
        spellCheck={false}
        autoCapitalize="none"
        dir="auto"
        {...(props.numeric === true ? { inputMode: "numeric" as const } : {})}
        {...(props.code === true ? { className: "font-mono tracking-widest" } : {})}
      />
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
    const method = value(event, "method") as Path;
    void run(() => postJson<Attempt>("/v1/recovery", { identifier, method }));
  };

  const step = (attempt: Attempt, body: Record<string, unknown>) => {
    const id = attempt.attempt ?? "";
    void run(() => postJson<Attempt>(`/v1/recovery/${encodeURIComponent(id)}`, body), attempt);
  };

  const refresh = (attempt: Attempt) => {
    const id = attempt.attempt ?? "";
    void run(() => getJson<Attempt>(`/v1/recovery/${encodeURIComponent(id)}`), attempt);
  };

  const extend = (attempt: Attempt) => {
    const id = attempt.attempt ?? "";
    void run(
      () => postJson<Attempt>(`/v1/recovery/${encodeURIComponent(id)}/extension`, {}),
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
              label={t("label.identifier")}
              autoComplete="username"
              maxLength={320}
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
            onPassword={(newPassword) => {
              step(state.attempt, { new_password: newPassword });
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
              onPress={() => {
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
}) {
  const a = props.attempt;
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
      </div>
      {proving && sentCode && !props.sent && (
        <Button {...primary} disabled={props.busy} onPress={props.onSend}>
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
        <Button {...quiet} disabled={props.busy} onPress={props.onExtend}>
          {t("page.recovery_extend")}
        </Button>
      )}
      {a.state === "cooling_down" && (
        <Button {...primary} disabled={props.busy} onPress={props.onContinue}>
          {t("page.recovery_continue")}
        </Button>
      )}
      {(a.state === "evidence_met" || a.state === "cooling_down") && (
        <Button {...quiet} disabled={props.busy} onPress={props.onRefresh}>
          {t("page.recovery_refresh")}
        </Button>
      )}
      {a.state === "rebind_open" && (
        <form
          className={stack}
          onSubmit={(e) => {
            e.preventDefault();
            props.onPassword(value(e, "new_password"));
          }}
        >
          <Field
            name="new_password"
            label={t("label.new_password")}
            type="password"
            autoComplete="new-password"
            maxLength={128}
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
