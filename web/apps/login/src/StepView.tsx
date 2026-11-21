import { Button } from "@access/ui/components/button";
import { Checkbox } from "@access/ui/components/checkbox";
import { Field as FieldBox, FieldLabel, FieldLegend, FieldSet } from "@access/ui/components/field";
import { Input } from "@access/ui/components/input";
import { NativeSelect, NativeSelectOption } from "@access/ui/components/native-select";
import { PasswordInput } from "@access/ui/components/password-input";
import { QrCode } from "@access/ui/components/qr-code";
import { RecoveryCodeList } from "@access/ui/components/recovery-code-list";
import { type SyntheticEvent, useEffect, useRef, useState } from "react";
import * as v from "valibot";

import { LOGIN, under } from "./base.js";
import type {
  CertificateNode,
  ChoiceNode,
  DocumentsNode,
  FieldName,
  InputNode,
  LoginUi,
  Message,
  Method,
  OptionName,
  OptionNode,
  PasskeyCreateNode,
  ProviderNode,
  RecoveryCodesNode,
  Submission,
  SubmitNode,
  TotpSetupNode,
  UiNode,
} from "./contract.js";
import { Empty, follow, postJson, returnTo } from "./http.js";
import { passwordWords, t, text } from "./i18n.js";
import {
  link,
  note,
  other,
  otherLink,
  pressable,
  primary,
  problem,
  quiet,
  stack,
  Title,
} from "./Layout.js";
import { PushWait, pushOf } from "./PushWait.js";
import {
  askPasskey,
  conditionalCreateAvailable,
  conditionalGetAvailable,
  createPasskey,
  getPasskey,
  passkeysSupported,
  sendSignal,
} from "./passkey.js";
import { RECOVER_IDENTIFIER } from "./Recovery.js";

interface Props {
  readonly ui: LoginUi;
  readonly busy: boolean;
  readonly onSubmit: (submission: Submission) => void;
}

type Fields = Partial<Record<FieldName, string>>;

const htmlType = {
  text: "text",
  password: "password",
  code: "text",
  tel: "tel",
  date: "date",
  email: "text",
} as const;

/** Codes that are digits only get the numeric keyboard; recovery codes are not (TN-107). */
const numeric = new Set<FieldName>(["totp_code", "email_code", "sms_code"]);

/** TN-162: the ways a second step can be given, strongest first; a recovery code only on request. */
type Way = "passkey" | "push" | "totp" | "sms" | "recovery_code";
const WAYS: readonly Way[] = ["passkey", "push", "totp", "sms", "recovery_code"];
const WAY_METHODS: Readonly<Record<Way, readonly Method[]>> = {
  passkey: [],
  push: ["push"],
  totp: ["totp"],
  sms: ["send_sms", "sms"],
  recovery_code: ["recovery_code"],
};

/** TN-162: the way chosen on each flow, and the flows whose text message went. */
const chosenWay = new Map<string, Way>();
const smsSent = new Set<string>();

function waysOf(nodes: readonly UiNode[]): Way[] {
  return WAYS.filter((w) =>
    w === "passkey"
      ? passkeysSupported() && nodes.some((n) => n.type === "passkey_get")
      : nodes.some((n) => n.type === "submit" && WAY_METHODS[w].includes(n.method)),
  );
}

/** TN-176: a way offered under "Try another way", named and described for choosing it. */
function WayChoice(props: {
  readonly way: Way;
  readonly busy: boolean;
  readonly onPick: (way: Way) => void;
}) {
  const id = `way-${props.way}`;
  return (
    <button
      type="button"
      className="flex min-h-14 w-full flex-col items-start gap-0.5 rounded-xl border border-border bg-card px-4 py-3 text-start outline-none hover:bg-muted focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50"
      disabled={props.busy}
      onClick={() => props.onPick(props.way)}
      aria-labelledby={`${id}-title`}
      aria-describedby={`${id}-hint`}
      data-way={props.way}
    >
      <span id={`${id}-title`} className="font-medium">
        {t(`page.way_${props.way}`)}
      </span>
      <span id={`${id}-hint`} className={note}>
        {t(`page.way_${props.way}_hint`)}
      </span>
    </button>
  );
}

function methodsInOrder(nodes: readonly UiNode[]): Method[] {
  const seen: Method[] = [];
  for (const node of nodes) {
    if ((node.type === "input" || node.type === "submit") && !seen.includes(node.method)) {
      seen.push(node.method);
    }
  }
  return seen;
}

// TN-107: paste and autofill are never blocked; one pasteable field per code
function Field({
  node,
  invalid,
  error,
}: {
  readonly node: InputNode;
  readonly invalid: boolean;
  readonly error?: Message | undefined;
}) {
  if (node.kind === "hidden") return null;
  const id = `field-${node.name}-${node.method}`;
  if (node.kind === "date") return <DateField node={node} id={id} error={error} />;
  // TN-169: a message about this field sits under it, and a hint says what it takes
  const hintId = `${id}-hint`;
  const errorId = `${id}-error`;
  const describedBy = [error === undefined ? "" : errorId, node.hint === undefined ? "" : hintId]
    .filter((x) => x !== "")
    .join(" ");
  const below = (
    <>
      {error !== undefined && (
        <p id={errorId} role="alert" className={problem} data-message-id={error.id}>
          {text(error)}
        </p>
      )}
      {node.hint !== undefined && (
        <p id={hintId} className={note}>
          {text(node.hint)}
        </p>
      )}
    </>
  );
  if (node.kind === "password") {
    return (
      <FieldBox className="gap-2">
        <FieldLabel htmlFor={id} className="text-sm">
          {text(node.label)}
        </FieldLabel>
        <PasswordInput
          id={id}
          name={node.name}
          autoComplete={node.autocomplete}
          required={node.required}
          maxLength={node.max_length}
          spellCheck={false}
          autoCapitalize="none"
          dir="auto"
          words={passwordWords()}
          {...(invalid ? { "aria-invalid": true, "aria-describedby": ERRORS_ID } : {})}
        />
      </FieldBox>
    );
  }
  return (
    <FieldBox className="gap-2">
      <FieldLabel htmlFor={id} className="text-sm">
        {text(node.label)}
      </FieldLabel>
      <Input
        id={id}
        name={node.name}
        type={htmlType[node.kind]}
        autoComplete={node.autocomplete}
        required={node.required}
        maxLength={node.max_length}
        readOnly={node.read_only === true}
        defaultValue={node.value}
        {...(numeric.has(node.name) || node.numeric === true
          ? { inputMode: "numeric" as const }
          : node.kind === "email"
            ? { inputMode: "email" as const }
            : {})}
        spellCheck={false}
        autoCapitalize="none"
        dir="auto"
        {...(node.kind === "code" ? { className: "font-mono tracking-widest" } : {})}
        {...(error !== undefined ? { "aria-invalid": true } : {})}
        {...(describedBy === "" ? {} : { "aria-describedby": describedBy })}
      />
      {below}
    </FieldBox>
  );
}

/** TN-169: a date of birth as three boxes, day, month and year, never a calendar picker. */
function DateField(props: {
  readonly node: InputNode;
  readonly id: string;
  readonly error?: Message | undefined;
}) {
  const { node, id, error } = props;
  const errorId = `${id}-error`;
  const parts = [
    { part: "day", label: t("page.birthdate_day"), size: 2, auto: "bday-day" },
    { part: "month", label: t("page.birthdate_month"), size: 2, auto: "bday-month" },
    { part: "year", label: t("page.birthdate_year"), size: 4, auto: "bday-year" },
  ] as const;
  return (
    <FieldSet className="gap-2" {...(error === undefined ? {} : { "aria-describedby": errorId })}>
      <FieldLegend variant="label" className="mb-0 text-sm">
        {text(node.label)}
      </FieldLegend>
      <div className="flex gap-3">
        {parts.map((p) => (
          <FieldBox key={p.part} className={p.size === 4 ? "w-24 gap-1" : "w-16 gap-1"}>
            <FieldLabel htmlFor={`${id}-${p.part}`} className="text-sm font-normal">
              {p.label}
            </FieldLabel>
            <Input
              id={`${id}-${p.part}`}
              name={`${node.name}_${p.part}`}
              type="text"
              inputMode="numeric"
              autoComplete={p.auto}
              required={node.required}
              maxLength={p.size}
              {...(error !== undefined ? { "aria-invalid": true } : {})}
            />
          </FieldBox>
        ))}
      </div>
      {error !== undefined && (
        <p id={errorId} role="alert" className={problem} data-message-id={error.id}>
          {text(error)}
        </p>
      )}
    </FieldSet>
  );
}

/** The `YYYY-MM-DD` of the three boxes of a date field, or what was typed when it isn't whole. */
function dateOf(data: FormData, name: FieldName): string {
  const part = (p: string) => {
    const v = data.get(`${name}_${p}`);
    return typeof v === "string" ? v.trim() : "";
  };
  const [day, month, year] = [part("day"), part("month"), part("year")];
  if (day === "" && month === "" && year === "") return "";
  return `${year.padStart(4, "0")}-${month.padStart(2, "0")}-${day.padStart(2, "0")}`;
}

// TN-158
function Choice({ node }: { readonly node: ChoiceNode }) {
  const id = `field-${node.name}-${node.method}`;
  return (
    <FieldBox className="gap-2">
      <FieldLabel htmlFor={id} className="text-sm">
        {text(node.label)}
      </FieldLabel>
      <NativeSelect id={id} name={node.name} required defaultValue={node.options[0]?.value}>
        {node.options.map((o) => (
          <NativeSelectOption key={o.value} value={o.value}>
            {text(o.label)}
          </NativeSelectOption>
        ))}
      </NativeSelect>
    </FieldBox>
  );
}

// TN-158 (12)
function Documents({ node }: { readonly node: DocumentsNode }) {
  const id = `field-${node.name}-${node.method}`;
  return (
    <FieldBox className="gap-2">
      <ul className="flex flex-col gap-1 text-sm">
        {node.documents.map((d) => (
          <li key={d.href}>
            <a className="underline" href={d.href} target="_blank" rel="noopener noreferrer">
              {d.title}
            </a>
          </li>
        ))}
      </ul>
      <FieldBox orientation="horizontal">
        <Checkbox id={id} name={node.name} value="true" required className={pressable} />
        <FieldLabel htmlFor={id} className="text-sm">
          {text(node.label)}
        </FieldLabel>
      </FieldBox>
    </FieldBox>
  );
}

/** TN-165: the step's error list, which a refused password field points at. */
const ERRORS_ID = "step-errors";

/** TN-168: "Can't sign in?" takes the typed identifier to the recovery page, never in the URL. */
function handIdentifier() {
  const typed = document.querySelector<HTMLInputElement>('input[name="identifier"]')?.value.trim();
  if (typed === undefined || typed === "") return;
  try {
    window.sessionStorage.setItem(RECOVER_IDENTIFIER, typed);
  } catch {
    // a browser without session storage types it again
  }
}

function MethodForm(props: {
  readonly method: Method;
  readonly invalid: boolean;
  readonly fieldErrors?: readonly Message[];
  readonly nodes: readonly UiNode[];
  readonly busy: boolean;
  readonly options: Fields;
  readonly onSubmit: (submission: Submission) => void;
  /** TN-174: the code went out; this method's button asks for a new one after a short wait. */
  readonly resend?: boolean;
}) {
  const inputs = props.nodes.filter(
    (n): n is InputNode => n.type === "input" && n.method === props.method,
  );
  const drawn = props.nodes.filter(
    (n): n is InputNode | ChoiceNode | DocumentsNode =>
      (n.type === "input" || n.type === "choice" || n.type === "documents") &&
      n.method === props.method,
  );
  const buttons = props.nodes.filter(
    (n): n is SubmitNode => n.type === "submit" && n.method === props.method,
  );
  const handle = (event: SyntheticEvent<HTMLFormElement>) => {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const fields: Fields = {};
    for (const input of inputs) {
      if (input.read_only === true || input.kind === "hidden") continue;
      if (input.kind === "date") {
        fields[input.name] = dateOf(data, input.name);
        continue;
      }
      const value = data.get(input.name);
      if (typeof value === "string") fields[input.name] = value;
    }
    for (const node of drawn) {
      if (node.type === "input") continue;
      const value = data.get(node.name);
      if (typeof value === "string") fields[node.name] = value;
    }
    props.onSubmit({ method: props.method, fields: { ...fields, ...props.options } });
  };
  return (
    <form className={stack} onSubmit={handle} noValidate={false}>
      {drawn.map((node) =>
        node.type === "choice" ? (
          <Choice key={node.name} node={node} />
        ) : node.type === "documents" ? (
          <Documents key={node.name} node={node} />
        ) : (
          <Field
            key={node.name}
            node={node}
            invalid={props.invalid}
            error={props.fieldErrors?.find((m) => m.field === node.name)}
          />
        ),
      )}
      {buttons.map((node) =>
        props.method === "resend" || props.resend === true ? (
          <Resend
            key={node.label.id}
            label={props.method === "resend" ? text(node.label) : t("action.resend_code")}
            busy={props.busy}
            since={props.nodes}
          />
        ) : (
          <Button
            key={node.label.id}
            type="submit"
            {...(props.method === "restart" || props.method === "skip" ? quiet : primary)}
            disabled={props.busy}
          >
            {text(node.label)}
          </Button>
        ),
      )}
    </form>
  );
}

/** TN-171: seconds before a new code can be asked for, counted from when the step appeared. */
const RESEND_WAIT_S = 30;

/** TN-171: "Send a new code", closed for the first seconds of each step with the time left. */
function Resend(props: {
  readonly label: string;
  readonly busy: boolean;
  readonly since: unknown;
}) {
  const [left, setLeft] = useState(RESEND_WAIT_S);
  useEffect(() => {
    setLeft(RESEND_WAIT_S);
    const timer = window.setInterval(() => {
      setLeft((s) => {
        if (s <= 1) window.clearInterval(timer);
        return Math.max(0, s - 1);
      });
    }, 1000);
    return () => {
      window.clearInterval(timer);
    };
  }, [props.since]);
  return (
    <Button type="submit" {...quiet} disabled={props.busy || left > 0} data-testid="resend">
      {left > 0 ? t("page.resend_in", { seconds: String(left) }) : props.label}
    </Button>
  );
}

function Option(props: {
  readonly node: OptionNode;
  readonly checked: boolean;
  readonly onChange: (name: OptionName, checked: boolean) => void;
}) {
  const id = `option-${props.node.name}`;
  return (
    <FieldBox orientation="horizontal">
      <Checkbox
        className={pressable}
        id={id}
        name={props.node.name}
        aria-labelledby={`${id}-label`}
        checked={props.checked}
        onCheckedChange={(checked) => {
          props.onChange(props.node.name, checked);
        }}
      />
      <FieldLabel id={`${id}-label`} htmlFor={id} className="min-h-6 text-sm font-normal">
        {text(props.node.label)}
      </FieldLabel>
    </FieldBox>
  );
}

// OP-153 m.3 (l): a full-page navigation; the provider redirect is the server's
function Provider({ node }: { readonly node: ProviderNode }) {
  return (
    <a className={otherLink} href={under(node.href)} data-provider={node.provider}>
      {text(node.label)}
    </a>
  );
}

/** TN-172: where certificate sign-in starts for this page's flow: this host on the mTLS port. */
export function certificateHref(port: number, flow: string): string {
  const url = new URL(under("/login/certificate"), window.location.href);
  url.protocol = "https:";
  url.port = String(port);
  url.search = new URLSearchParams({ flow }).toString();
  return url.href;
}

// TN-172: a full-page navigation; the browser asks for the certificate there
function Certificate({ node, flow }: { readonly node: CertificateNode; readonly flow: string }) {
  return (
    <div className="flex flex-col gap-1">
      <a
        className={otherLink}
        href={certificateHref(node.port, flow)}
        aria-describedby="certificate-hint"
        data-testid="certificate"
      >
        {text(node.label)}
      </a>
      <p id="certificate-hint" className={note}>
        {text(node.hint)}
      </p>
    </div>
  );
}

// OP-159 m.48 (a): the key of a TOTP set up at sign-in; the code that proves it is the step's input
function TotpSetup({ node }: { readonly node: TotpSetupNode }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="flex flex-col gap-2" data-testid="totp-setup">
      <p className="text-sm">{text(node.label)}</p>
      {/* TN-155 */}
      <QrCode value={node.uri} label={t("page.totp_qr")} className="self-center" />
      <p className="text-sm text-muted-foreground">{t("page.totp_scan")}</p>
      <p
        className="break-all rounded-lg bg-muted px-3 py-2 font-mono text-base tracking-widest"
        data-testid="totp-secret"
      >
        {node.secret}
      </p>
      <p className="flex flex-wrap gap-3">
        <Button
          type="button"
          {...quiet}
          onClick={() => {
            void navigator.clipboard.writeText(node.secret).then(
              () => {
                setCopied(true);
              },
              () => undefined,
            );
          }}
        >
          {copied ? t("page.totp_copied") : t("page.totp_copy")}
        </Button>
        <a className={link} href={node.uri} data-testid="totp-uri">
          {t("page.totp_open")}
        </a>
      </p>
    </div>
  );
}

// OP-159 m.48 (a), §10.2.2: shown once; the sign-in continues only after the person says they saved them
/** TN-166 */
function codeWords() {
  return {
    copy: t("page.codes_copy"),
    copied: t("page.codes_copied"),
    download: t("page.codes_download"),
    print: t("page.codes_print"),
    title: t("page.codes_file_title", {
      host: window.location.hostname,
      date: new Date().toISOString().slice(0, 10),
    }),
  };
}

function RecoveryCodes(props: {
  readonly node: RecoveryCodesNode;
  readonly target: string | undefined;
}) {
  const [busy, setBusy] = useState(false);
  const proceed = async () => {
    setBusy(true);
    await postJson("/v1/account/recovery-codes/acknowledgement", {}, Empty);
    if (props.target !== undefined) follow(props.target);
  };
  return (
    <div className="flex flex-col gap-3" data-testid="recovery-codes">
      <p className="text-sm">{t("page.codes_save")}</p>
      <RecoveryCodeList
        codes={props.node.codes}
        words={codeWords()}
        fileName={`recovery-codes-${window.location.hostname}.txt`}
      />
      <Button {...primary} disabled={busy} onClick={() => void proceed()}>
        {t("page.codes_saved")}
      </Button>
    </div>
  );
}

/** Conditional create is opportunistic; it never holds the user back for longer than this. */
const conditionalCreateWaitMs = 2000;

/** Credentials the server called unknown; autofill does not resubmit them (TN-97). */
const refused = new Set<string>();

// OP-159 m.46 (f)
const Credential = v.looseObject({ id: v.string() });

function credentialId(json: string): string {
  const parsed = v.safeParse(Credential, JSON.parse(json));
  return parsed.success ? parsed.output.id : "";
}

function heading(ui: LoginUi): string {
  if (ui.kind === "registration") return t("registration.title");
  if (ui.step === "complete") return t("page.signing_in");
  // TN-162
  if (ui.step === "second_factor") return t("page.second_factor_title");
  return t("page.sign_in");
}

/**
 * OP-159 m.47 (b), TN-138: a second step is required and nothing on the step can give one: the
 * account has none yet and the step offers no way to add one.
 */
function noSecondStep(ui: LoginUi): boolean {
  if (ui.step !== "second_factor") return false;
  const missing = ui.requirements.some(
    (r) => r.requirement === "second_factor" && r.state === "missing",
  );
  const offered = ui.nodes.some(
    (n) =>
      n.type === "passkey_get" ||
      n.type === "passkey_create" ||
      n.type === "push_number" ||
      n.type === "totp_setup" ||
      ((n.type === "input" || n.type === "submit") &&
        n.method !== "restart" &&
        n.method !== "skip"),
  );
  return missing && !offered;
}

function initialOptions(nodes: readonly UiNode[]): Fields {
  const out: Fields = {};
  for (const n of nodes) if (n.type === "option" && n.checked) out[n.name] = "true";
  return out;
}

export function StepView({ ui, busy, onSubmit }: Props) {
  const autofill = ui.nodes.find((n) => n.type === "passkey_autofill");
  const passkeyButton = ui.nodes.find((n) => n.type === "passkey_get");
  const create = ui.nodes.find((n): n is PasskeyCreateNode => n.type === "passkey_create");
  const totpSetup = ui.nodes.find((n): n is TotpSetupNode => n.type === "totp_setup");
  const recoveryCodes = ui.nodes.find((n): n is RecoveryCodesNode => n.type === "recovery_codes");
  const optionNodes = ui.nodes.filter((n): n is OptionNode => n.type === "option");
  const providers = ui.nodes.filter((n): n is ProviderNode => n.type === "provider");
  const certificate = ui.nodes.find((n): n is CertificateNode => n.type === "certificate");
  const push = pushOf(ui);
  const conditional = useRef<AbortController | null>(null);
  const title = useRef<HTMLHeadingElement>(null);
  const first = useRef(true);
  const [round, setRound] = useState(0);
  const [options, setOptions] = useState<Fields>(() => initialOptions(ui.nodes));
  const [shown, setShown] = useState(ui);

  // X33, TN-36: the choices belong to the step they were offered on
  const [passkeyFailed, setPasskeyFailed] = useState(false);
  if (shown !== ui) {
    setShown(ui);
    setOptions(initialOptions(ui.nodes));
    setPasskeyFailed(false);
  }

  // TN-107: a new step is announced by moving focus to its heading
  useEffect(() => {
    if (first.current) {
      first.current = false;
      // TN-170: a sign-in page that opens on the identifier puts the caret in its empty field
      if (ui.step !== "identifier") return;
      const field = document.querySelector<HTMLInputElement>(
        'input[name="identifier"]:not([readonly])',
      );
      if (field !== null && field.value === "") field.focus();
      return;
    }
    title.current?.focus();
  }, [ui.flow, ui.step]);

  // TN-165: a refused password is cleared and its field takes the focus again
  const section = useRef<HTMLElement>(null);
  useEffect(() => {
    if (!ui.messages.some((m) => m.severity === "error")) return;
    // TN-169: a message about one field focuses that field
    const about = ui.messages.find((m) => m.severity === "error" && m.field !== undefined)?.field;
    if (about !== undefined) {
      const target = section.current?.querySelector<HTMLInputElement>(
        `input[name="${about}"], input[name="${about}_day"]`,
      );
      if (target !== null && target !== undefined) {
        target.focus();
        return;
      }
    }
    const field = section.current?.querySelector<HTMLInputElement>(
      'input[name="password"]:not([readonly])',
    );
    if (field === null || field === undefined) return;
    field.value = "";
    field.focus();
  }, [ui]);

  // TN-97
  useEffect(() => {
    const signals = ui.nodes.flatMap((n) => (n.type === "passkey_signal" ? [n.signal] : []));
    for (const s of signals) if (s.kind === "unknown_credential") refused.add(s.credential_id);
    void Promise.all(signals.map(sendSignal)).then(async () => {
      const target = ui.step === "complete" ? (returnTo() ?? ui.redirect_to) : undefined;
      if (target === undefined) return;
      if (create?.mediation === "explicit") return;
      // OP-159 m.48 (a): the recovery codes are read first
      if (recoveryCodes !== undefined) return;
      // §10.2.4
      if (create?.mediation === "conditional" && (await conditionalCreateAvailable())) {
        const credential = await createPasskey(
          create.options,
          "conditional",
          AbortSignal.timeout(conditionalCreateWaitMs),
        );
        if (credential !== null) {
          onSubmit({ method: "passkey_register", fields: { passkey_credential: credential } });
          return;
        }
      }
      follow(target);
    });
  }, [ui, create, recoveryCodes, onSubmit]);

  const optionsRef = useRef(options);
  useEffect(() => {
    optionsRef.current = options;
  }, [options]);

  // TN-99
  useEffect(() => {
    if (autofill === undefined) return;
    const controller = new AbortController();
    conditional.current = controller;
    void conditionalGetAvailable().then(async (available) => {
      if (!available || controller.signal.aborted) return;
      const credential = await getPasskey(autofill.options, "conditional", controller.signal);
      if (credential !== null && !refused.has(credentialId(credential))) {
        onSubmit({
          method: "passkey",
          fields: { passkey_credential: credential, ...optionsRef.current },
        });
      }
    });
    return () => {
      controller.abort();
    };
  }, [autofill, onSubmit, round]);

  const signInWithPasskey = async () => {
    if (passkeyButton === undefined) return;
    conditional.current?.abort();
    setPasskeyFailed(false);
    const result = await askPasskey(passkeyButton.options, undefined, new AbortController().signal);
    if (result.kind !== "credential") {
      setPasskeyFailed(result.kind === "failed");
      setRound((r) => r + 1);
      return;
    }
    onSubmit({ method: "passkey", fields: { passkey_credential: result.json, ...options } });
  };

  const registerPasskey = async () => {
    if (create === undefined) return;
    const credential = await createPasskey(create.options, undefined, new AbortController().signal);
    if (credential !== null) {
      onSubmit({ method: "passkey_register", fields: { passkey_credential: credential } });
    }
  };

  const setOption = (name: OptionName, checked: boolean) => {
    setOptions((o) => {
      const rest = Object.fromEntries(Object.entries(o).filter(([k]) => k !== name)) as Fields;
      return checked ? { ...rest, [name]: "true" } : rest;
    });
  };

  const drawnFields = new Set(
    ui.nodes.flatMap((n) => (n.type === "input" && n.kind !== "hidden" ? [n.name] : [])),
  );
  const fieldErrors = ui.messages.filter(
    (m) => m.severity === "error" && m.field !== undefined && drawnFields.has(m.field),
  );
  const errors = ui.messages.filter((m) => m.severity === "error" && !fieldErrors.includes(m));
  const infos = ui.messages.filter((m) => m.severity === "info");
  const login = ui.kind === undefined || ui.kind === "login";

  // TN-162: one way at a time on the second step, the others behind "Try another way"
  const second = ui.step === "second_factor";
  const ways = second ? waysOf(ui.nodes) : [];
  const passkeyOnly =
    second && ways.length === 0 && passkeyButton !== undefined && !passkeysSupported();
  const primary = ways.find((w) => w !== "recovery_code") ?? ways[0];
  const remembered = chosenWay.get(ui.flow);
  const way = remembered !== undefined && ways.includes(remembered) ? remembered : primary;
  const [listing, setListing] = useState(false);
  const [, setPicked] = useState(0);
  if (ui.messages.some((m) => m.id === "sms.sent")) smsSent.add(ui.flow);
  const pick = (w: Way) => {
    chosenWay.set(ui.flow, w);
    setListing(false);
    setPicked((n) => n + 1);
  };
  const visible = (method: Method): boolean => {
    if (!second || way === undefined) return true;
    if (!WAY_METHODS[way].includes(method)) return false;
    return method !== "sms" || smsSent.has(ui.flow);
  };
  // TN-174: read with the step's messages, so a new answer on the same flow reads the set again
  const sentSms = second && (ui.messages.some((m) => m.id === "sms.sent") || smsSent.has(ui.flow));
  const submit = (s: Submission) => {
    if (s.method === "send_sms") smsSent.add(ui.flow);
    onSubmit(s);
  };

  return (
    <section
      ref={section}
      aria-labelledby="step-heading"
      data-step={ui.step}
      data-kind={ui.kind ?? "login"}
      className={stack}
    >
      <Title id="step-heading" ref={title}>
        {heading(ui)}
      </Title>
      <div
        id={ERRORS_ID}
        role="alert"
        className="flex flex-col gap-2 empty:-mb-4"
        data-testid="errors"
      >
        {errors.map((m) => (
          <p key={m.id} className={problem} data-message-id={m.id}>
            {text(m)}
          </p>
        ))}
        {passkeyFailed && (
          <p className={problem} data-message-id="passkey.failed">
            {t("passkey.failed")}
          </p>
        )}
        {passkeyOnly && (
          <p className={problem} data-message-id="passkey.unsupported">
            {t("passkey.unsupported")}
          </p>
        )}
      </div>
      <div role="status" className="flex flex-col gap-2 empty:-mb-4">
        {infos.map((m) => (
          <p key={m.id} className={note} data-message-id={m.id}>
            {text(m)}
          </p>
        ))}
      </div>
      {push !== undefined && <PushWait node={push} />}
      {totpSetup !== undefined && <TotpSetup node={totpSetup} />}
      {recoveryCodes !== undefined && (
        <RecoveryCodes
          node={recoveryCodes}
          target={ui.step === "complete" ? (returnTo() ?? ui.redirect_to) : undefined}
        />
      )}
      {noSecondStep(ui) && (
        <p className={problem} data-testid="second-step-missing">
          {t("page.second_step_missing")}
        </p>
      )}
      {optionNodes.length > 0 && (
        <FieldSet className="gap-3">
          <FieldLegend className="sr-only">{t("page.options")}</FieldLegend>
          {optionNodes.map((node) => (
            <Option
              key={node.name}
              node={node}
              checked={options[node.name] === "true"}
              onChange={setOption}
            />
          ))}
        </FieldSet>
      )}
      {methodsInOrder(ui.nodes)
        .filter((m) => m !== "restart" && m !== "skip" && visible(m))
        .sort((a, b) => Number(a === "send_sms" && sentSms) - Number(b === "send_sms" && sentSms))
        .map((method) => (
          <MethodForm
            key={method}
            method={method}
            invalid={errors.length > 0}
            fieldErrors={fieldErrors}
            nodes={ui.nodes}
            busy={busy}
            options={options}
            onSubmit={submit}
            resend={method === "send_sms" && sentSms}
          />
        ))}
      {passkeyButton !== undefined && passkeysSupported() && (!second || way === "passkey") && (
        <Button {...other} disabled={busy} onClick={() => void signInWithPasskey()}>
          {text(passkeyButton.label)}
        </Button>
      )}
      {create?.mediation === "explicit" && (
        <Button {...other} disabled={busy} onClick={() => void registerPasskey()}>
          {text(create.label)}
        </Button>
      )}
      {second && ways.length > 1 && !listing && (
        <Button {...quiet} disabled={busy} onClick={() => setListing(true)}>
          {t("page.other_ways")}
        </Button>
      )}
      {second && listing && (
        <nav className="flex flex-col gap-2" aria-label={t("page.other_ways_title")}>
          {ways
            .filter((w) => w !== way)
            .map((w) => (
              <WayChoice key={w} way={w} busy={busy} onPick={pick} />
            ))}
        </nav>
      )}
      {certificate !== undefined && <Certificate node={certificate} flow={ui.flow} />}
      {providers.length > 0 && (
        <nav className="flex flex-col gap-2" aria-label={t("page.providers")}>
          {providers.map((node) => (
            <Provider key={node.provider} node={node} />
          ))}
        </nav>
      )}
      {methodsInOrder(ui.nodes)
        .filter((m) => m === "restart" || m === "skip")
        .map((method) => (
          <MethodForm
            key={method}
            method={method}
            invalid={false}
            nodes={ui.nodes}
            busy={busy}
            options={{}}
            onSubmit={onSubmit}
          />
        ))}
      {login && (ui.step === "identifier" || ui.step === "authenticate") && (
        <p className="flex flex-wrap justify-between gap-2">
          <a className={link} href={`${LOGIN}/recovery`} onClick={handIdentifier}>
            {t("page.recover")}
          </a>{" "}
          <a className={link} href={`${LOGIN}?reason=create`}>
            {t("page.create_account")}
          </a>
        </p>
      )}
      {ui.kind === "registration" && ui.step !== "complete" && (
        <p>
          <a className={link} href={LOGIN}>
            {t("action.have_account")}
          </a>
        </p>
      )}
    </section>
  );
}
