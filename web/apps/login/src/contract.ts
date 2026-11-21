/** The login node contract (`sdks/openapi/login.json`); the hosted login reads nothing else from the server (TN-106, X40). */

import * as v from "valibot";

export const contractVersion = 1;
export const flowsPath = "/v1/login/flows";
export const stepUpPath = "/v1/login/step-up";

export type Step = "identifier" | "authenticate" | "second_factor" | "profile" | "complete";
export type FlowKind =
  | "login"
  | "registration"
  | "recovery"
  | "settings"
  | "consent"
  | "invitation"
  | "link";
export type FieldName =
  | "identifier"
  | "password"
  | "totp_code"
  | "recovery_code"
  | "passkey_credential"
  | "email_code"
  | "email"
  | "new_password"
  | "display_name"
  | "acknowledged"
  | "invitation_code"
  | "link_code"
  | "bot_token"
  | "keep_signed_in"
  | "remember_device"
  | "sms_code"
  | "phone"
  | "national_id"
  | "national_id_scheme"
  | "accept_documents"
  | "birthdate";
/** A step-wide choice, sent with every submission of the step when checked (X33, TN-36). */
export type OptionName = "keep_signed_in" | "remember_device";
export type Method =
  | "identifier"
  | "password"
  | "passkey"
  | "totp"
  | "recovery_code"
  | "passkey_register"
  | "skip"
  | "restart"
  | "email_code"
  | "magic_link"
  | "register"
  | "recover"
  | "new_password"
  | "share"
  | "dont_share"
  | "accept_invitation"
  | "link"
  | "acknowledge"
  | "push"
  | "send_sms"
  | "sms"
  | "profile"
  | "profile_code"
  | "resend";

export interface Text {
  readonly id: string;
  readonly text: string;
}

export interface Message extends Text {
  readonly severity: "info" | "error";
  readonly retry_after_s?: number;
  /** TN-162: the values of the text's placeholders. */
  readonly args?: Readonly<Record<string, string>>;
  /** TN-169: the input the message is about. */
  readonly field?: FieldName;
}

export interface RequirementStatus {
  readonly requirement: "identifier" | "first_factor" | "second_factor" | "profile";
  readonly state: "missing" | "satisfied";
}

export type PasskeyOptions = Readonly<Record<string, unknown>>;

export type PasskeySignal =
  | { readonly kind: "unknown_credential"; readonly rp_id: string; readonly credential_id: string }
  | {
      readonly kind: "all_accepted_credentials";
      readonly rp_id: string;
      readonly user_id: string;
      readonly all_accepted_credential_ids: readonly string[];
    }
  | {
      readonly kind: "current_user_details";
      readonly rp_id: string;
      readonly user_id: string;
      readonly name: string;
      readonly display_name: string;
    };

export interface InputNode {
  readonly type: "input";
  readonly name: FieldName;
  readonly method: Method;
  readonly kind: "text" | "password" | "code" | "hidden" | "tel" | "date" | "email";
  readonly autocomplete: string;
  readonly required: boolean;
  readonly max_length: number;
  readonly label: Text;
  readonly value?: string;
  readonly read_only?: boolean;
  /** TN-169: a line under the field that says what it takes. */
  readonly hint?: Text;
  /** TN-169: digits only. */
  readonly numeric?: boolean;
}

export interface SubmitNode {
  readonly type: "submit";
  readonly method: Method;
  readonly label: Text;
}

export interface PasskeyGetNode {
  readonly type: "passkey_get";
  readonly label: Text;
  readonly options: PasskeyOptions;
}

export interface PasskeyAutofillNode {
  readonly type: "passkey_autofill";
  readonly field: FieldName;
  readonly options: PasskeyOptions;
}

export interface PasskeyCreateNode {
  readonly type: "passkey_create";
  readonly mediation: "explicit" | "conditional";
  readonly label: Text;
  readonly options: PasskeyOptions;
}

export interface PasskeySignalNode {
  readonly type: "passkey_signal";
  readonly signal: PasskeySignal;
}

/** TN-158: one of a closed list, drawn as a select and submitted with its method. */
export interface ChoiceNode {
  readonly type: "choice";
  readonly name: FieldName;
  readonly method: Method;
  readonly label: Text;
  readonly options: readonly { readonly value: string; readonly label: Text }[];
}

/** TN-158 (12): the environment's documents and one required checkbox that accepts them all. */
export interface DocumentsNode {
  readonly type: "documents";
  readonly name: FieldName;
  readonly method: Method;
  readonly label: Text;
  readonly documents: readonly { readonly title: string; readonly href: string }[];
}

export interface OptionNode {
  readonly type: "option";
  readonly name: OptionName;
  readonly label: Text;
  readonly checked: boolean;
}

/** A social sign-in: a full-page navigation to `href` (OP-153 m.3 (l)). */
export interface ProviderNode {
  readonly type: "provider";
  readonly provider: string;
  readonly label: Text;
  readonly href: string;
}

/** TN-172: certificate sign-in, a full-page navigation to the mTLS listener's `port` at this host. */
export interface CertificateNode {
  readonly type: "certificate";
  readonly label: Text;
  readonly hint: Text;
  readonly port: number;
}

/** The number to type into the approver while a push waits; the push never carries it (OP-156 m.3 (d)). */
export interface PushNumberNode {
  readonly type: "push_number";
  readonly number: number;
  readonly approver?: string;
  readonly label: Text;
  readonly expires_at: string;
}

/** OP-159 m.48 (a): the key of a TOTP set up at sign-in, for manual entry and as an `otpauth://` link. */
export interface TotpSetupNode {
  readonly type: "totp_setup";
  readonly label: Text;
  readonly secret: string;
  readonly uri: string;
}

/** OP-159 m.48 (a), §10.2.2: recovery codes, shown once on the completed step of a sign-in that enrolled. */
export interface RecoveryCodesNode {
  readonly type: "recovery_codes";
  readonly label: Text;
  readonly codes: readonly string[];
}

export type UiNode =
  | InputNode
  | ChoiceNode
  | DocumentsNode
  | TotpSetupNode
  | RecoveryCodesNode
  | PushNumberNode
  | OptionNode
  | ProviderNode
  | CertificateNode
  | SubmitNode
  | PasskeyGetNode
  | PasskeyAutofillNode
  | PasskeyCreateNode
  | PasskeySignalNode;

export interface LoginUi {
  readonly version: number;
  readonly flow: string;
  readonly kind?: FlowKind;
  readonly step: Step;
  readonly action: string;
  readonly requirements: readonly RequirementStatus[];
  readonly nodes: readonly UiNode[];
  readonly messages: readonly Message[];
  readonly redirect_to?: string;
}

export interface Submission {
  readonly method: Method;
  readonly fields: Readonly<Partial<Record<FieldName, string>>>;
}

// OP-159 m.46 (f)
const STEPS = ["identifier", "authenticate", "second_factor", "profile", "complete"] as const;
const FLOW_KINDS = [
  "login",
  "registration",
  "recovery",
  "settings",
  "consent",
  "invitation",
  "link",
] as const;
const FIELD_NAMES = [
  "identifier",
  "password",
  "totp_code",
  "recovery_code",
  "passkey_credential",
  "email_code",
  "email",
  "new_password",
  "display_name",
  "acknowledged",
  "invitation_code",
  "link_code",
  "bot_token",
  "keep_signed_in",
  "remember_device",
  "sms_code",
  "phone",
  "national_id",
  "national_id_scheme",
  "accept_documents",
  "birthdate",
] as const satisfies readonly FieldName[];
const METHODS = [
  "identifier",
  "password",
  "passkey",
  "totp",
  "recovery_code",
  "passkey_register",
  "skip",
  "restart",
  "email_code",
  "magic_link",
  "register",
  "recover",
  "new_password",
  "share",
  "dont_share",
  "accept_invitation",
  "link",
  "acknowledge",
  "push",
  "send_sms",
  "sms",
  "profile",
  "profile_code",
  "resend",
] as const satisfies readonly Method[];

const TextS = v.object({ id: v.string(), text: v.string() });
const MessageS: v.GenericSchema<unknown, Message> = v.object({
  id: v.string(),
  text: v.string(),
  severity: v.picklist(["info", "error"]),
  retry_after_s: v.exactOptional(v.number()),
  args: v.exactOptional(v.record(v.string(), v.string())),
  field: v.exactOptional(v.picklist(FIELD_NAMES)),
});
const RequirementS: v.GenericSchema<unknown, RequirementStatus> = v.object({
  requirement: v.picklist(["identifier", "first_factor", "second_factor", "profile"]),
  state: v.picklist(["missing", "satisfied"]),
});
const OptionsS = v.record(v.string(), v.unknown());
const FieldNameS = v.picklist(FIELD_NAMES);
const MethodS = v.picklist(METHODS);

const InputS: v.GenericSchema<unknown, InputNode> = v.object({
  type: v.literal("input"),
  name: FieldNameS,
  method: MethodS,
  kind: v.picklist(["text", "password", "code", "hidden", "tel", "date", "email"]),
  autocomplete: v.string(),
  required: v.boolean(),
  max_length: v.number(),
  label: TextS,
  value: v.exactOptional(v.string()),
  read_only: v.exactOptional(v.boolean()),
  hint: v.exactOptional(TextS),
  numeric: v.exactOptional(v.boolean()),
});
const SubmitS: v.GenericSchema<unknown, SubmitNode> = v.object({
  type: v.literal("submit"),
  method: MethodS,
  label: TextS,
});
const PasskeyGetS: v.GenericSchema<unknown, PasskeyGetNode> = v.object({
  type: v.literal("passkey_get"),
  label: TextS,
  options: OptionsS,
});
const PasskeyAutofillS: v.GenericSchema<unknown, PasskeyAutofillNode> = v.object({
  type: v.literal("passkey_autofill"),
  field: FieldNameS,
  options: OptionsS,
});
const PasskeyCreateS: v.GenericSchema<unknown, PasskeyCreateNode> = v.object({
  type: v.literal("passkey_create"),
  mediation: v.picklist(["explicit", "conditional"]),
  label: TextS,
  options: OptionsS,
});
const SignalS: v.GenericSchema<unknown, PasskeySignal> = v.variant("kind", [
  v.object({
    kind: v.literal("unknown_credential"),
    rp_id: v.string(),
    credential_id: v.string(),
  }),
  v.object({
    kind: v.literal("all_accepted_credentials"),
    rp_id: v.string(),
    user_id: v.string(),
    all_accepted_credential_ids: v.array(v.string()),
  }),
  v.object({
    kind: v.literal("current_user_details"),
    rp_id: v.string(),
    user_id: v.string(),
    name: v.string(),
    display_name: v.string(),
  }),
]);
const PasskeySignalS: v.GenericSchema<unknown, PasskeySignalNode> = v.object({
  type: v.literal("passkey_signal"),
  signal: SignalS,
});
const ChoiceS: v.GenericSchema<unknown, ChoiceNode> = v.object({
  type: v.literal("choice"),
  name: v.picklist(FIELD_NAMES),
  method: v.picklist(METHODS),
  label: TextS,
  options: v.pipe(v.array(v.object({ value: v.string(), label: TextS })), v.minLength(1)),
});
// TN-158 (12): a document opens only over https, in a new tab
const DocumentsS: v.GenericSchema<unknown, DocumentsNode> = v.object({
  type: v.literal("documents"),
  name: v.picklist(FIELD_NAMES),
  method: v.picklist(METHODS),
  label: TextS,
  documents: v.pipe(
    v.array(v.object({ title: v.string(), href: v.pipe(v.string(), v.startsWith("https://")) })),
    v.minLength(1),
  ),
});
const OptionS: v.GenericSchema<unknown, OptionNode> = v.object({
  type: v.literal("option"),
  name: v.picklist(["keep_signed_in", "remember_device"]),
  label: TextS,
  checked: v.boolean(),
});
// OP-153 m.3 (l): a provider link leaves only for a path of this site; the redirect onward is the server's
const ProviderS: v.GenericSchema<unknown, ProviderNode> = v.object({
  type: v.literal("provider"),
  provider: v.string(),
  label: TextS,
  href: v.custom<string>(isLocalPath),
});
const CertificateS: v.GenericSchema<unknown, CertificateNode> = v.object({
  type: v.literal("certificate"),
  label: TextS,
  hint: TextS,
  port: v.pipe(v.number(), v.integer(), v.minValue(1), v.maxValue(65_535)),
});
const PushNumberS: v.GenericSchema<unknown, PushNumberNode> = v.object({
  type: v.literal("push_number"),
  number: v.number(),
  approver: v.exactOptional(v.string()),
  label: TextS,
  expires_at: v.string(),
});

const TotpSetupS: v.GenericSchema<unknown, TotpSetupNode> = v.object({
  type: v.literal("totp_setup"),
  label: TextS,
  secret: v.string(),
  uri: v.pipe(v.string(), v.startsWith("otpauth://")),
});
const RecoveryCodesS: v.GenericSchema<unknown, RecoveryCodesNode> = v.object({
  type: v.literal("recovery_codes"),
  label: TextS,
  codes: v.array(v.string()),
});

const NODES: Readonly<Record<string, v.GenericSchema<unknown, UiNode>>> = {
  input: InputS,
  submit: SubmitS,
  passkey_get: PasskeyGetS,
  passkey_autofill: PasskeyAutofillS,
  passkey_create: PasskeyCreateS,
  passkey_signal: PasskeySignalS,
  option: OptionS,
  choice: ChoiceS,
  documents: DocumentsS,
  provider: ProviderS,
  certificate: CertificateS,
  push_number: PushNumberS,
  totp_setup: TotpSetupS,
  recovery_codes: RecoveryCodesS,
};

const NodeType = v.looseObject({ type: v.string() });

/** A node this client knows, read by its schema; any other node is dropped (OP-65: additive). */
function knownNode(node: unknown): UiNode[] {
  const head = v.safeParse(NodeType, node);
  const schema = head.success ? NODES[head.output.type] : undefined;
  if (schema === undefined) return [];
  const read = v.safeParse(schema, node);
  return read.success ? [read.output] : [];
}

const LoginUiS = v.object({
  version: v.literal(contractVersion),
  flow: v.pipe(v.string(), v.regex(/^[A-Za-z0-9_-]{1,128}$/)),
  kind: v.exactOptional(v.picklist(FLOW_KINDS)),
  step: v.picklist(STEPS),
  action: v.pipe(v.string(), v.startsWith(`${flowsPath}/`)),
  requirements: v.array(RequirementS),
  nodes: v.array(v.unknown()),
  messages: v.array(MessageS),
  redirect_to: v.exactOptional(v.string()),
});

/** A login step, or `null` when the body is not one. Node types this client does not know are dropped (OP-65: additive changes). */
export function parseUi(body: unknown): LoginUi | null {
  const read = v.safeParse(LoginUiS, body);
  if (!read.success) return null;
  return { ...read.output, nodes: read.output.nodes.flatMap(knownNode) };
}

/** A path on this origin: starts with one `/`, never `//` or `/\`. */
export function isLocalPath(href: unknown): href is string {
  return typeof href === "string" && /^\/(?![/\\])/.test(href);
}
