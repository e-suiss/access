/** The login node contract (`sdks/openapi/login.json`); the hosted login reads nothing else from the server (TN-106, X40). */

export const contractVersion = 1;
export const flowsPath = "/v1/login/flows";
export const stepUpPath = "/v1/login/step-up";

export type Step = "identifier" | "authenticate" | "second_factor" | "complete";
export type FlowKind =
  "login" | "registration" | "recovery" | "settings" | "consent" | "invitation" | "link";
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
  | "remember_device";
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
  | "push";

export interface Text {
  readonly id: string;
  readonly text: string;
}

export interface Message extends Text {
  readonly severity: "info" | "error";
  readonly retry_after_s?: number;
}

export interface RequirementStatus {
  readonly requirement: "identifier" | "first_factor" | "second_factor";
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
  readonly kind: "text" | "password" | "code" | "hidden";
  readonly autocomplete: string;
  readonly required: boolean;
  readonly max_length: number;
  readonly label: Text;
  readonly value?: string;
  readonly read_only?: boolean;
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

/** The number to type into the approver while a push waits; the push never carries it (OP-156 m.3 (d)). */
export interface PushNumberNode {
  readonly type: "push_number";
  readonly number: number;
  readonly approver?: string;
  readonly label: Text;
  readonly expires_at: string;
}

export type UiNode =
  | InputNode
  | PushNumberNode
  | OptionNode
  | ProviderNode
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

const nodeTypes = new Set<string>([
  "input",
  "submit",
  "passkey_get",
  "passkey_autofill",
  "passkey_create",
  "passkey_signal",
  "option",
  "provider",
  "push_number",
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** A login step, or `null` when the body is not one. Node types this client does not know are dropped (OP-65: additive changes). */
export function parseUi(body: unknown): LoginUi | null {
  if (!isRecord(body) || body["version"] !== contractVersion) return null;
  const { flow, step, action, nodes, messages, requirements } = body;
  if (typeof flow !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(flow)) return null;
  if (
    typeof step !== "string" ||
    typeof action !== "string" ||
    !action.startsWith(`${flowsPath}/`)
  ) {
    return null;
  }
  if (!Array.isArray(nodes) || !Array.isArray(messages) || !Array.isArray(requirements))
    return null;
  const known = nodes.filter(
    (n: unknown): n is UiNode =>
      isRecord(n) && typeof n["type"] === "string" && nodeTypes.has(n["type"]) && local(n),
  );
  return { ...(body as unknown as LoginUi), nodes: known };
}

/** A provider link leaves only for a path of this site; the redirect onward is the server's. */
function local(node: Record<string, unknown>): boolean {
  if (node["type"] !== "provider") return true;
  return isLocalPath(node["href"]);
}

/** A path on this origin: starts with one `/`, never `//` or `/\`. */
export function isLocalPath(href: unknown): href is string {
  return typeof href === "string" && /^\/(?![/\\])/.test(href);
}
