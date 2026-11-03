/** The login node contract (`sdks/openapi/login.json`); the hosted login reads nothing else from the server (TN-106, X40). */

export const contractVersion = 1;
export const flowsPath = "/v1/login/flows";

export type Step = "identifier" | "authenticate" | "second_factor" | "complete";
export type FieldName =
  "identifier" | "password" | "totp_code" | "recovery_code" | "passkey_credential";
export type Method =
  | "identifier"
  | "password"
  | "passkey"
  | "totp"
  | "recovery_code"
  | "passkey_register"
  | "skip"
  | "restart";

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
  readonly kind: "text" | "password" | "code";
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

export type UiNode =
  | InputNode
  | SubmitNode
  | PasskeyGetNode
  | PasskeyAutofillNode
  | PasskeyCreateNode
  | PasskeySignalNode;

export interface LoginUi {
  readonly version: number;
  readonly flow: string;
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
      isRecord(n) && typeof n["type"] === "string" && nodeTypes.has(n["type"]),
  );
  return { ...(body as unknown as LoginUi), nodes: known };
}
