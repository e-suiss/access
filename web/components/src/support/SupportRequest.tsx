// OP-157 m.3 (f), §8.16, TN-137 (1), XI-7
import { EN } from "../texts.js";
import { type Opener, type Request, mayOpen, say, termsArgs, titleArgs } from "./model.js";

export interface SupportRequestProps {
  readonly request: Request;
  /** Who opened the sheet: only the person, or a Needs Attention item; never the operator. */
  readonly openedBy: Opener;
  /** The person gives exactly what was asked; the host signs and sends the drafted Exercise. */
  readonly onGive: () => void;
  readonly onDecline: () => void;
  /** While the person's device signs and Access records. */
  readonly busy?: boolean;
  readonly catalogue?: Readonly<Record<string, string>> | undefined;
}

/** The person's S1 for a support request: "Give *Acme Support* access: view your account
 * settings · case #4411 · for 60 minutes · can't change sign-in methods, payments or email ·
 * can't pass on". It is a delegation, so the verb is "Give access", never "Approve". */
export function SupportRequest({
  request,
  openedBy,
  onGive,
  onDecline,
  busy,
  catalogue,
}: SupportRequestProps) {
  if (!mayOpen(openedBy)) {
    return null;
  }
  const title = say(EN, "support.give_title", catalogue, titleArgs(request));
  return (
    <section className="access-support-request" role="dialog" aria-label={title}>
      <h3>{title}</h3>
      <p>{say(EN, "support.give_terms", catalogue, termsArgs(request))}</p>
      {request.readOnly ? <p>{say(EN, "support.read_only", catalogue)}</p> : null}
      <button type="button" disabled={busy === true} onClick={onGive}>
        {say(EN, "action.give_access", catalogue)}
      </button>
      <button type="button" className="secondary" disabled={busy === true} onClick={onDecline}>
        {say(EN, "support.decline", catalogue)}
      </button>
    </section>
  );
}

export interface SupportActionsProps {
  /** Asks the person for support access; the person decides on their own page. */
  readonly onRequest: () => void;
  /** Starts the break-glass path where the realm declared one. */
  readonly onEmergency?: () => void;
  readonly catalogue?: Readonly<Record<string, string>> | undefined;
}

/** The operator's two actions in place of impersonation (§8.10): "Request support access" and,
 * where declared, "Emergency access (break-glass)". There is no "Log in as". */
export function SupportActions({ onRequest, onEmergency, catalogue }: SupportActionsProps) {
  return (
    <div className="access-support-actions">
      <button type="button" onClick={onRequest}>
        {say(EN, "support.request", catalogue)}
      </button>
      {onEmergency === undefined ? null : (
        <button type="button" className="secondary" onClick={onEmergency}>
          {say(EN, "support.emergency", catalogue)}
        </button>
      )}
    </div>
  );
}
