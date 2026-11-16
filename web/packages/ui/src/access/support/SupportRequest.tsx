// OP-157 m.3 (f), §8.16, TN-137 (1), XI-7
import { Button } from "@access/ui/components/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@access/ui/components/card";

import { EN } from "../texts.js";
import { mayOpen, type Opener, type Request, say, termsArgs, titleArgs } from "./model.js";

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
    <Card className="access-support-request" role="dialog" aria-label={title}>
      <CardHeader>
        <CardTitle>
          <h3>{title}</h3>
        </CardTitle>
        <CardDescription>
          {say(EN, "support.give_terms", catalogue, termsArgs(request))}
        </CardDescription>
      </CardHeader>
      {request.readOnly ? (
        <CardContent>
          <p className="text-sm text-muted-foreground">{say(EN, "support.read_only", catalogue)}</p>
        </CardContent>
      ) : null}
      <CardFooter className="flex-col gap-2 sm:flex-row-reverse sm:justify-start">
        <Button
          type="button"
          className="w-full sm:w-auto"
          disabled={busy === true}
          onClick={onGive}
        >
          {say(EN, "action.give_access", catalogue)}
        </Button>
        <Button
          type="button"
          variant="secondary"
          className="w-full sm:w-auto"
          disabled={busy === true}
          onClick={onDecline}
        >
          {say(EN, "support.decline", catalogue)}
        </Button>
      </CardFooter>
    </Card>
  );
}

export interface SupportActionsProps {
  /** Asks the person for support access; the person decides on their own page. */
  readonly onRequest: () => void;
  /** Starts the break-glass path where the environment declared one. */
  readonly onEmergency?: () => void;
  readonly catalogue?: Readonly<Record<string, string>> | undefined;
}

/** The operator's two actions in place of impersonation (§8.10): "Request support access" and,
 * where declared, "Emergency access (break-glass)". There is no way to become the person. */
export function SupportActions({ onRequest, onEmergency, catalogue }: SupportActionsProps) {
  return (
    <div className="access-support-actions flex flex-wrap gap-2">
      <Button type="button" onClick={onRequest}>
        {say(EN, "support.request", catalogue)}
      </Button>
      {onEmergency === undefined ? null : (
        <Button type="button" variant="destructive" onClick={onEmergency}>
          {say(EN, "support.emergency", catalogue)}
        </Button>
      )}
    </div>
  );
}
