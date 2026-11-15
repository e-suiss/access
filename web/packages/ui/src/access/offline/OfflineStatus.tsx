// OP-156 m.3 (v), §8.17.5.8, §8.13, CI-9, INV-24
// `<OfflineStatus />`: a till's offline window from its Verifier Profile and slice counter, as
// `@esuiss/access` `offline.stateAt` reads them. The window is shown with the condition it rests
// on (the till follows its declared profile); after it ends the till must go online, and nothing
// reads as "allowed offline".
import { Alert, AlertDescription } from "@access/ui/components/alert";
import { Card, CardContent, CardHeader, CardTitle } from "@access/ui/components/card";

import { type Money, money } from "../payment/model.js";
import { say } from "../payment/Payment.js";

/** The till's report. */
export interface OfflineReport {
  readonly since: number;
  readonly until: number;
  readonly voidsLeft?: number;
  readonly amountLeft?: Money;
}

/** Where the till stands. */
export type OfflineState =
  | { readonly kind: "online" }
  | { readonly kind: "offline"; readonly report: OfflineReport }
  | { readonly kind: "ended"; readonly report: OfflineReport };

export interface OfflineStatusProps {
  readonly state: OfflineState;
  /** A time as the viewer reads it. */
  readonly time: (ms: number) => string;
  readonly locale: string;
  readonly catalogue?: Readonly<Record<string, string>> | undefined;
}

/** "Offline since 14:02 · can act offline until 18:00 · 3 voids and 2,000 TRY left". */
export function OfflineStatus({ state, time, locale, catalogue }: OfflineStatusProps) {
  if (state.kind === "online") return null;
  const r = state.report;
  const title = say({ text: "offline.title" }, catalogue);
  if (state.kind === "ended") {
    return (
      <section className="access-offline" aria-label={title} data-state="ended">
        <Alert variant="destructive">
          <AlertDescription className="text-foreground">
            {say({ text: "offline.ended", args: { time: time(r.until) } }, catalogue)}
          </AlertDescription>
        </Alert>
      </section>
    );
  }
  return (
    <section className="access-offline" aria-label={title} data-state="offline">
      <Card size="sm">
        <CardHeader>
          <CardTitle>
            <h3>{title}</h3>
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-1 text-sm">
          <p>{say({ text: "offline.since", args: { time: time(r.since) } }, catalogue)}</p>
          <p>{say({ text: "offline.until", args: { time: time(r.until) } }, catalogue)}</p>
          {r.voidsLeft !== undefined && r.amountLeft !== undefined && (
            <p data-testid="offline-left" className="text-muted-foreground">
              {say(
                {
                  text: "offline.remaining",
                  args: { voids: String(r.voidsLeft), amount: money(r.amountLeft, locale) },
                },
                catalogue,
              )}
            </p>
          )}
        </CardContent>
      </Card>
    </section>
  );
}
