// TN-107, X29, §8.13: what every S10/S11 write shares. A write that needs a fresh confirmation
// sends the browser to the hosted login and back; a lost sign-in says only "Please sign in
// again to continue."; every outcome is announced in a live region.
import { useCallback, useState, type ReactElement } from "react";

import { FRONTEND, PAGE, Problem } from "../lib/api.js";
import { locale, t } from "../lib/i18n.js";

/** An announcement: polite status or an assertive alert. */
export interface Said {
  readonly text: string;
  readonly alert: boolean;
}

/** Where the hosted login confirms the person and comes back to `return_to` (X29). */
export function confirmAgainUrl(here: string = location.pathname): string {
  const back = here.startsWith(PAGE) ? here : PAGE;
  return `${FRONTEND}/login?reason=reauthenticate&return_to=${encodeURIComponent(back)}`;
}

/** The text a refused call shows, or `null` when the browser is sent elsewhere. */
export function refusal(e: unknown, codes: Readonly<Record<string, string>> = {}): string | null {
  if (!(e instanceof Problem)) return t("account.failed");
  if (e.code === "step-up-required") {
    location.assign(confirmAgainUrl());
    return null;
  }
  // §8.13
  if (e.status === 401) return t("account.sign_in_again");
  const own = codes[e.code];
  return own === undefined ? t("account.failed") : t(own);
}

/** A live region and the `say` that fills it. */
export function useAnnouncer(): {
  readonly say: (text: string, alert?: boolean) => void;
  readonly fail: (e: unknown, codes?: Readonly<Record<string, string>>) => void;
  readonly region: ReactElement;
} {
  const [said, setSaid] = useState<Said | null>(null);
  const say = useCallback((text: string, alert = false) => {
    setSaid({ text, alert });
  }, []);
  const fail = useCallback((e: unknown, codes?: Readonly<Record<string, string>>) => {
    const text = refusal(e, codes);
    if (text !== null) setSaid({ text, alert: true });
  }, []);
  const region = (
    <div className="flex flex-col gap-1 not-has-[p:not(:empty)]:absolute">
      <p
        aria-live="polite"
        aria-atomic="true"
        className="text-sm text-muted-foreground"
        data-testid="said"
      >
        {said !== null && !said.alert ? said.text : ""}
      </p>
      <p
        aria-live="assertive"
        aria-atomic="true"
        className="text-sm font-semibold text-destructive"
        data-testid="said-alert"
      >
        {said?.alert === true ? said.text : ""}
      </p>
    </div>
  );
  return { say, fail, region };
}

/** A date as the viewer reads it, from RFC 3339 or epoch milliseconds. */
export function when(at: string | number | null | undefined): string {
  if (at === null || at === undefined) return "";
  const d = new Date(at);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleString(locale);
}
