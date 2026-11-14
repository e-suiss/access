// §8.12, §8.17.9.7, §13.6, OP-158 m.3 (m): Audit ▸ Recovery and handover. Whether the governing
// domain can be recovered ("Recovery not available" otherwise, §13.6 S7), and each handover and
// forced recovery with the record position it took effect at. After a recovery the banner says
// which changes may be lost and that revocations made after that time must be made again;
// nothing here starts a recovery, which only `access-cli domain recover` does.
import type { ReactElement } from "react";

import { Card, CardContent } from "@suiss/access-ui/components/ui/card";

import { t } from "../i18n/index.js";
import { adminGet } from "../lib/admin.js";
import { BULLETS, HINT, Notice } from "../ui.js";
import { at, type Ctx, Show, useLoad } from "./parts.js";

interface Entry {
  readonly kind: "recovered" | "handover";
  readonly position: string;
  readonly at: string;
  readonly lost_after?: string;
}

interface RecoveryView {
  readonly recovery: "available" | "not_available";
  readonly recovery_threshold?: { readonly k: number; readonly n: number };
  readonly history: readonly Entry[];
}

/** The recovery and handover screen. */
export function Recovery({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const realm = encodeURIComponent(ctx.session.realm);
  const view = useLoad(() => adminGet<RecoveryView>(ctx.instance, `realms/${realm}/recovery`));
  return (
    <div data-testid="recovery" className="flex flex-col gap-4">
      <p className="text-muted-foreground">{t("recoveryIntro")}</p>
      <Show l={view}>
        {(v) => {
          const last = [...v.history].reverse().find((e) => e.kind === "recovered");
          return (
            <>
              {last?.lost_after !== undefined && (
                <Notice tone="warning" role="alert" data-testid="recovery-banner">
                  {t("recoveryRecoveredAt", { position: last.position })}.{" "}
                  {t("recoveryChangesLost", { time: at(last.lost_after) })}
                </Notice>
              )}
              <Card>
                <CardContent className="flex flex-col gap-4">
                  {v.recovery === "not_available" ? (
                    <section data-testid="recovery-not-available" className="flex flex-col gap-1">
                      <h3 className="text-base font-semibold">{t("recoveryNotAvailable")}</h3>
                      <p className={HINT}>{t("recoveryNotAvailableWhy")}</p>
                    </section>
                  ) : (
                    <p data-testid="recovery-available">
                      {t("recoveryAvailable", {
                        k: String(v.recovery_threshold?.k ?? 0),
                        n: String(v.recovery_threshold?.n ?? 0),
                      })}
                    </p>
                  )}
                  {v.history.length === 0 ? (
                    <p className={HINT}>{t("none")}</p>
                  ) : (
                    <ul data-testid="recovery-history" className={BULLETS}>
                      {v.history.map((e) => (
                        <li
                          key={`${e.kind}-${e.position}`}
                          data-testid="recovery-entry"
                          data-kind={e.kind}
                        >
                          {e.kind === "recovered"
                            ? t("recoveryRecoveredAt", { position: e.position })
                            : t("recoveryHandoverAtPosition", { position: e.position })}{" "}
                          <time dateTime={e.at} className="text-muted-foreground">
                            {at(e.at)}
                          </time>
                        </li>
                      ))}
                    </ul>
                  )}
                </CardContent>
              </Card>
            </>
          );
        }}
      </Show>
    </div>
  );
}
