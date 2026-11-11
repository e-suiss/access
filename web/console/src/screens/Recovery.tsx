// §8.12, §8.17.9.7, §13.6, OP-158 m.3 (m): Audit ▸ Recovery and handover. Whether the governing
// domain can be recovered ("Recovery not available" otherwise, §13.6 S7), and each handover and
// forced recovery with the record position it took effect at. After a recovery the banner says
// which changes may be lost and that revocations made after that time must be made again;
// nothing here starts a recovery, which only `access-cli domain recover` does.
import type { ReactElement } from "react";

import { t } from "../i18n/index.js";
import { adminGet } from "../lib/admin.js";
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
    <div data-testid="recovery">
      <p>{t("recoveryIntro")}</p>
      <Show l={view}>
        {(v) => {
          const last = [...v.history].reverse().find((e) => e.kind === "recovered");
          return (
            <>
              {last?.lost_after !== undefined && (
                <p role="alert" data-testid="recovery-banner">
                  {t("recoveryRecoveredAt", { position: last.position })}.{" "}
                  {t("recoveryChangesLost", { time: at(last.lost_after) })}
                </p>
              )}
              {v.recovery === "not_available" ? (
                <section data-testid="recovery-not-available">
                  <h3>{t("recoveryNotAvailable")}</h3>
                  <p>{t("recoveryNotAvailableWhy")}</p>
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
                <p>{t("none")}</p>
              ) : (
                <ul data-testid="recovery-history">
                  {v.history.map((e) => (
                    <li
                      key={`${e.kind}-${e.position}`}
                      data-testid="recovery-entry"
                      data-kind={e.kind}
                    >
                      {e.kind === "recovered"
                        ? t("recoveryRecoveredAt", { position: e.position })
                        : t("recoveryHandoverAtPosition", { position: e.position })}{" "}
                      <time dateTime={e.at}>{at(e.at)}</time>
                    </li>
                  ))}
                </ul>
              )}
            </>
          );
        }}
      </Show>
    </div>
  );
}
