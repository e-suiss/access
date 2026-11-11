// §12.5.4, TN-127, OP-158 m.3 (v): Observability ▸ Rate limits. Each bucket's share in use now
// and over 1 h and 24 h, the heaviest consumers as digests, refusals by type and the warning
// threshold, as the management API reports them; nothing here changes a limit.
import type { ReactElement } from "react";

import { t } from "../i18n/index.js";
import { adminGet } from "../lib/admin.js";
import { type Ctx, Show, useLoad } from "./parts.js";

interface Bucket {
  readonly name: string;
  readonly now_percent: number;
  readonly average_1h_percent: number;
  readonly average_24h_percent: number;
  readonly above_threshold: boolean;
}

interface Consumer {
  readonly consumer: string;
  readonly requests: number;
}

interface Event {
  readonly kind: string;
  readonly last_hour: number;
  readonly last_day: number;
}

interface RateLimitsView {
  readonly rate_limit_rps: number;
  readonly usage: {
    readonly buckets: readonly Bucket[];
    readonly top_consumers: readonly Consumer[];
    readonly events: readonly Event[];
    readonly threshold_percent: number;
  };
}

const percent = (n: number) => `${String(n)}%`;

/** The rate limits screen. */
export function RateLimits({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const realm = encodeURIComponent(ctx.session.realm);
  const view = useLoad(() => adminGet<RateLimitsView>(ctx.instance, `realms/${realm}/rate-limits`));
  return (
    <div data-testid="rate-limits">
      <p>{t("rateLimitsIntro")}</p>
      <Show l={view}>
        {(v) => (
          <>
            {v.usage.buckets.some((b) => b.above_threshold) && (
              <p role="alert" data-testid="rate-limits-warning">
                {t("rateLimitsThreshold", { percent: String(v.usage.threshold_percent) })}
              </p>
            )}
            {v.usage.buckets.length === 0 ? (
              <p>{t("none")}</p>
            ) : (
              <table data-testid="rate-limits-buckets">
                <thead>
                  <tr>
                    <th scope="col">{t("rateLimitsBucket")}</th>
                    <th scope="col">{t("rateLimitsNow")}</th>
                    <th scope="col">{t("rateLimitsAverage1h")}</th>
                    <th scope="col">{t("rateLimitsAverage24h")}</th>
                  </tr>
                </thead>
                <tbody>
                  {v.usage.buckets.map((b) => (
                    <tr key={b.name} data-testid="rate-limits-bucket" data-name={b.name}>
                      <th scope="row" className="mono">
                        {b.name}
                      </th>
                      <td data-above={b.above_threshold ? "true" : "false"}>
                        {percent(b.now_percent)}
                      </td>
                      <td>{percent(b.average_1h_percent)}</td>
                      <td>{percent(b.average_24h_percent)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <h3>{t("rateLimitsTopConsumers")}</h3>
            {v.usage.top_consumers.length === 0 ? (
              <p>{t("none")}</p>
            ) : (
              <ol data-testid="rate-limits-consumers">
                {v.usage.top_consumers.map((c) => (
                  <li key={c.consumer}>
                    <span className="mono">{c.consumer}</span> ·{" "}
                    {t("rateLimitsRequests", { n: String(c.requests) })}
                  </li>
                ))}
              </ol>
            )}
            <h3>{t("rateLimitsEvents")}</h3>
            {v.usage.events.length === 0 ? (
              <p>{t("none")}</p>
            ) : (
              <dl className="facts" data-testid="rate-limits-events">
                {v.usage.events.map((e) => (
                  <div key={e.kind}>
                    <dt className="mono">{e.kind}</dt>
                    <dd>
                      {t("rateLimitsLastHour", { n: String(e.last_hour) })} ·{" "}
                      {t("rateLimitsLastDay", { n: String(e.last_day) })}
                    </dd>
                  </div>
                ))}
              </dl>
            )}
          </>
        )}
      </Show>
    </div>
  );
}
