// §12.5.4, TN-127, OP-158 m.3 (v): Observability ▸ Rate limits. Each bucket's share in use now
// and over 1 h and 24 h, the heaviest consumers as digests, refusals by type and the warning
// threshold, as the management API reports them; nothing here changes a limit.
import type { ReactElement } from "react";

import { Card, CardContent } from "@suiss/access-ui/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@suiss/access-ui/components/ui/table";

import { t } from "../i18n/index.js";
import { adminGet } from "../lib/admin.js";
import { HINT, MONO, Notice, NUMBERED, ROWS } from "../ui.js";
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
    <div data-testid="rate-limits" className="flex flex-col gap-4">
      <p className="text-muted-foreground">{t("rateLimitsIntro")}</p>
      <Show l={view}>
        {(v) => (
          <>
            {v.usage.buckets.some((b) => b.above_threshold) && (
              <Notice tone="warning" role="alert" data-testid="rate-limits-warning">
                {t("rateLimitsThreshold", { percent: String(v.usage.threshold_percent) })}
              </Notice>
            )}
            <Card>
              <CardContent className="flex flex-col gap-4">
                {v.usage.buckets.length === 0 ? (
                  <p className={HINT}>{t("none")}</p>
                ) : (
                  <Table data-testid="rate-limits-buckets">
                    <TableHeader>
                      <TableRow className="hover:bg-transparent">
                        <TableHead scope="col">{t("rateLimitsBucket")}</TableHead>
                        <TableHead scope="col">{t("rateLimitsNow")}</TableHead>
                        <TableHead scope="col">{t("rateLimitsAverage1h")}</TableHead>
                        <TableHead scope="col">{t("rateLimitsAverage24h")}</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {v.usage.buckets.map((b) => (
                        <TableRow key={b.name} data-testid="rate-limits-bucket" data-name={b.name}>
                          <TableHead scope="row" className={`${MONO} text-sm text-foreground`}>
                            {b.name}
                          </TableHead>
                          <TableCell
                            data-above={b.above_threshold ? "true" : "false"}
                            className={
                              b.above_threshold ? "font-semibold text-destructive" : undefined
                            }
                          >
                            {percent(b.now_percent)}
                          </TableCell>
                          <TableCell>{percent(b.average_1h_percent)}</TableCell>
                          <TableCell>{percent(b.average_24h_percent)}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
                <h3 className="text-base font-semibold">{t("rateLimitsTopConsumers")}</h3>
                {v.usage.top_consumers.length === 0 ? (
                  <p className={HINT}>{t("none")}</p>
                ) : (
                  <ol data-testid="rate-limits-consumers" className={NUMBERED}>
                    {v.usage.top_consumers.map((c) => (
                      <li key={c.consumer}>
                        <span className={MONO}>{c.consumer}</span> ·{" "}
                        {t("rateLimitsRequests", { n: String(c.requests) })}
                      </li>
                    ))}
                  </ol>
                )}
                <h3 className="text-base font-semibold">{t("rateLimitsEvents")}</h3>
                {v.usage.events.length === 0 ? (
                  <p className={HINT}>{t("none")}</p>
                ) : (
                  <dl className={ROWS} data-testid="rate-limits-events">
                    {v.usage.events.map((e) => (
                      <div key={e.kind}>
                        <dt className={MONO}>{e.kind}</dt>
                        <dd>
                          {t("rateLimitsLastHour", { n: String(e.last_hour) })} ·{" "}
                          {t("rateLimitsLastDay", { n: String(e.last_day) })}
                        </dd>
                      </div>
                    ))}
                  </dl>
                )}
              </CardContent>
            </Card>
          </>
        )}
      </Show>
    </div>
  );
}
