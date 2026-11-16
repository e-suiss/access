// §12.5.4, TN-127, OP-158 m.3 (v): Observability ▸ Rate limits. Each bucket's share in use now
// and over 1 h and 24 h, the heaviest consumers as digests, refusals by type and the warning
// threshold, as the management API reports them; nothing here changes a limit.

import { Card, CardContent } from "@access/ui/components/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@access/ui/components/table";
import type { ReactElement } from "react";
import * as v from "valibot";

import { t } from "../i18n/index.js";
import { adminGet } from "../lib/admin.js";
import { HINT, MONO, Notice, NUMBERED, ROWS } from "../ui.js";
import { type Ctx, readKey, Show, useLoad } from "./parts.js";

// OP-159 m.46 (f)
const Bucket = v.looseObject({
  name: v.string(),
  now_percent: v.number(),
  average_1h_percent: v.number(),
  average_24h_percent: v.number(),
  above_threshold: v.boolean(),
});

const Consumer = v.looseObject({ consumer: v.string(), requests: v.number() });

const Event = v.looseObject({ kind: v.string(), last_hour: v.number(), last_day: v.number() });

const RateLimitsView = v.looseObject({
  rate_limit_rps: v.number(),
  usage: v.looseObject({
    buckets: v.array(Bucket),
    top_consumers: v.array(Consumer),
    events: v.array(Event),
    threshold_percent: v.number(),
  }),
});

const percent = (n: number) => `${String(n)}%`;

/** The rate limits screen. */
export function RateLimits({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const environment = encodeURIComponent(ctx.session.environment);
  const view = useLoad(readKey(ctx, `envs/${environment}/rate-limits`), () =>
    adminGet(ctx.instance, `envs/${environment}/rate-limits`, RateLimitsView),
  );
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
