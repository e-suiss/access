// INV-28, TN-93, §12.3.8, OP-157 m.3 (h): break-glass is a protected Grant given in advance.
// Marking an account gives it no authority; each use is reviewed afterwards by someone else,
// and a drill runs at least every 90 days.

import { Badge } from "@access/ui/components/badge";
import { Button } from "@access/ui/components/button";
import { type ReactElement, useState } from "react";
import * as v from "valibot";

import { t } from "../i18n/index.js";
import { adminGet, change, items, type WriteResult } from "../lib/admin.js";
import { FORM, HINT, MONO, Notice } from "../ui.js";
import { at, type Ctx, Field, Panel, readKey, Show, useLoad, useRun } from "./parts.js";

const CLASSES = ["drill", "emergency", "misuse"] as const;

// OP-159 m.46 (f)
const Accounts = items(
  v.looseObject({
    account_id: v.string(),
    member: v.string(),
    organization: v.string(),
    organization_name: v.string(),
    marked_at: v.number(),
  }),
);

const Uses = items(
  v.looseObject({
    exercise: v.string(),
    drill: v.boolean(),
    used_at: v.number(),
    due_at: v.number(),
    state: v.picklist(["pending", "overdue", "reviewed"]),
    classification: v.nullable(v.picklist(CLASSES)),
    next_due_at: v.exactOptional(v.nullable(v.number())),
  }),
);

const DRILL_EVERY_MS = 90 * 86_400_000;

const classOf = (c: (typeof CLASSES)[number]): string =>
  c === "drill"
    ? t("breakglassClassDrill")
    : c === "emergency"
      ? t("breakglassClassEmergency")
      : t("breakglassClassMisuse");

/** The break-glass screen. */
export function BreakGlass({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const environment = encodeURIComponent(ctx.session.environment);
  const accounts = useLoad(readKey(ctx, `envs/${environment}/breakglass/accounts`), () =>
    adminGet(ctx.instance, `envs/${environment}/breakglass/accounts`, Accounts),
  );
  const reviews = useLoad(readKey(ctx, `envs/${environment}/breakglass/reviews`), () =>
    adminGet(ctx.instance, `envs/${environment}/breakglass/reviews`, Uses),
  );
  const [organization, setOrganization] = useState("");
  const [member, setMember] = useState("");
  const [w, write] = useRun<WriteResult>();
  const [now] = useState(() => Date.now());
  const send = (operation: string, path: string, body: Record<string, unknown>, key?: string) => {
    write(() =>
      change(ctx.instance, ctx.confirm, ctx.session.environment, {
        operation,
        method: "POST",
        path,
        body,
        ...(key === undefined ? {} : { key }),
      }),
    );
  };
  return (
    <>
      <p>{t("breakglassIntro")}</p>
      <Panel id="breakglass-accounts" title={t("breakglassAccountsTitle")}>
        <p>{t("breakglassAccountsIntro")}</p>
        <Show l={accounts}>
          {(p) =>
            p.items.length === 0 ? (
              <p className={HINT}>{t("none")}</p>
            ) : (
              <ul data-testid="breakglass-accounts" className="flex flex-col divide-y">
                {p.items.map((a) => (
                  <li
                    key={`${a.organization}/${a.member}`}
                    className="flex flex-wrap items-center gap-x-2 gap-y-1 py-3 text-sm first:pt-0 last:pb-0"
                  >
                    <span className={MONO}>{a.account_id}</span> ·{" "}
                    {t("breakglassMarkedAt", { name: a.organization_name, date: at(a.marked_at) })}{" "}
                    <Button
                      variant="outline"
                      size="sm"
                      className="ms-auto"
                      onClick={() => {
                        send(
                          "clearBreakglassAccount",
                          `breakglass/accounts/${encodeURIComponent(a.member)}/clear`,
                          { organization: a.organization },
                          a.member,
                        );
                      }}
                    >
                      {t("breakglassClear")}
                    </Button>
                  </li>
                ))}
              </ul>
            )
          }
        </Show>
        <form
          className={FORM}
          onSubmit={(e) => {
            e.preventDefault();
            send("markBreakglassAccount", "breakglass/accounts", { organization, member });
          }}
        >
          <Field
            id="breakglass-organization"
            label={t("breakglassOrganization")}
            value={organization}
            onChange={setOrganization}
          />
          <Field
            id="breakglass-member"
            label={t("breakglassMember")}
            value={member}
            onChange={setMember}
          />
          <Button
            type="submit"
            className="self-start"
            disabled={organization === "" || member === ""}
          >
            {t("breakglassMark")}
          </Button>
        </form>
      </Panel>
      <Panel id="breakglass-grants" title={t("breakglassGrantsTitle")}>
        <Notice role="note" data-testid="breakglass-minimum-two">
          {t("breakglassMinimumTwo")}
        </Notice>
      </Panel>
      <Panel id="breakglass-reviews" title={t("breakglassReviewsTitle")}>
        <Show l={reviews}>
          {(p) =>
            p.items.length === 0 ? (
              <p className={HINT}>{t("breakglassNoReviews")}</p>
            ) : (
              <ul data-testid="breakglass-reviews" className="flex flex-col divide-y">
                {p.items.map((u) => (
                  <li
                    key={u.exercise}
                    className="flex flex-wrap items-center gap-x-2 gap-y-1 py-3 text-sm first:pt-0 last:pb-0"
                  >
                    <span className={MONO}>{u.exercise.slice(0, 12)}</span> ·{" "}
                    {t("breakglassUsed", { date: at(u.used_at) })}
                    {u.drill && <> · {t("breakglassDrill")}</>} ·{" "}
                    {u.state === "reviewed" && u.classification !== null ? (
                      t("breakglassReviewedAs", { class: classOf(u.classification) })
                    ) : (
                      <>
                        {u.state === "overdue" ? (
                          <Badge variant="destructive">{t("breakglassReviewOverdue")}</Badge>
                        ) : (
                          t("breakglassReviewDue", { date: at(u.due_at) })
                        )}{" "}
                        {CLASSES.map((c) => (
                          <Button
                            key={c}
                            variant="outline"
                            size="sm"
                            onClick={() => {
                              send(
                                "reviewBreakglassUse",
                                `breakglass/reviews/${encodeURIComponent(u.exercise)}`,
                                { classification: c },
                                u.exercise,
                              );
                            }}
                          >
                            {t("breakglassReviewAs", { class: classOf(c) })}
                          </Button>
                        ))}
                      </>
                    )}
                  </li>
                ))}
              </ul>
            )
          }
        </Show>
      </Panel>
      <Panel id="breakglass-drills" title={t("breakglassDrillsTitle")}>
        <Show l={reviews}>
          {(p) => {
            const since = accounts.status === "done" ? accounts.value.items : [];
            const last = p.items.filter((u) => u.drill).map((u) => u.used_at);
            if (since.length === 0) {
              return <p className={HINT}>{t("none")}</p>;
            }
            const from =
              last.length > 0 ? Math.max(...last) : Math.min(...since.map((a) => a.marked_at));
            const due = from + DRILL_EVERY_MS;
            return (
              <p data-testid="breakglass-drill">
                {due < now
                  ? t("breakglassDrillOverdue")
                  : t("breakglassDrillDue", { date: at(due) })}
              </p>
            );
          }}
        </Show>
      </Panel>
      <Show l={w}>
        {(r) => <Notice role="status">{t("changeRecorded", { exercise: r.exercise_id })}</Notice>}
      </Show>
    </>
  );
}
