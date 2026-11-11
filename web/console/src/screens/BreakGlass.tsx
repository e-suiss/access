// INV-28, TN-93, §12.3.8, OP-157 m.3 (h): break-glass is a protected Grant given in advance.
// Marking an account gives it no authority; each use is reviewed afterwards by someone else,
// and a drill runs at least every 90 days.
import { useState, type ReactElement } from "react";

import { t } from "../i18n/index.js";
import { adminGet, change, type WriteResult } from "../lib/admin.js";
import { type Ctx, Field, Panel, Show, at, useLoad, useRun } from "./parts.js";

interface Account {
  readonly account_id: string;
  readonly member: string;
  readonly organization: string;
  readonly organization_name: string;
  readonly marked_at: number;
}

interface Use {
  readonly exercise: string;
  readonly drill: boolean;
  readonly used_at: number;
  readonly due_at: number;
  readonly state: "pending" | "overdue" | "reviewed";
  readonly classification: "drill" | "emergency" | "misuse" | null;
  readonly next_due_at?: number | null;
}

interface Page<T> {
  readonly items: readonly T[];
}

const CLASSES = ["drill", "emergency", "misuse"] as const;

const DRILL_EVERY_MS = 90 * 86_400_000;

const className = (c: (typeof CLASSES)[number]): string =>
  c === "drill"
    ? t("breakglassClassDrill")
    : c === "emergency"
      ? t("breakglassClassEmergency")
      : t("breakglassClassMisuse");

/** The break-glass screen. */
export function BreakGlass({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const realm = encodeURIComponent(ctx.session.realm);
  const accounts = useLoad(() =>
    adminGet<Page<Account>>(ctx.instance, `realms/${realm}/breakglass/accounts`),
  );
  const reviews = useLoad(() =>
    adminGet<Page<Use>>(ctx.instance, `realms/${realm}/breakglass/reviews`),
  );
  const [organization, setOrganization] = useState("");
  const [member, setMember] = useState("");
  const [w, write] = useRun<WriteResult>();
  const [now] = useState(() => Date.now());
  const send = (operation: string, path: string, body: Record<string, unknown>, key?: string) => {
    write(() =>
      change(ctx.instance, ctx.confirm, ctx.session.realm, {
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
              <p>{t("none")}</p>
            ) : (
              <ul data-testid="breakglass-accounts">
                {p.items.map((a) => (
                  <li key={`${a.organization}/${a.member}`}>
                    <span className="mono">{a.account_id}</span> ·{" "}
                    {t("breakglassMarkedAt", { name: a.organization_name, date: at(a.marked_at) })}{" "}
                    <button
                      type="button"
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
                    </button>
                  </li>
                ))}
              </ul>
            )
          }
        </Show>
        <form
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
          <button type="submit" disabled={organization === "" || member === ""}>
            {t("breakglassMark")}
          </button>
        </form>
      </Panel>
      <Panel id="breakglass-grants" title={t("breakglassGrantsTitle")}>
        <p role="note" data-testid="breakglass-minimum-two">
          {t("breakglassMinimumTwo")}
        </p>
      </Panel>
      <Panel id="breakglass-reviews" title={t("breakglassReviewsTitle")}>
        <Show l={reviews}>
          {(p) =>
            p.items.length === 0 ? (
              <p>{t("breakglassNoReviews")}</p>
            ) : (
              <ul data-testid="breakglass-reviews">
                {p.items.map((u) => (
                  <li key={u.exercise}>
                    <span className="mono">{u.exercise.slice(0, 12)}</span> ·{" "}
                    {t("breakglassUsed", { date: at(u.used_at) })}
                    {u.drill && <> · {t("breakglassDrill")}</>} ·{" "}
                    {u.state === "reviewed" && u.classification !== null ? (
                      t("breakglassReviewedAs", { class: className(u.classification) })
                    ) : (
                      <>
                        {u.state === "overdue" ? (
                          <strong>{t("breakglassReviewOverdue")}</strong>
                        ) : (
                          t("breakglassReviewDue", { date: at(u.due_at) })
                        )}{" "}
                        {CLASSES.map((c) => (
                          <button
                            key={c}
                            type="button"
                            onClick={() => {
                              send(
                                "reviewBreakglassUse",
                                `breakglass/reviews/${encodeURIComponent(u.exercise)}`,
                                { classification: c },
                                u.exercise,
                              );
                            }}
                          >
                            {t("breakglassReviewAs", { class: className(c) })}
                          </button>
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
              return <p>{t("none")}</p>;
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
        {(r) => <p role="status">{t("changeRecorded", { exercise: r.exercise_id })}</p>}
      </Show>
    </>
  );
}
