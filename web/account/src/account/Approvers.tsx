// S11, OP-156 m.3 (d): the person's approvers, apps on their phone that approve sign-ins by push
// after the number on the sign-in page is typed in. An approver registers itself from its app with
// its own key; here they are listed and removed. Removing needs a recent sign-in and deletes
// nothing on the server.
import { useCallback, useEffect, useState, type ReactElement } from "react";

import { frontend, json } from "../lib/api.js";
import { t } from "../lib/i18n.js";
import { useAnnouncer, when } from "./common.js";

/** What `GET /v1/approvers` answers. */
export interface ApproverList {
  readonly approvers: readonly {
    readonly id: string;
    readonly name: string;
    readonly device_key: string;
    readonly registered_at: string;
    readonly last_used_at: string | null;
  }[];
}

const CODES = { "no-such-approver": "methods.removed" } as const;

/** "Approvers". */
export function Approvers(): ReactElement {
  const [list, setList] = useState<ApproverList | null>(null);
  const { say, fail, region } = useAnnouncer();
  const reload = useCallback(() => {
    json<ApproverList>(frontend("/v1/approvers"))
      .then(setList)
      .catch((e: unknown) => {
        fail(e);
      });
  }, [fail]);
  useEffect(reload, [reload]);
  return (
    <section aria-labelledby="approvers-heading" data-testid="approvers">
      <h3 id="approvers-heading">{t("approvers.title")}</h3>
      <p className="meta">{t("approvers.intro")}</p>
      {region}
      {list === null ? (
        <p>{t("shell.loading")}</p>
      ) : list.approvers.length === 0 ? (
        <p>{t("approvers.none")}</p>
      ) : (
        <ul className="rows">
          {list.approvers.map((a) => (
            <li key={a.id} className="row" data-testid="approver-row">
              <strong>{a.name}</strong>
              <span className="meta">
                {" · "}
                {t("methods.added_on", { date: when(a.registered_at) })}
              </span>
              <div className="actions">
                <button
                  type="button"
                  className="secondary"
                  aria-label={`${t("approvers.remove")}: ${a.name}`}
                  onClick={() => {
                    void json(
                      frontend(`/v1/approvers/${encodeURIComponent(a.id)}/retire`, {
                        method: "POST",
                      }),
                    )
                      .then(() => {
                        say(t("methods.removed"));
                        reload();
                      })
                      .catch((e: unknown) => {
                        fail(e, CODES);
                      });
                  }}
                >
                  {t("approvers.remove")}
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
