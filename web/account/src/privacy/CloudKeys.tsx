// OP-156 m.3 (w), E59: One's cloud key permissions, each letting a checked cloud environment
// open named data of the person for one purpose, for at most a day. The person sees every live
// one and stops it with one tap; stopping tells the environment to destroy its copies.
import { useCallback, useEffect, useState, type ReactElement } from "react";

import { useAnnouncer, when } from "../account/common.js";
import { frontend, json } from "../lib/api.js";
import { t } from "../lib/i18n.js";

/** What `GET /v1/me/cloud-key-permissions` answers. */
export interface CloudKeyList {
  readonly permissions: readonly {
    readonly id: string;
    readonly purpose: string;
    readonly classes: readonly string[];
    readonly valid_until: string;
    readonly state: string;
    readonly destroy: boolean;
  }[];
}

/** "Cloud use of your data by One". */
export function CloudKeys(): ReactElement | null {
  const [list, setList] = useState<CloudKeyList | null>(null);
  const { say, fail, region } = useAnnouncer();
  const reload = useCallback(() => {
    json<CloudKeyList>(frontend("/v1/me/cloud-key-permissions"))
      .then(setList)
      .catch((e: unknown) => {
        fail(e);
      });
  }, [fail]);
  useEffect(reload, [reload]);
  const live = list?.permissions.filter((p) => p.state === "live") ?? [];
  if (list !== null && live.length === 0) return null;
  return (
    <section aria-labelledby="cloud-key-heading" data-testid="cloud-keys">
      <h3 id="cloud-key-heading">{t("cloud_key.title")}</h3>
      {region}
      {list === null ? (
        <p>{t("shell.loading")}</p>
      ) : (
        <ul className="rows">
          {live.map((p) => (
            <li key={p.id} className="row" data-testid="cloud-key-row">
              <p>
                {t("cloud_key.intro", {
                  classes: p.classes.join(", "),
                  purpose: p.purpose,
                })}
              </p>
              <span className="meta">{t("cloud_key.until", { time: when(p.valid_until) })}</span>
              <div className="actions">
                <button
                  type="button"
                  className="secondary"
                  onClick={() => {
                    void json(
                      frontend(`/v1/me/cloud-key-permissions/${encodeURIComponent(p.id)}/revoke`, {
                        method: "POST",
                      }),
                    )
                      .then(() => {
                        say(t("cloud_key.revoke"));
                        reload();
                      })
                      .catch((e: unknown) => {
                        fail(e);
                      });
                  }}
                >
                  {t("cloud_key.revoke")}
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
