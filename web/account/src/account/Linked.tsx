// S11 (§8.5; TN-65, TN-68, OP-153 m.3 (m), (z)): the other sign-ins linked to this account and
// the apps it shares identity details with. A linked sign-in is never called "merged"; linking
// proves control of the other sign-in at its provider. Sharing details with an app is not
// authority: stopping it keeps the record and the app receives no details until asked again.
import { useCallback, useEffect, useState, type ReactElement } from "react";

import { frontend, json } from "../lib/api.js";
import { t } from "../lib/i18n.js";
import { useAnnouncer, when } from "./common.js";

interface LinkedList {
  readonly linked: readonly {
    readonly link: string;
    readonly provider: string;
    readonly linked_at_ms: number;
    readonly verified_at_ms: number | null;
  }[];
}

interface Apps {
  readonly apps: readonly {
    readonly client_id: string;
    readonly app: string;
    readonly claims: readonly string[];
    readonly since_ms: number;
  }[];
}

const LINK_CODES = {
  "last-sign-in-method": "methods.last_method",
  "no-such-provider": "linked.unavailable",
} as const;

/** "Linked sign-ins". */
export function LinkedSignIns(): ReactElement {
  const [list, setList] = useState<LinkedList | null>(null);
  const { say, fail, region } = useAnnouncer();
  const reload = useCallback(() => {
    json<LinkedList>(frontend("/v1/account/linked"))
      .then(setList)
      .catch((e: unknown) => {
        fail(e);
      });
  }, [fail]);
  useEffect(reload, [reload]);
  return (
    <section aria-labelledby="linked-heading" data-testid="linked-sign-ins">
      <h3 id="linked-heading">{t("settings.linked_sign_ins")}</h3>
      {region}
      {list === null ? (
        <p>{t("shell.loading")}</p>
      ) : list.linked.length === 0 ? (
        <p>{t("linked.none")}</p>
      ) : (
        <ul className="rows">
          {list.linked.map((l) => (
            <li key={l.link} className="row" data-testid="linked-row">
              <strong>{l.provider}</strong>
              <span className="meta">
                {" · "}
                {t("linked.since", { date: when(l.linked_at_ms) })}
              </span>
              <div className="actions">
                <button
                  type="button"
                  className="secondary"
                  aria-label={`${t("action.remove")}: ${l.provider}`}
                  onClick={() => {
                    void json(
                      frontend(`/v1/account/linked/${encodeURIComponent(l.link)}`, {
                        method: "DELETE",
                      }),
                    )
                      .then(() => {
                        say(t("methods.removed"));
                        reload();
                      })
                      .catch((e: unknown) => {
                        fail(e, LINK_CODES);
                      });
                  }}
                >
                  {t("action.remove")}
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

/** "Connected apps" (OP-153 m.3 (z)). */
export function ConnectedApps(): ReactElement {
  const [apps, setApps] = useState<Apps | null>(null);
  const { say, fail, region } = useAnnouncer();
  const reload = useCallback(() => {
    json<Apps>(frontend("/v1/account/connected-apps"))
      .then(setApps)
      .catch((e: unknown) => {
        fail(e);
      });
  }, [fail]);
  useEffect(reload, [reload]);
  return (
    <section aria-labelledby="apps-heading" data-testid="connected-apps">
      <h3 id="apps-heading">{t("settings.connected_apps")}</h3>
      {region}
      {apps === null ? (
        <p>{t("shell.loading")}</p>
      ) : apps.apps.length === 0 ? (
        <p>{t("apps.none")}</p>
      ) : (
        <ul className="rows">
          {apps.apps.map((a) => (
            <li key={a.client_id} className="row" data-testid="app-row">
              <strong>{a.app}</strong>
              <p className="meta">{t("apps.claims", { claims: a.claims.join(", ") })}</p>
              <p className="meta">{t("apps.since", { date: when(a.since_ms) })}</p>
              <div className="actions">
                <button
                  type="button"
                  className="secondary"
                  aria-label={`${t("action.stop_sharing")}: ${a.app}`}
                  onClick={() => {
                    void json(
                      frontend(`/v1/account/connected-apps/${encodeURIComponent(a.client_id)}`, {
                        method: "DELETE",
                      }),
                    )
                      .then(() => {
                        say(t("apps.stopped"));
                        reload();
                      })
                      .catch((e: unknown) => {
                        fail(e);
                      });
                  }}
                >
                  {t("action.stop_sharing")}
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
