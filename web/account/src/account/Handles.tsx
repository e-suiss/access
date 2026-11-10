// E56, OP-156 m.4 (Q20): the person's names beside their permanent ID, a Suiss subdomain or a
// domain they own. A name shows only once the site points back to the person; until then it
// waits and can be checked again. A removed name is never handed to anyone else.
import { useCallback, useEffect, useState, type ReactElement } from "react";

import { frontend, json } from "../lib/api.js";
import { t } from "../lib/i18n.js";
import { useAnnouncer } from "./common.js";

/** What `GET /v1/me/handles` answers. */
export interface HandleList {
  readonly handles: readonly {
    readonly id: string;
    readonly handle: string;
    readonly kind: string;
    readonly state: string;
    readonly shown: boolean;
  }[];
}

/** "Your names". */
export function Handles(): ReactElement {
  const [list, setList] = useState<HandleList | null>(null);
  const [draft, setDraft] = useState("");
  const { say, fail, region } = useAnnouncer();
  const reload = useCallback(() => {
    json<HandleList>(frontend("/v1/me/handles"))
      .then(setList)
      .catch((e: unknown) => {
        fail(e);
      });
  }, [fail]);
  useEffect(reload, [reload]);
  const post = (path: string, body?: unknown): void => {
    void json(frontend(path, body === undefined ? { method: "POST" } : { method: "POST", body }))
      .then(() => {
        say(t("handle.title"));
        reload();
      })
      .catch((e: unknown) => {
        fail(e);
      });
  };
  return (
    <section aria-labelledby="handles-heading" data-testid="handles">
      <h3 id="handles-heading">{t("handle.title")}</h3>
      <p className="meta">{t("handle.intro")}</p>
      {region}
      {list === null ? (
        <p>{t("shell.loading")}</p>
      ) : (
        <ul className="rows">
          {list.handles.map((h) => (
            <li key={h.id} className="row" data-testid="handle-row">
              <strong>{h.handle}</strong>
              {h.shown ? null : (
                <span className="meta">
                  {" · "}
                  {t("handle.pending", { site: h.handle })}
                </span>
              )}
              <div className="actions">
                {h.shown ? null : (
                  <button
                    type="button"
                    className="secondary"
                    onClick={() => {
                      post(`/v1/me/handles/${encodeURIComponent(h.id)}/verify`);
                    }}
                  >
                    {t("handle.check")}
                  </button>
                )}
                <button
                  type="button"
                  className="secondary"
                  aria-label={`${t("handle.remove")}: ${h.handle}`}
                  onClick={() => {
                    post(`/v1/me/handles/${encodeURIComponent(h.id)}/retire`);
                  }}
                >
                  {t("handle.remove")}
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          post("/v1/me/handles", { handle: draft });
          setDraft("");
        }}
      >
        <label>
          {t("handle.add")}
          <input
            value={draft}
            onChange={(e) => {
              setDraft(e.target.value);
            }}
          />
        </label>
        <button type="submit">{t("handle.add")}</button>
      </form>
    </section>
  );
}
