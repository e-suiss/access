// Ek B 3089, TN-128: the identity plane's own, authority-free screens; the cookie is enough
import { loadKernel } from "@esuiss/access";
import { useCallback, useEffect, useState, type ReactElement } from "react";

import { t } from "../i18n/index.js";
import { json, type SessionInfo, type SessionRow } from "../lib/api.js";

function when(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

export function Profile({ session }: { readonly session: SessionInfo }): ReactElement {
  return (
    <main id="main" tabIndex={-1}>
      <h1>{t("profileTitle")}</h1>
      <dl className="facts">
        <dt>{t("profileName")}</dt>
        <dd data-testid="display-name">{session.display_name}</dd>
        <dt>{t("profileAccount")}</dt>
        <dd className="mono">{session.account}</dd>
        <dt>{t("profileRealm")}</dt>
        <dd className="mono">{session.realm}</dd>
      </dl>
      <p className="hint">{t("profileEditNote")}</p>
    </main>
  );
}

export function Sessions({ onEnded }: { readonly onEnded: () => void }): ReactElement {
  const [rows, setRows] = useState<readonly SessionRow[] | null>(null);
  const [failed, setFailed] = useState(false);

  const load = useCallback(() => {
    json<{ sessions: SessionRow[] }>("/sessions").then(
      (v) => {
        setRows(v.sessions);
      },
      () => {
        setFailed(true);
      },
    );
  }, []);

  useEffect(load, [load]);

  const end = (row: SessionRow) => {
    json(`/sessions/${encodeURIComponent(row.id)}/revoke`, { method: "POST" }).then(
      () => {
        if (row.current) onEnded();
        else load();
      },
      () => {
        setFailed(true);
      },
    );
  };

  return (
    <main id="main" tabIndex={-1}>
      <h1>{t("sessionsTitle")}</h1>
      <p>{t("sessionsIntro")}</p>
      {failed && <p role="alert">{t("unavailable")}</p>}
      {rows === null && !failed && <p aria-busy="true">{t("loading")}</p>}
      {rows !== null && (
        <table>
          <thead>
            <tr>
              <th scope="col">{t("sessionsKind")}</th>
              <th scope="col">{t("sessionsCreated")}</th>
              <th scope="col">{t("sessionsLastSeen")}</th>
              <th scope="col">{t("sessionsActions")}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <th scope="row">
                  {r.kind === "console" ? t("sessionsConsole") : t("sessionsLogin")}
                  {r.current && <span className="tag"> {t("sessionsCurrent")}</span>}
                </th>
                <td>{when(r.created_at)}</td>
                <td>{when(r.last_seen_at)}</td>
                <td>
                  <button
                    type="button"
                    onClick={() => {
                      end(r);
                    }}
                  >
                    {t("sessionsEnd")}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </main>
  );
}

export function About(): ReactElement {
  const [kernel, setKernel] = useState<string | null>(null);
  const [server, setServer] = useState<string | null>(null);
  useEffect(() => {
    loadKernel().then(
      (k) => {
        setKernel(k.apiVersion());
      },
      () => {
        setKernel(t("aboutUnknown"));
      },
    );
    json<{ server_version?: string }>("/about").then(
      (v) => {
        setServer(v.server_version ?? t("aboutUnknown"));
      },
      () => {
        setServer(t("aboutUnknown"));
      },
    );
  }, []);
  return (
    <main id="main" tabIndex={-1}>
      <h1>{t("aboutTitle")}</h1>
      <dl className="facts" aria-busy={kernel === null || server === null}>
        <dt>{t("aboutKernel")}</dt>
        <dd className="mono" data-testid="kernel-api-version">
          {kernel ?? t("loading")}
        </dd>
        <dt>{t("aboutServer")}</dt>
        <dd className="mono" data-testid="server-version">
          {server ?? t("loading")}
        </dd>
      </dl>
    </main>
  );
}
