// S11 (§8.5, OP-153 m.3 (w), (bb), (ee), (ff); IDP-37, OP-43, TN-78): the account's own privacy
// screens over the Frontend API, with the session cookie only. Preferences are never authority;
// a deletion says its date and what is kept; the security history shows a masked network and
// no risk score.
import { useCallback, useEffect, useState, type ReactElement } from "react";

import { frontend, json } from "../lib/api.js";
import { t } from "../lib/i18n.js";

const CHANNELS = ["email", "sms", "call", "push"] as const;
const TOPICS = ["campaign", "newsletter", "product_news"] as const;

interface Preferences {
  readonly current: Readonly<Record<string, boolean>>;
  readonly history: readonly {
    readonly channel: string;
    readonly topic: string;
    readonly granted: boolean;
    readonly at: string;
  }[];
}

interface Documents {
  readonly acceptances: readonly {
    readonly document_type: string;
    readonly version: string;
    readonly locale: string;
    readonly at: string;
  }[];
}

interface History {
  readonly days: number;
  readonly entries: readonly {
    readonly at: string;
    readonly category: string;
    readonly event: string;
  }[];
}

type Deletion =
  | { readonly scheduled: false }
  | {
      readonly scheduled: true;
      readonly deleted_on: string;
      readonly cancellable: boolean;
      readonly statement: string;
    };

interface Requests {
  readonly requests: readonly {
    readonly kind: string;
    readonly received_at: string;
    readonly due_at: string;
    readonly outcome?: string | null;
  }[];
}

function PreferencesView(): ReactElement {
  const [prefs, setPrefs] = useState<Preferences | null>(null);
  const [draft, setDraft] = useState<Record<string, boolean>>({});
  const [saved, setSaved] = useState(false);
  const load = useCallback(() => {
    void json<Preferences>(frontend("/v1/account/preferences")).then((p) => {
      setPrefs(p);
      setDraft({ ...p.current });
    });
  }, []);
  useEffect(load, [load]);
  if (prefs === null) return <p>{t("shell.loading")}</p>;
  return (
    <section aria-label={t("privacy.preferences")} data-testid="preferences">
      <h3>{t("privacy.preferences")}</h3>
      <table>
        <thead>
          <tr>
            <th />
            {CHANNELS.map((c) => (
              <th key={c} scope="col">
                {t(`privacy.channel.${c}`)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {TOPICS.map((topic) => (
            <tr key={topic}>
              <th scope="row">{t(`privacy.topic.${topic}`)}</th>
              {CHANNELS.map((c) => {
                const k = `${c}:${topic}`;
                return (
                  <td key={k}>
                    <input
                      type="checkbox"
                      aria-label={`${t(`privacy.topic.${topic}`)} · ${t(`privacy.channel.${c}`)}`}
                      checked={draft[k] ?? false}
                      onChange={(e) => {
                        setSaved(false);
                        setDraft({ ...draft, [k]: e.target.checked });
                      }}
                    />
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
      <button
        type="button"
        onClick={() => {
          const changes = Object.entries(draft)
            .filter(([k, v]) => prefs.current[k] !== v)
            .map(([k, granted]) => {
              const [channel = "", topic = ""] = k.split(":");
              return { channel, topic, granted };
            });
          void json<Preferences>(
            frontend("/v1/account/preferences", { method: "PUT", body: { changes } }),
          ).then((p) => {
            setPrefs(p);
            setDraft({ ...p.current });
            setSaved(true);
          });
        }}
      >
        {t("action.save")}
      </button>
      {saved && <p role="status">{t("privacy.saved")}</p>}
      <h4>{t("privacy.preference_history")}</h4>
      <ul>
        {prefs.history.map((h) => (
          <li key={`${h.at}:${h.channel}:${h.topic}`}>
            {h.at} · {t(`privacy.topic.${h.topic}`)} · {t(`privacy.channel.${h.channel}`)} ·{" "}
            {h.granted ? "✓" : "✗"}
          </li>
        ))}
      </ul>
    </section>
  );
}

function useRead(path: string): unknown {
  const [v, setV] = useState<unknown>(null);
  useEffect(() => {
    void json<unknown>(frontend(path)).then(setV);
  }, [path]);
  return v;
}

function DocumentsView(): ReactElement {
  const d = useRead("/v1/account/documents") as Documents | null;
  return (
    <section aria-label={t("privacy.documents")} data-testid="documents">
      <h3>{t("privacy.documents")}</h3>
      {d === null ? (
        <p>{t("shell.loading")}</p>
      ) : d.acceptances.length === 0 ? (
        <p>{t("privacy.no_documents")}</p>
      ) : (
        <ul>
          {d.acceptances.map((a) => (
            <li key={`${a.document_type}:${a.version}:${a.at}`}>
              {a.document_type} {a.version} · {a.locale} · {a.at}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function HistoryView(): ReactElement {
  const h = useRead("/v1/account/security-history") as History | null;
  return (
    <section
      aria-label={t("privacy.security_history", { days: "90" })}
      data-testid="security-history"
    >
      <h3>{t("privacy.security_history", { days: String(h?.days ?? 90) })}</h3>
      {h === null ? (
        <p>{t("shell.loading")}</p>
      ) : h.entries.length === 0 ? (
        <p>{t("privacy.no_history")}</p>
      ) : (
        <ul>
          {h.entries.map((e) => (
            <li key={`${e.at}:${e.event}`}>
              {e.at} · {e.category}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function DeletionView(): ReactElement {
  const [d, setD] = useState<Deletion | null>(null);
  const load = useCallback(() => {
    void json<Deletion>(frontend("/v1/account/deletion")).then(setD);
  }, []);
  useEffect(load, [load]);
  return (
    <section aria-label={t("privacy.deletion")} data-testid="deletion">
      <h3>{t("privacy.deletion")}</h3>
      {d === null ? (
        <p>{t("shell.loading")}</p>
      ) : !d.scheduled ? (
        <p>{t("privacy.deletion_none")}</p>
      ) : (
        <>
          <p>{t("account.deletion_scheduled")}</p>
          <p>{d.deleted_on}</p>
          <p>{d.statement}</p>
          {d.cancellable && (
            <button
              type="button"
              onClick={() => {
                void frontend("/v1/account/deletion", { method: "DELETE" }).then(load);
              }}
            >
              {t("action.cancel_deletion")}
            </button>
          )}
        </>
      )}
    </section>
  );
}

function RequestsView(): ReactElement {
  const r = useRead("/v1/account/data-requests") as Requests | null;
  return (
    <section aria-label={t("privacy.data_requests")} data-testid="data-requests">
      <h3>{t("privacy.data_requests")}</h3>
      {r === null ? (
        <p>{t("shell.loading")}</p>
      ) : r.requests.length === 0 ? (
        <p>{t("privacy.no_requests")}</p>
      ) : (
        <ul>
          {r.requests.map((q) => (
            <li key={`${q.kind}:${q.received_at}`}>
              {q.kind} · {q.received_at} · {q.due_at}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

export function Privacy(): ReactElement {
  return (
    <div data-testid="privacy">
      <h2>{t("privacy.title")}</h2>
      <PreferencesView />
      <DocumentsView />
      <HistoryView />
      <DeletionView />
      <RequestsView />
    </div>
  );
}
