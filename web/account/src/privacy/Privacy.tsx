// S11 (§8.5, OP-153 m.3 (w), (bb), (ee), (ff); IDP-37, OP-43, TN-78): the account's own privacy
// screens over the Frontend API, with the session cookie only. Preferences are never authority;
// a deletion says its date and what is kept; the security history shows a masked network and
// no risk score.
import { Button } from "@suiss/access-ui/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@suiss/access-ui/components/ui/table";
import { useCallback, useEffect, useState, type ReactElement } from "react";

import { frontend, json } from "../lib/api.js";
import { t } from "../lib/i18n.js";
import { Actions, Check, Loading, Meta, Nothing, PageTitle, Panel, Part } from "../lib/ui.js";
import { CloudKeys } from "./CloudKeys.js";

const CHANNELS = ["email", "sms", "call", "push"] as const;
const TOPICS = ["campaign", "newsletter", "product_news"] as const;

const LIST = "divide-y text-sm";

interface Preferences {
  readonly current: Readonly<Record<string, boolean>>;
  readonly history: readonly {
    readonly channel: string;
    readonly topic: string;
    readonly granted: boolean;
    readonly at: string;
  }[];
  /** OP-156 m.3 (c): present when the realm records consent with İYS through Relay. */
  readonly iys?: {
    readonly channels: Readonly<
      Record<
        string,
        {
          readonly consent: "approved" | "rejected";
          readonly status: "recorded" | "failed" | "pending";
          readonly at: string | null;
        }
      >
    >;
  };
}

function IysView({ iys }: { readonly iys: NonNullable<Preferences["iys"]> }): ReactElement {
  return (
    <Part aria-label={t("iys.title")} data-testid="iys">
      <h4 className="font-semibold">{t("iys.title")}</h4>
      <Meta>{t("iys.intro")}</Meta>
      <ul className={LIST}>
        {Object.entries(iys.channels).map(([channel, c]) => (
          <li key={channel} data-testid={`iys-${channel}`} className="py-2">
            {t(`privacy.channel.${channel}`)} ·{" "}
            {c.status === "recorded"
              ? t("iys.recorded", { time: c.at ?? "" })
              : c.status === "failed"
                ? t("iys.failed")
                : t("iys.pending")}
          </li>
        ))}
      </ul>
    </Part>
  );
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
  if (prefs === null) return <Loading rows={3} />;
  return (
    <Panel
      aria-label={t("privacy.preferences")}
      data-testid="preferences"
      title={t("privacy.preferences")}
    >
      <Table>
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            <TableHead />
            {CHANNELS.map((c) => (
              <TableHead key={c} scope="col" className="text-center">
                {t(`privacy.channel.${c}`)}
              </TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {TOPICS.map((topic) => (
            <TableRow key={topic}>
              <TableHead scope="row" className="text-sm text-foreground">
                {t(`privacy.topic.${topic}`)}
              </TableHead>
              {CHANNELS.map((c) => {
                const k = `${c}:${topic}`;
                return (
                  <TableCell key={k}>
                    <div className="flex justify-center">
                      <Check
                        aria-label={`${t(`privacy.topic.${topic}`)} · ${t(`privacy.channel.${c}`)}`}
                        checked={draft[k] ?? false}
                        onChange={(e) => {
                          setSaved(false);
                          setDraft({ ...draft, [k]: e.target.checked });
                        }}
                      />
                    </div>
                  </TableCell>
                );
              })}
            </TableRow>
          ))}
        </TableBody>
      </Table>
      <Actions>
        <Button
          onPress={() => {
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
        </Button>
        {saved && (
          <p role="status" className="text-sm text-muted-foreground">
            {t("privacy.saved")}
          </p>
        )}
      </Actions>
      {prefs.iys !== undefined && <IysView iys={prefs.iys} />}
      <Part>
        <h4 className="font-semibold">{t("privacy.preference_history")}</h4>
        <ul className={LIST}>
          {prefs.history.map((h) => (
            <li key={`${h.at}:${h.channel}:${h.topic}`} className="py-2">
              {h.at} · {t(`privacy.topic.${h.topic}`)} · {t(`privacy.channel.${h.channel}`)} ·{" "}
              {h.granted ? "✓" : "✗"}
            </li>
          ))}
        </ul>
      </Part>
    </Panel>
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
    <Panel
      aria-label={t("privacy.documents")}
      data-testid="documents"
      title={t("privacy.documents")}
    >
      {d === null ? (
        <Loading />
      ) : d.acceptances.length === 0 ? (
        <Nothing>{t("privacy.no_documents")}</Nothing>
      ) : (
        <ul className={LIST}>
          {d.acceptances.map((a) => (
            <li key={`${a.document_type}:${a.version}:${a.at}`} className="py-2">
              {a.document_type} {a.version} · {a.locale} · {a.at}
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

function HistoryView(): ReactElement {
  const h = useRead("/v1/account/security-history") as History | null;
  return (
    <Panel
      aria-label={t("privacy.security_history", { days: "90" })}
      data-testid="security-history"
      title={t("privacy.security_history", { days: String(h?.days ?? 90) })}
    >
      {h === null ? (
        <Loading />
      ) : h.entries.length === 0 ? (
        <Nothing>{t("privacy.no_history")}</Nothing>
      ) : (
        <ul className={LIST}>
          {h.entries.map((e) => (
            <li key={`${e.at}:${e.event}`} className="py-2">
              {e.at} · {e.category}
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

function DeletionView(): ReactElement {
  const [d, setD] = useState<Deletion | null>(null);
  const load = useCallback(() => {
    void json<Deletion>(frontend("/v1/account/deletion")).then(setD);
  }, []);
  useEffect(load, [load]);
  return (
    <Panel aria-label={t("privacy.deletion")} data-testid="deletion" title={t("privacy.deletion")}>
      {d === null ? (
        <Loading rows={1} />
      ) : !d.scheduled ? (
        <Meta>{t("privacy.deletion_none")}</Meta>
      ) : (
        <>
          <div className="flex flex-col gap-1 rounded-xl bg-muted p-4">
            <p className="font-semibold">{t("account.deletion_scheduled")}</p>
            <p>{d.deleted_on}</p>
            <p className="text-sm text-muted-foreground">{d.statement}</p>
          </div>
          {d.cancellable && (
            <Actions>
              <Button
                variant="outline"
                onPress={() => {
                  void frontend("/v1/account/deletion", { method: "DELETE" }).then(load);
                }}
              >
                {t("action.cancel_deletion")}
              </Button>
            </Actions>
          )}
        </>
      )}
    </Panel>
  );
}

function RequestsView(): ReactElement {
  const r = useRead("/v1/account/data-requests") as Requests | null;
  return (
    <Panel
      aria-label={t("privacy.data_requests")}
      data-testid="data-requests"
      title={t("privacy.data_requests")}
    >
      {r === null ? (
        <Loading />
      ) : r.requests.length === 0 ? (
        <Nothing>{t("privacy.no_requests")}</Nothing>
      ) : (
        <ul className={LIST}>
          {r.requests.map((q) => (
            <li key={`${q.kind}:${q.received_at}`} className="py-2">
              {q.kind} · {q.received_at} · {q.due_at}
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

export function Privacy(): ReactElement {
  return (
    <div data-testid="privacy" className="flex flex-col gap-6">
      <PageTitle>{t("privacy.title")}</PageTitle>
      <PreferencesView />
      <CloudKeys />
      <DocumentsView />
      <HistoryView />
      <DeletionView />
      <RequestsView />
    </div>
  );
}
