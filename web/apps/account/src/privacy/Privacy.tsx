// S11 (§8.5, OP-153 m.3 (w), (bb), (ee), (ff); IDP-37, OP-43, TN-78): the account's own privacy
// screens over the Frontend API, with the session cookie only. Preferences are never authority;
// a deletion says its date and what is kept; the security history shows a masked network and
// no risk score.
import { Button } from "@access/ui/components/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@access/ui/components/table";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type ReactElement } from "react";
import * as v from "valibot";

import { frontend, json } from "../lib/api.js";
import { t } from "../lib/i18n.js";
import { Actions, Check, Loading, Meta, Nothing, PageTitle, Panel, Part } from "../lib/ui.js";
import { CloudKeys } from "./CloudKeys.js";

const CHANNELS = ["email", "sms", "call", "push"] as const;
const TOPICS = ["campaign", "newsletter", "product_news"] as const;

const LIST = "divide-y text-sm";

const Preferences = v.object({
  current: v.record(v.string(), v.boolean()),
  history: v.array(
    v.object({ channel: v.string(), topic: v.string(), granted: v.boolean(), at: v.string() }),
  ),
  /** OP-156 m.3 (c): present when the environment records consent with İYS through Relay. */
  iys: v.optional(
    v.object({
      channels: v.record(
        v.string(),
        v.object({
          consent: v.picklist(["approved", "rejected"]),
          status: v.picklist(["recorded", "failed", "pending"]),
          at: v.nullable(v.string()),
        }),
      ),
    }),
  ),
});
type Preferences = v.InferOutput<typeof Preferences>;

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

const Documents = v.object({
  acceptances: v.array(
    v.object({
      document_type: v.string(),
      version: v.string(),
      locale: v.string(),
      at: v.string(),
    }),
  ),
});

const History = v.object({
  days: v.number(),
  entries: v.array(v.object({ at: v.string(), category: v.string(), event: v.string() })),
});

const Deletion = v.variant("scheduled", [
  v.object({ scheduled: v.literal(false) }),
  v.object({
    scheduled: v.literal(true),
    deleted_on: v.string(),
    cancellable: v.boolean(),
    statement: v.string(),
  }),
]);

const Requests = v.object({
  requests: v.array(
    v.object({
      kind: v.string(),
      received_at: v.string(),
      due_at: v.string(),
      outcome: v.optional(v.nullable(v.string())),
    }),
  ),
});

const PREFERENCES = "/v1/account/preferences";
const DELETION = "/v1/account/deletion";

function useRead<S extends v.GenericSchema>(path: string, schema: S): v.InferOutput<S> | undefined {
  return useQuery({ queryKey: [path], queryFn: () => json(frontend(path), schema) }).data;
}

function PreferencesView(): ReactElement {
  const queries = useQueryClient();
  const prefs = useRead(PREFERENCES, Preferences);
  const [edited, setDraft] = useState<Record<string, boolean> | null>(null);
  const [saved, setSaved] = useState(false);
  const save = useMutation({
    mutationFn: (changes: readonly { channel: string; topic: string; granted: boolean }[]) =>
      json(frontend(PREFERENCES, { method: "PUT", body: { changes } }), Preferences),
    onSuccess: (p) => {
      queries.setQueryData([PREFERENCES], p);
      setDraft(null);
      setSaved(true);
    },
  });
  if (prefs === undefined) return <Loading rows={3} />;
  const draft = edited ?? prefs.current;
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
          onClick={() => {
            const changes = Object.entries(draft)
              .filter(([k, granted]) => prefs.current[k] !== granted)
              .map(([k, granted]) => {
                const [channel = "", topic = ""] = k.split(":");
                return { channel, topic, granted };
              });
            save.mutate(changes);
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

function DocumentsView(): ReactElement {
  const d = useRead("/v1/account/documents", Documents);
  return (
    <Panel
      aria-label={t("privacy.documents")}
      data-testid="documents"
      title={t("privacy.documents")}
    >
      {d === undefined ? (
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
  const h = useRead("/v1/account/security-history", History);
  return (
    <Panel
      aria-label={t("privacy.security_history", { days: "90" })}
      data-testid="security-history"
      title={t("privacy.security_history", { days: String(h?.days ?? 90) })}
    >
      {h === undefined ? (
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
  const queries = useQueryClient();
  const d = useRead(DELETION, Deletion);
  const cancel = useMutation({
    mutationFn: () => frontend(DELETION, { method: "DELETE" }),
    onSuccess: () => {
      void queries.invalidateQueries({ queryKey: [DELETION] });
    },
  });
  return (
    <Panel aria-label={t("privacy.deletion")} data-testid="deletion" title={t("privacy.deletion")}>
      {d === undefined ? (
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
                onClick={() => {
                  cancel.mutate();
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
  const r = useRead("/v1/account/data-requests", Requests);
  return (
    <Panel
      aria-label={t("privacy.data_requests")}
      data-testid="data-requests"
      title={t("privacy.data_requests")}
    >
      {r === undefined ? (
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
