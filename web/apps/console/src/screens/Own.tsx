// Ek B 3089, TN-128: the identity plane's own, authority-free screens; the cookie is enough
import { loadKernel } from "@esuiss/access";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { ReactElement } from "react";
import * as v from "valibot";

import { Badge } from "@access/ui/components/badge";
import { Button } from "@access/ui/components/button";
import { Card, CardContent } from "@access/ui/components/card";

import { DataTable } from "../DataTable.js";
import { t } from "../i18n/index.js";
import { json, type SessionInfo, SessionRow, send } from "../lib/api.js";
import { Busy, FACTS, Failure, HINT, MONO, Page } from "../ui.js";

function when(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

export function Profile({ session }: { readonly session: SessionInfo }): ReactElement {
  return (
    <Page title={t("profileTitle")}>
      <Card>
        <CardContent className="flex flex-col gap-4">
          <dl className={FACTS}>
            <dt>{t("profileName")}</dt>
            <dd data-testid="display-name">{session.display_name}</dd>
            <dt>{t("profileAccount")}</dt>
            <dd className={MONO}>{session.account}</dd>
            <dt>{t("profileEnvironment")}</dt>
            <dd className={MONO}>{session.environment}</dd>
          </dl>
          <p className={HINT}>{t("profileEditNote")}</p>
        </CardContent>
      </Card>
    </Page>
  );
}

const SESSIONS = ["sessions"] as const;

const Sessions_ = v.object({ sessions: v.array(SessionRow) });

const About_ = v.looseObject({ server_version: v.exactOptional(v.string()) });

export function Sessions({ onEnded }: { readonly onEnded: () => void }): ReactElement {
  const client = useQueryClient();
  const list = useQuery({ queryKey: SESSIONS, queryFn: () => json("/sessions", Sessions_) });
  const end = useMutation({
    mutationFn: (row: SessionRow) =>
      send(`/sessions/${encodeURIComponent(row.id)}/revoke`, { method: "POST" }),
    retry: false,
    onSuccess: (_, row) => {
      if (row.current) onEnded();
      else void client.invalidateQueries({ queryKey: SESSIONS });
    },
  });
  const failed = list.isError || end.isError;

  return (
    <Page title={t("sessionsTitle")} intro={t("sessionsIntro")}>
      {failed && <Failure>{t("unavailable")}</Failure>}
      {list.isPending && <Busy />}
      {list.data !== undefined && (
        <Card className="py-2">
          <DataTable
            rows={list.data.sessions}
            rowKey={(r) => r.id}
            label={t("sessionsTitle")}
            columns={[
              {
                id: "kind",
                header: t("sessionsKind"),
                rowHeader: true,
                cell: (r) => (
                  <span className="flex items-center gap-2">
                    {r.kind === "console" ? t("sessionsConsole") : t("sessionsLogin")}
                    {r.current && <Badge variant="outline">{t("sessionsCurrent")}</Badge>}
                  </span>
                ),
              },
              { id: "created", header: t("sessionsCreated"), cell: (r) => when(r.created_at) },
              { id: "seen", header: t("sessionsLastSeen"), cell: (r) => when(r.last_seen_at) },
              {
                id: "actions",
                header: <span className="sr-only">{t("sessionsActions")}</span>,
                className: "text-end",
                cell: (r) => (
                  <Button
                    variant="destructive"
                    size="sm"
                    onClick={() => {
                      end.mutate(r);
                    }}
                  >
                    {t("sessionsEnd")}
                  </Button>
                ),
              },
            ]}
          />
        </Card>
      )}
    </Page>
  );
}

export function About(): ReactElement {
  const k = useQuery({
    queryKey: ["kernel-version"],
    queryFn: async () => (await loadKernel()).apiVersion(),
    staleTime: Number.POSITIVE_INFINITY,
  });
  const about = useQuery({ queryKey: ["about"], queryFn: () => json("/about", About_) });
  const kernel = k.isPending ? null : (k.data ?? t("aboutUnknown"));
  const server = about.isPending ? null : (about.data?.server_version ?? t("aboutUnknown"));
  return (
    <Page title={t("aboutTitle")}>
      <Card>
        <CardContent>
          <dl className={FACTS} aria-busy={kernel === null || server === null}>
            <dt>{t("aboutKernel")}</dt>
            <dd className={MONO} data-testid="kernel-api-version">
              {kernel ?? t("loading")}
            </dd>
            <dt>{t("aboutServer")}</dt>
            <dd className={MONO} data-testid="server-version">
              {server ?? t("loading")}
            </dd>
          </dl>
        </CardContent>
      </Card>
    </Page>
  );
}
