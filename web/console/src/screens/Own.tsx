// Ek B 3089, TN-128: the identity plane's own, authority-free screens; the cookie is enough
import { loadKernel } from "@esuiss/access";
import { useCallback, useEffect, useState, type ReactElement } from "react";

import { Badge } from "@suiss/access-ui/components/ui/badge";
import { Button } from "@suiss/access-ui/components/ui/button";
import { Card, CardContent } from "@suiss/access-ui/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@suiss/access-ui/components/ui/table";

import { t } from "../i18n/index.js";
import { json, type SessionInfo, type SessionRow } from "../lib/api.js";
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
            <dt>{t("profileRealm")}</dt>
            <dd className={MONO}>{session.realm}</dd>
          </dl>
          <p className={HINT}>{t("profileEditNote")}</p>
        </CardContent>
      </Card>
    </Page>
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
    <Page title={t("sessionsTitle")} intro={t("sessionsIntro")}>
      {failed && <Failure>{t("unavailable")}</Failure>}
      {rows === null && !failed && <Busy />}
      {rows !== null && (
        <Card className="py-2">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead scope="col">{t("sessionsKind")}</TableHead>
                <TableHead scope="col">{t("sessionsCreated")}</TableHead>
                <TableHead scope="col">{t("sessionsLastSeen")}</TableHead>
                <TableHead scope="col">
                  <span className="sr-only">{t("sessionsActions")}</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((r) => (
                <TableRow key={r.id}>
                  <TableHead scope="row" className="text-sm font-medium text-foreground">
                    <span className="flex items-center gap-2">
                      {r.kind === "console" ? t("sessionsConsole") : t("sessionsLogin")}
                      {r.current && <Badge variant="outline">{t("sessionsCurrent")}</Badge>}
                    </span>
                  </TableHead>
                  <TableCell>{when(r.created_at)}</TableCell>
                  <TableCell>{when(r.last_seen_at)}</TableCell>
                  <TableCell className="text-end">
                    <Button
                      variant="destructive"
                      size="sm"
                      onPress={() => {
                        end(r);
                      }}
                    >
                      {t("sessionsEnd")}
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}
    </Page>
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
