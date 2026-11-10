// OP-156 m.3 (s), X22: the realm's export sinks of the read-only SIEM projection. Registering and
// retiring a sink are each one signed change; the secret is write-only and never shown again.
// What a sink holds is a copy, never the record: the audit records answer every question.
import { useState, type ReactElement } from "react";

import { t } from "../i18n/index.js";
import { adminGet, change, type WriteResult } from "../lib/admin.js";
import { type Ctx, Field, Panel, Show, useLoad, useRun } from "./parts.js";

interface Delivery {
  readonly sent: string;
  readonly failures: number;
  readonly failing_since: string | null;
  readonly last_error: string | null;
  readonly last_sent_at: string | null;
}

interface Sink {
  readonly name: string;
  readonly adapter: string;
  readonly preset: string | null;
  readonly format: string | null;
  readonly endpoint: string;
  readonly has_secret: boolean;
  readonly status: string;
  readonly record: string;
  readonly delivery: Delivery | null;
}

interface Page<T> {
  readonly items: readonly T[];
}

/** The adapter and preset an administrator picks, as the API names them. */
const KINDS = [
  { value: "collector:splunk", adapter: "collector", preset: "splunk" },
  { value: "collector:sentinel", adapter: "collector", preset: "sentinel" },
  { value: "collector:datadog", adapter: "collector", preset: "datadog" },
  { value: "collector:elastic", adapter: "collector", preset: "elastic" },
  { value: "collector", adapter: "collector" },
  { value: "s3_parquet", adapter: "s3_parquet" },
  { value: "otlp", adapter: "otlp" },
  { value: "syslog:cef", adapter: "syslog", format: "cef" },
  { value: "syslog:leef", adapter: "syslog", format: "leef" },
] as const;

type KindValue = (typeof KINDS)[number]["value"];

function kindLabel(s: Sink): string {
  return [s.adapter, s.preset ?? s.format].filter((x) => x !== null).join(" · ");
}

function status(s: Sink): string {
  if (s.status !== "live") return t("exportRetired");
  if (s.delivery !== null && s.delivery.failures > 0) {
    return t("exportFailing", { code: s.delivery.last_error ?? "" });
  }
  return t("exportDelivering", { sent: s.delivery?.sent ?? "0" });
}

/** The SIEM export screen. */
export function Export({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const realm = encodeURIComponent(ctx.session.realm);
  const sinks = useLoad(() => adminGet<Page<Sink>>(ctx.instance, `realms/${realm}/export-sinks`));
  const [name, setName] = useState("");
  const [kind, setKind] = useState<KindValue>("collector:splunk");
  const [endpoint, setEndpoint] = useState("");
  const [settings, setSettings] = useState("{}");
  const [secret, setSecret] = useState("");
  const [w, write] = useRun<WriteResult>();
  const send = (operation: string, path: string, body: Record<string, unknown>, key?: string) => {
    write(() =>
      change(ctx.instance, ctx.confirm, ctx.session.realm, {
        operation,
        method: "POST",
        path,
        body,
        ...(key === undefined ? {} : { key }),
      }),
    );
  };
  const register = () => {
    const k = KINDS.find((x) => x.value === kind) ?? KINDS[0];
    let parsed: unknown;
    try {
      parsed = JSON.parse(settings);
    } catch {
      parsed = undefined;
    }
    send("registerExportSink", "export-sinks", {
      name,
      adapter: k.adapter,
      ...("preset" in k ? { preset: k.preset } : {}),
      ...("format" in k ? { format: k.format } : {}),
      endpoint,
      settings: parsed,
      ...(secret === "" ? {} : { secret }),
    });
    setSecret("");
  };
  return (
    <>
      <Panel id="export-sinks" title={t("exportSinksTitle")}>
        <p>{t("exportSinksIntro")}</p>
        <p role="note" data-testid="export-copy-note">
          {t("exportCopyNote")} <a href="/console/audit/records">{t("exportRecordsLink")}</a>
        </p>
        <Show l={sinks}>
          {(p) =>
            p.items.length === 0 ? (
              <p>{t("none")}</p>
            ) : (
              <ul data-testid="export-sinks">
                {p.items.map((s) => (
                  <li key={s.name}>
                    <span className="mono">{s.name}</span> · {kindLabel(s)} ·{" "}
                    <span className="mono">{s.endpoint}</span> · {status(s)}
                    {s.has_secret ? ` · ${t("exportSecretStored")}` : ""}
                    {s.status === "live" && (
                      <>
                        {" "}
                        <button
                          type="button"
                          onClick={() => {
                            send(
                              "retireExportSink",
                              `export-sinks/${encodeURIComponent(s.name)}/retire`,
                              {},
                              s.name,
                            );
                          }}
                        >
                          {t("exportRetire", { name: s.name })}
                        </button>
                      </>
                    )}
                  </li>
                ))}
              </ul>
            )
          }
        </Show>
      </Panel>
      <Panel id="export-register" title={t("exportRegister")}>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            register();
          }}
        >
          <Field
            id="export-name"
            label={t("exportName")}
            value={name}
            onChange={setName}
            hint={t("exportNameHint")}
          />
          <p className="field">
            <label htmlFor="export-kind">{t("exportKind")}</label>
            <select
              id="export-kind"
              value={kind}
              onChange={(e) => {
                setKind(e.target.value as KindValue);
              }}
            >
              {KINDS.map((k) => (
                <option key={k.value} value={k.value}>
                  {k.value.replace(":", " · ")}
                </option>
              ))}
            </select>
          </p>
          <Field
            id="export-endpoint"
            label={t("exportEndpoint")}
            value={endpoint}
            onChange={setEndpoint}
            hint={t("exportEndpointHint")}
          />
          <p className="field">
            <label htmlFor="export-settings">{t("exportSettings")}</label>
            <textarea
              id="export-settings"
              className="mono"
              value={settings}
              onChange={(e) => {
                setSettings(e.target.value);
              }}
            />
          </p>
          <p className="field">
            <label htmlFor="export-secret">{t("exportSecret")}</label>
            <input
              id="export-secret"
              type="password"
              autoComplete="off"
              value={secret}
              aria-describedby="export-secret-hint"
              onChange={(e) => {
                setSecret(e.target.value);
              }}
            />
            <span id="export-secret-hint" className="hint">
              {t("exportSecretHint")}
            </span>
          </p>
          <button type="submit" disabled={name === "" || endpoint === ""}>
            {t("exportRegisterSend")}
          </button>
        </form>
      </Panel>
      <Show l={w}>
        {(r) => <p role="status">{t("changeRecorded", { exercise: r.exercise_id })}</p>}
      </Show>
    </>
  );
}
