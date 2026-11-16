// OP-156 m.3 (s), X22: the environment's export sinks of the read-only SIEM projection. Registering and
// retiring a sink are each one signed change; the secret is write-only and never shown again.
// What a sink holds is a copy, never the record: the audit records answer every question.

import { Badge } from "@access/ui/components/badge";
import { Button } from "@access/ui/components/button";
import { FieldDescription, FieldLabel, Field as FieldRoot } from "@access/ui/components/field";
import { Input } from "@access/ui/components/input";
import { NativeSelect, NativeSelectOption } from "@access/ui/components/native-select";
import { Textarea } from "@access/ui/components/textarea";
import { Link } from "@tanstack/react-router";
import { type ReactElement, useState } from "react";
import * as v from "valibot";

import { t } from "../i18n/index.js";
import { adminGet, change, items, type WriteResult } from "../lib/admin.js";
import { FORM, HINT, MONO, Notice } from "../ui.js";
import { type Ctx, Field, Panel, readKey, Show, useLoad, useRun } from "./parts.js";

// OP-159 m.46 (f)
const Delivery = v.looseObject({
  sent: v.string(),
  failures: v.number(),
  failing_since: v.nullable(v.string()),
  last_error: v.nullable(v.string()),
  last_sent_at: v.nullable(v.string()),
});

const Sink = v.looseObject({
  name: v.string(),
  adapter: v.string(),
  preset: v.nullable(v.string()),
  format: v.nullable(v.string()),
  endpoint: v.string(),
  has_secret: v.boolean(),
  status: v.string(),
  record: v.string(),
  delivery: v.nullable(Delivery),
});

type Sink = v.InferOutput<typeof Sink>;

const Sinks = items(Sink);

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
  const environment = encodeURIComponent(ctx.session.environment);
  const sinks = useLoad(readKey(ctx, `envs/${environment}/export-sinks`), () =>
    adminGet(ctx.instance, `envs/${environment}/export-sinks`, Sinks),
  );
  const [name, setName] = useState("");
  const [kind, setKind] = useState<KindValue>("collector:splunk");
  const [endpoint, setEndpoint] = useState("");
  const [settings, setSettings] = useState("{}");
  const [secret, setSecret] = useState("");
  const [w, write] = useRun<WriteResult>();
  const send = (operation: string, path: string, body: Record<string, unknown>, key?: string) => {
    write(() =>
      change(ctx.instance, ctx.confirm, ctx.session.environment, {
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
        <Notice role="note" data-testid="export-copy-note">
          {t("exportCopyNote")}{" "}
          <Link
            to="/$environment/audit/{-$screen}"
            params={{ environment: ctx.session.environment, screen: "records" }}
            className="text-primary underline underline-offset-2 hover:text-foreground"
          >
            {t("exportRecordsLink")}
          </Link>
        </Notice>
        <Show l={sinks}>
          {(p) =>
            p.items.length === 0 ? (
              <p className={HINT}>{t("none")}</p>
            ) : (
              <ul data-testid="export-sinks" className="flex flex-col divide-y">
                {p.items.map((s) => (
                  <li
                    key={s.name}
                    className="flex flex-wrap items-center gap-x-2 gap-y-1 py-3 text-sm first:pt-0 last:pb-0"
                  >
                    <span className={`${MONO} font-medium`}>{s.name}</span> · {kindLabel(s)} ·{" "}
                    <span className={MONO}>{s.endpoint}</span> ·{" "}
                    <Badge variant={s.status === "live" ? "outline" : "secondary"}>
                      {status(s)}
                    </Badge>
                    {s.has_secret ? ` · ${t("exportSecretStored")}` : ""}
                    {s.status === "live" && (
                      <>
                        {" "}
                        <Button
                          variant="outline"
                          size="sm"
                          className="ms-auto"
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
                        </Button>
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
          className={FORM}
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
          <FieldRoot className="gap-2">
            <FieldLabel htmlFor="export-kind" className="text-sm">
              {t("exportKind")}
            </FieldLabel>
            <NativeSelect
              id="export-kind"
              size="sm"
              value={kind}
              onChange={(e) => {
                setKind(e.target.value as KindValue);
              }}
            >
              {KINDS.map((k) => (
                <NativeSelectOption key={k.value} value={k.value}>
                  {k.value.replace(":", " · ")}
                </NativeSelectOption>
              ))}
            </NativeSelect>
          </FieldRoot>
          <Field
            id="export-endpoint"
            label={t("exportEndpoint")}
            value={endpoint}
            onChange={setEndpoint}
            hint={t("exportEndpointHint")}
          />
          <FieldRoot className="gap-2">
            <FieldLabel htmlFor="export-settings" className="text-sm">
              {t("exportSettings")}
            </FieldLabel>
            <Textarea
              id="export-settings"
              className={`${MONO} text-sm`}
              value={settings}
              onChange={(e) => {
                setSettings(e.target.value);
              }}
            />
          </FieldRoot>
          <FieldRoot className="gap-2">
            <FieldLabel htmlFor="export-secret" className="text-sm">
              {t("exportSecret")}
            </FieldLabel>
            <Input
              id="export-secret"
              type="password"
              size="md"
              autoComplete="off"
              value={secret}
              aria-describedby="export-secret-hint"
              onChange={(e) => {
                setSecret(e.target.value);
              }}
            />
            <FieldDescription id="export-secret-hint">{t("exportSecretHint")}</FieldDescription>
          </FieldRoot>
          <Button type="submit" className="self-start" disabled={name === "" || endpoint === ""}>
            {t("exportRegisterSend")}
          </Button>
        </form>
      </Panel>
      <Show l={w}>
        {(r) => <Notice role="status">{t("changeRecorded", { exercise: r.exercise_id })}</Notice>}
      </Show>
    </>
  );
}
