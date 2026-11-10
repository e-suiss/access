// IDP-35, OP-156 m.3 (q), §8.17.9.8: the realm's HR sources, their imports and the HR
// connectors. Registering, retiring and importing are each one signed change; an HR source's
// records select people for roles only through the domain's protected subject-selection
// acceptance of its issuer, so a role a rule over them holds shows "Sync from HR".
import { useState, type ReactElement } from "react";

import { t } from "../i18n/index.js";
import { adminGet, change, type WriteResult } from "../lib/admin.js";
import { search } from "../lib/adp.js";
import { type Ctx, Field, Panel, Show, useLoad, useRun } from "./parts.js";

interface HrSource {
  readonly name: string;
  readonly issuer: string;
  readonly status: string;
  readonly people: number;
  readonly version: number;
}

interface HrConnector {
  readonly name: string;
  readonly source: string;
  readonly vendor: string;
  readonly status: string;
}

interface Page<T> {
  readonly items: readonly T[];
}

interface AcceptedSource {
  readonly use: string;
  readonly issuer: { readonly party?: string };
}

interface SourcesReport {
  readonly sources: readonly AcceptedSource[];
}

/** The HR systems `services/hr-connector` reads, in the order they ship. */
export const VENDORS = [
  ["personio", "Personio"],
  ["bamboohr", "BambooHR"],
  ["hibob", "HiBob"],
  ["workday", "Workday"],
  ["successfactors", "SAP SuccessFactors"],
  ["kolayik", "Kolay İK"],
  ["logo", "Logo"],
] as const;

function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) {
    s += String.fromCharCode(b);
  }
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** The records of an import file: JSONL lines that are not blank, or CSV rows after the header (RFC 4180 quoting). */
export function recordCount(format: "jsonl" | "csv", text: string): number {
  if (format === "jsonl") {
    return text.split("\n").filter((l) => l.trim() !== "").length;
  }
  let rows = 0;
  let quoted = false;
  let filled = false;
  for (const c of text.replace(/^\uFEFF/, "")) {
    if (c === '"') {
      quoted = !quoted;
      filled = true;
    } else if (c === "\n" && !quoted) {
      if (filled) {
        rows += 1;
      }
      filled = false;
    } else if (c !== "\r") {
      filled = true;
    }
  }
  if (filled) {
    rows += 1;
  }
  return Math.max(rows - 1, 0);
}

async function digest(text: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return b64url(new Uint8Array(d));
}

/** Whether the domain accepts `issuer` for subject selection: then the source's records select. */
function accepted(report: SourcesReport | undefined, issuer: string): boolean {
  return (report?.sources ?? []).some(
    (s) => s.use === "subject-selection" && s.issuer.party === issuer,
  );
}

/** The HR screen. */
export function Hr({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const realm = encodeURIComponent(ctx.session.realm);
  const sources = useLoad(() =>
    adminGet<Page<HrSource>>(ctx.instance, `realms/${realm}/hr-sources`),
  );
  const connectors = useLoad(() =>
    adminGet<Page<HrConnector>>(ctx.instance, `realms/${realm}/hr-connectors`),
  );
  const report = useLoad(() =>
    search<SourcesReport>(ctx.instance, "sources", {}).then((a) => a.results[0]),
  );
  const [name, setName] = useState("");
  const [connector, setConnector] = useState("");
  const [target, setTarget] = useState("");
  const [vendor, setVendor] = useState<string>(VENDORS[0][0]);
  const [into, setInto] = useState("");
  const [format, setFormat] = useState<"jsonl" | "csv">("csv");
  const [file, setFile] = useState<File | undefined>(undefined);
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
  const upload = () => {
    if (file === undefined || into === "") {
      return;
    }
    write(async () => {
      const content = await file.text();
      const operation = format === "csv" ? "importHrCsv" : "importHrBatch";
      const route = format === "csv" ? "records:csv" : "records:batch";
      return change(ctx.instance, ctx.confirm, ctx.session.realm, {
        operation,
        method: "POST",
        path: `hr-sources/${encodeURIComponent(into)}/${route}`,
        key: into,
        body: {
          file: await digest(content),
          records: recordCount(format, content),
          content,
        },
      });
    });
  };
  return (
    <>
      <Panel id="hr-sources" title={t("hrSourcesTitle")}>
        <p>{t("hrSourcesIntro")}</p>
        <Show l={sources}>
          {(s) =>
            s.items.length === 0 ? (
              <p>{t("none")}</p>
            ) : (
              <ul data-testid="hr-sources">
                {s.items.map((src) => (
                  <li key={src.name} data-testid="hr-source" data-name={src.name}>
                    <strong className="mono">{src.name}</strong> ·{" "}
                    {src.status === "live" ? t("hrLive") : t("hrRetired")} ·{" "}
                    {t("hrPeople", { n: String(src.people) })}
                    <dl className="facts">
                      <dt>{t("acceptedIssuer")}</dt>
                      <dd className="mono">{src.issuer}</dd>
                      <dt>{t("hrRoleSource")}</dt>
                      <dd data-testid="hr-sync">
                        {report.status === "done" && accepted(report.value, src.issuer)
                          ? t("hrSyncFromHr", { source: src.name })
                          : t("hrNotAccepted")}
                      </dd>
                    </dl>
                    {src.status === "live" && (
                      <button
                        type="button"
                        onClick={() => {
                          send(
                            "retireHrSource",
                            `hr-sources/${encodeURIComponent(src.name)}/retire`,
                            {},
                            src.name,
                          );
                        }}
                      >
                        {t("hrRetire", { name: src.name })}
                      </button>
                    )}
                  </li>
                ))}
              </ul>
            )
          }
        </Show>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            send("registerHrSource", "hr-sources", { name });
          }}
        >
          <h4>{t("hrSourceRegister")}</h4>
          <Field
            id="hr-source-name"
            label={t("hrSourceName")}
            value={name}
            onChange={setName}
            hint={t("hrNameHint")}
          />
          <button type="submit" disabled={name === ""}>
            {t("hrRegisterSend")}
          </button>
        </form>
      </Panel>
      <Panel id="hr-import" title={t("hrImportTitle")}>
        <p>{t("hrImportIntro")}</p>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            upload();
          }}
        >
          <Field
            id="hr-import-source"
            label={t("hrImportSource")}
            value={into}
            onChange={setInto}
          />
          <fieldset>
            <legend>{t("hrImportFormat")}</legend>
            <label>
              <input
                type="radio"
                name="hr-format"
                checked={format === "csv"}
                onChange={() => {
                  setFormat("csv");
                }}
              />{" "}
              {t("hrCsv")}
            </label>{" "}
            <label>
              <input
                type="radio"
                name="hr-format"
                checked={format === "jsonl"}
                onChange={() => {
                  setFormat("jsonl");
                }}
              />{" "}
              {t("hrJsonl")}
            </label>
          </fieldset>
          <p className="mono" data-testid="hr-columns">
            employee_id,email,department,title,manager,start_date,end_date,employment_status
          </p>
          <label htmlFor="hr-import-file">{t("hrImportFile")}</label>{" "}
          <input
            id="hr-import-file"
            type="file"
            accept={format === "csv" ? ".csv,text/csv" : ".jsonl,application/jsonl"}
            onChange={(e) => {
              setFile(e.target.files?.[0]);
            }}
          />
          <p>
            <button type="submit" disabled={file === undefined || into === ""}>
              {t("hrImportSend")}
            </button>
          </p>
        </form>
        <p role="note" data-testid="hr-lifecycle">
          {t("hrLifecycle")}
        </p>
      </Panel>
      <Panel id="hr-connectors" title={t("hrConnectorsTitle")}>
        <p>{t("hrConnectorsIntro")}</p>
        <Show l={connectors}>
          {(c) =>
            c.items.length === 0 ? (
              <p>{t("none")}</p>
            ) : (
              <ul data-testid="hr-connectors">
                {c.items.map((k) => (
                  <li key={k.name}>
                    <span className="mono">{k.name}</span> ·{" "}
                    {VENDORS.find(([v]) => v === k.vendor)?.[1] ?? k.vendor} →{" "}
                    <span className="mono">{k.source}</span> ·{" "}
                    {k.status === "live" ? t("hrLive") : t("hrRetired")}
                    {k.status === "live" && (
                      <>
                        {" "}
                        <button
                          type="button"
                          onClick={() => {
                            send(
                              "retireHrConnector",
                              `hr-connectors/${encodeURIComponent(k.name)}/retire`,
                              {},
                              k.name,
                            );
                          }}
                        >
                          {t("hrRetire", { name: k.name })}
                        </button>
                      </>
                    )}
                  </li>
                ))}
              </ul>
            )
          }
        </Show>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            send("registerHrConnector", "hr-connectors", {
              name: connector,
              source: target,
              vendor,
            });
          }}
        >
          <h4>{t("hrConnectorRegister")}</h4>
          <Field
            id="hr-connector-name"
            label={t("hrConnectorName")}
            value={connector}
            onChange={setConnector}
            hint={t("hrNameHint")}
          />
          <Field
            id="hr-connector-source"
            label={t("hrImportSource")}
            value={target}
            onChange={setTarget}
          />
          <label htmlFor="hr-connector-vendor">{t("hrVendor")}</label>{" "}
          <select
            id="hr-connector-vendor"
            value={vendor}
            onChange={(e) => {
              setVendor(e.target.value);
            }}
          >
            {VENDORS.map(([v, label]) => (
              <option key={v} value={v}>
                {label}
              </option>
            ))}
          </select>
          <p>
            <button type="submit" disabled={connector === "" || target === ""}>
              {t("hrRegisterSend")}
            </button>
          </p>
        </form>
      </Panel>
      <Show l={w}>
        {(r) => <p role="status">{t("changeRecorded", { exercise: r.exercise_id })}</p>}
      </Show>
    </>
  );
}
