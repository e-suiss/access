// IDP-32, OP-156 m.3 (p): the realm's Linux client hosts. Registering a host, retiring it, its
// offline limits and its break-glass switch are each one signed change. A host resolves and
// signs in exactly the people whose ssh.login access names its server group; sudo asks for a
// security key every time and never works offline.
import { useState, type ReactElement } from "react";

import { t } from "../i18n/index.js";
import { adminGet, change, type WriteResult } from "../lib/admin.js";
import { type Ctx, Field, Panel, Show, useLoad, useRun } from "./parts.js";

interface Host {
  readonly name: string;
  readonly host_group: string;
  readonly certificate: string;
  readonly sudo_ct: number;
  readonly nss_ttl_s: number;
  readonly console_ttl_s: number;
  readonly break_glass: boolean;
  readonly status: string;
}

interface Page<T> {
  readonly items: readonly T[];
}

const hours = (s: number): string => String(Math.round((s / 3600) * 10) / 10);

/** The Linux client screen. */
export function Linux({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const realm = encodeURIComponent(ctx.session.realm);
  const hosts = useLoad(() => adminGet<Page<Host>>(ctx.instance, `realms/${realm}/linux-hosts`));
  const [name, setName] = useState("");
  const [group, setGroup] = useState("");
  const [certificate, setCertificate] = useState("");
  const [w, write] = useRun<WriteResult>();
  const send = (
    operation: string,
    method: "POST" | "PUT",
    path: string,
    body: Record<string, unknown>,
    key?: string,
  ) => {
    write(() =>
      change(ctx.instance, ctx.confirm, ctx.session.realm, {
        operation,
        method,
        path,
        body,
        ...(key === undefined ? {} : { key }),
      }),
    );
  };
  const at = (h: Host, rest: string) => `linux-hosts/${encodeURIComponent(h.name)}/${rest}`;
  return (
    <>
      <Panel id="linux-hosts" title={t("linuxHostsTitle")}>
        <p>{t("linuxHostsIntro")}</p>
        <Show l={hosts}>
          {(p) =>
            p.items.length === 0 ? (
              <p>{t("none")}</p>
            ) : (
              <ul data-testid="linux-hosts">
                {p.items.map((h) => (
                  <li key={h.name}>
                    <span className="mono">{h.name}</span> · {h.host_group} ·{" "}
                    {h.status === "live" ? t("linuxHostLive") : t("linuxHostRetired")}
                    <dl className="facts">
                      <dt>{t("linuxOffline")}</dt>
                      <dd>
                        {t("linuxOfflineLimits", {
                          nss: hours(h.nss_ttl_s),
                          console: hours(h.console_ttl_s),
                        })}
                      </dd>
                      <dt>{t("linuxSudo")}</dt>
                      <dd>{t("linuxSudoTier", { ct: String(h.sudo_ct) })}</dd>
                      <dt>{t("linuxBreakGlass")}</dt>
                      <dd>{h.break_glass ? t("linuxBreakGlassOn") : t("linuxBreakGlassOff")}</dd>
                    </dl>
                    {h.status === "live" && (
                      <p>
                        <button
                          type="button"
                          onClick={() => {
                            send(
                              "putLinuxOfflinePolicy",
                              "PUT",
                              at(h, "offline-policy"),
                              { nss_ttl_s: 0, console_ttl_s: 0 },
                              h.name,
                            );
                          }}
                        >
                          {t("linuxOfflineOff", { name: h.name })}
                        </button>{" "}
                        <button
                          type="button"
                          className={h.break_glass ? "" : "danger"}
                          onClick={() => {
                            send(
                              "putLinuxBreakGlassPolicy",
                              "PUT",
                              at(h, "break-glass-policy"),
                              { enabled: !h.break_glass },
                              h.name,
                            );
                          }}
                        >
                          {h.break_glass
                            ? t("linuxBreakGlassDisable", { name: h.name })
                            : t("linuxBreakGlassEnable", { name: h.name })}
                        </button>{" "}
                        <button
                          type="button"
                          onClick={() => {
                            send("retireLinuxHost", "POST", at(h, "retire"), {}, h.name);
                          }}
                        >
                          {t("linuxHostRetire", { name: h.name })}
                        </button>
                      </p>
                    )}
                  </li>
                ))}
              </ul>
            )
          }
        </Show>
        <p role="note" data-testid="linux-break-glass-note">
          {t("linuxBreakGlassNote")}
        </p>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            send("registerLinuxHost", "POST", "linux-hosts", {
              name,
              host_group: group,
              certificate,
            });
          }}
        >
          <h4>{t("linuxHostRegister")}</h4>
          <Field
            id="linux-host-name"
            label={t("linuxHostName")}
            value={name}
            onChange={setName}
            hint={t("sshGroupNameHint")}
          />
          <Field
            id="linux-host-group"
            label={t("linuxHostGroup")}
            value={group}
            onChange={setGroup}
          />
          <Field
            id="linux-host-certificate"
            label={t("linuxHostCertificate")}
            value={certificate}
            onChange={setCertificate}
            hint={t("linuxHostCertificateHint")}
          />
          <button type="submit" disabled={name === "" || group === "" || certificate === ""}>
            {t("linuxHostRegisterSend")}
          </button>
        </form>
      </Panel>
      <Panel id="linux-setup" title={t("linuxSetupTitle")}>
        <pre className="mono" data-testid="linux-nsswitch">
          {"passwd: files access\ngroup:  files access"}
        </pre>
        <pre className="mono" data-testid="linux-pam">
          {"auth required /usr/lib/access/pam_access.so"}
        </pre>
      </Panel>
      <Show l={w}>
        {(r) => <p role="status">{t("changeRecorded", { exercise: r.exercise_id })}</p>}
      </Show>
    </>
  );
}
