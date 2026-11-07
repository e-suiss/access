// X11, TN-131: the signature screen is its own surface. It renders only what the Kernel decoded
// from the bytes about to be signed (never the UI's own copy), as text nodes, and nothing is
// signed until the user presses Sign.
import { useCallback, useEffect, useRef, useState, type ReactElement } from "react";

import { t } from "./i18n/index.js";
import type { Confirm, SignatureView } from "./lib/instance.js";

interface Pending {
  readonly view: SignatureView;
  readonly resolve: (signed: boolean) => void;
}

function time(ms: string): string {
  const n = Number(ms);
  return Number.isSafeInteger(n) ? new Date(n).toISOString() : ms;
}

function modeText(mode: SignatureView["statement"]["mode"]): string {
  if (mode === "commit") return t("signatureModeCommit");
  if (mode === "check") return t("signatureModeCheck");
  return t("signatureModeContinue");
}

function Body({ view }: { readonly view: SignatureView }): ReactElement {
  const s = view.statement;
  return (
    <>
      <dl className="signature-facts">
        <dt>{t("signatureMode")}</dt>
        <dd>{modeText(s.mode)}</dd>
        <dt>{t("signatureCapacity")}</dt>
        <dd>
          {s.capacity === "own"
            ? t("signatureCapacityOwn")
            : t("signatureCapacityFor", { party: s.capacity.for })}
        </dd>
        <dt>{t("signatureDomain")}</dt>
        <dd className="mono">{s.domain}</dd>
      </dl>
      {view.intents.map((i) => (
        <section
          key={i.digest}
          className="signature-intent"
          aria-label={`${i.action.namespace}.${i.action.name}`}
        >
          <dl>
            <dt>{t("signatureAction")}</dt>
            <dd className="mono">
              {i.action.namespace}.{i.action.name} v{i.action.major}
            </dd>
            <dt>{t("signatureResources")}</dt>
            <dd>
              <ul>
                {i.resources.map((r) => (
                  <li key={`${r.namespace}:${r.path.join("/")}`} className="mono">
                    {r.namespace}:[{r.path.join("/")}]
                  </li>
                ))}
              </ul>
            </dd>
            {Object.keys(i.params).length > 0 && (
              <>
                <dt>{t("signatureParams")}</dt>
                <dd>
                  <ul>
                    {Object.entries(i.params).map(([k, v]) => (
                      <li key={k}>
                        <span className="mono">{k}</span>: {v}
                      </li>
                    ))}
                  </ul>
                </dd>
              </>
            )}
            <dt>{t("signatureValidity")}</dt>
            <dd className="mono">
              {time(i.validity.from)} – {time(i.validity.until)}
            </dd>
          </dl>
        </section>
      ))}
    </>
  );
}

/** The signature screen and the `confirm` the signing functions call. */
export function useSignatureScreen(): readonly [Confirm, ReactElement | null] {
  const [pending, setPending] = useState<Pending | null>(null);
  const dialog = useRef<HTMLDialogElement>(null);

  const confirm = useCallback<Confirm>(
    (view) =>
      new Promise<boolean>((resolve) => {
        setPending({ view, resolve });
      }),
    [],
  );

  useEffect(() => {
    const d = dialog.current;
    if (pending !== null && d !== null && !d.open) d.showModal();
  }, [pending]);

  const finish = (signed: boolean) => {
    pending?.resolve(signed);
    dialog.current?.close();
    setPending(null);
  };

  const element =
    pending === null ? null : (
      <dialog
        ref={dialog}
        className="signature-surface"
        aria-labelledby="signature-title"
        aria-describedby="signature-intro"
        onCancel={(e) => {
          e.preventDefault();
          finish(false);
        }}
      >
        <h2 id="signature-title">{t("signatureTitle")}</h2>
        <p id="signature-intro">{t("signatureIntro")}</p>
        <Body view={pending.view} />
        <div className="actions">
          <button
            type="button"
            onClick={() => {
              finish(false);
            }}
          >
            {t("signatureCancel")}
          </button>
          <button
            type="button"
            className="primary"
            onClick={() => {
              finish(true);
            }}
          >
            {t("signatureSign")}
          </button>
        </div>
      </dialog>
    );
  return [confirm, element] as const;
}
