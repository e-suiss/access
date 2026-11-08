// X11, TN-131: the signature screen renders only what the Kernel decoded from the bytes about to
// be signed, as text nodes; nothing is signed until the person presses Sign. There is no
// "remember this" (XI-19).
import { useCallback, useState, type ReactElement } from "react";

import { t } from "../lib/i18n.js";
import type { Confirm, SignatureView } from "../lib/instance.js";

interface Pending {
  readonly view: SignatureView;
  readonly resolve: (signed: boolean) => void;
}

/** The screen and the `confirm` the signing calls take. */
export function useSignature(): {
  readonly confirm: Confirm;
  readonly dialog: ReactElement | null;
} {
  const [pending, setPending] = useState<Pending | null>(null);
  const confirm = useCallback<Confirm>(
    (view) =>
      new Promise<boolean>((resolve) => {
        setPending({ view, resolve });
      }),
    [],
  );
  const close = (signed: boolean) => {
    pending?.resolve(signed);
    setPending(null);
  };
  const dialog =
    pending === null ? null : (
      <div className="dialog" role="dialog" aria-modal="true" aria-label={t("sign.title")}>
        <h2>{t("sign.title")}</h2>
        {pending.view.intents.map((i) => (
          <dl key={i.digest} className="facts">
            <dt>{t("sign.action", { action: `${i.action.namespace}.${i.action.name}` })}</dt>
            <dd>
              <ul>
                {i.resources.map((r) => (
                  <li key={`${r.namespace}:${r.path.join("/")}`} className="mono">
                    {t("sign.resource", { resource: `${r.namespace}:${r.path.join("/")}` })}
                  </li>
                ))}
              </ul>
            </dd>
          </dl>
        ))}
        <div className="actions">
          <button
            type="button"
            onClick={() => {
              close(true);
            }}
          >
            {t("action.sign")}
          </button>
          <button
            type="button"
            className="secondary"
            onClick={() => {
              close(false);
            }}
          >
            {t("action.cancel")}
          </button>
        </div>
      </div>
    );
  return { confirm, dialog };
}
