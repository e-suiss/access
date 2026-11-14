// X11, TN-131: the signature screen is its own surface. It renders only what the Kernel decoded
// from the bytes about to be signed (never the UI's own copy), as text nodes, and nothing is
// signed until the user presses Sign.
import { useCallback, useState, type ReactElement } from "react";

import { Button } from "@suiss/access-ui/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@suiss/access-ui/components/ui/dialog";

import { t } from "./i18n/index.js";
import type { Confirm, SignatureView } from "./lib/instance.js";
import { BULLETS, MONO } from "./ui.js";

const FACTS =
  "grid grid-cols-1 gap-x-6 gap-y-1 sm:grid-cols-[minmax(8rem,max-content)_minmax(0,1fr)] [&>dd]:mb-2 sm:[&>dd]:mb-0 [&>dt]:font-semibold";

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
      <dl className={FACTS}>
        <dt>{t("signatureMode")}</dt>
        <dd>{modeText(s.mode)}</dd>
        <dt>{t("signatureCapacity")}</dt>
        <dd>
          {s.capacity === "own"
            ? t("signatureCapacityOwn")
            : t("signatureCapacityFor", { party: s.capacity.for })}
        </dd>
        <dt>{t("signatureDomain")}</dt>
        <dd className={MONO}>{s.domain}</dd>
      </dl>
      {view.intents.map((i) => (
        <section
          key={i.digest}
          className="border-t border-neutral-400 pt-4"
          aria-label={`${i.action.namespace}.${i.action.name}`}
        >
          <dl className={FACTS}>
            <dt>{t("signatureAction")}</dt>
            <dd className={MONO}>
              {i.action.namespace}.{i.action.name} v{i.action.major}
            </dd>
            <dt>{t("signatureResources")}</dt>
            <dd>
              <ul className={BULLETS}>
                {i.resources.map((r) => (
                  <li key={`${r.namespace}:${r.path.join("/")}`} className={MONO}>
                    {r.namespace}:[{r.path.join("/")}]
                  </li>
                ))}
              </ul>
            </dd>
            {Object.keys(i.params).length > 0 && (
              <>
                <dt>{t("signatureParams")}</dt>
                <dd>
                  <ul className={BULLETS}>
                    {Object.entries(i.params).map(([k, v]) => (
                      <li key={k}>
                        <span className={MONO}>{k}</span>: {v}
                      </li>
                    ))}
                  </ul>
                </dd>
              </>
            )}
            <dt>{t("signatureValidity")}</dt>
            <dd className={MONO}>
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

  const confirm = useCallback<Confirm>(
    (view) =>
      new Promise<boolean>((resolve) => {
        setPending({ view, resolve });
      }),
    [],
  );

  const finish = (signed: boolean) => {
    pending?.resolve(signed);
    setPending(null);
  };

  // X11: the signature screen looks like nothing else in the console
  const element =
    pending === null ? null : (
      <Dialog
        isOpen
        onOpenChange={(open) => {
          if (!open) finish(false);
        }}
      >
        <DialogContent
          showCloseButton={false}
          isDismissable={false}
          className="max-h-[calc(100svh-2rem)] overflow-y-auto bg-amber-50 text-neutral-900 ring-4 ring-neutral-900 sm:max-w-2xl dark:ring-neutral-100"
        >
          <DialogHeader>
            <DialogTitle className="text-xl">{t("signatureTitle")}</DialogTitle>
            <DialogDescription className="text-base text-neutral-700">
              {t("signatureIntro")}
            </DialogDescription>
          </DialogHeader>
          <Body view={pending.view} />
          <DialogFooter>
            <Button
              variant="outline"
              className="border-neutral-900 bg-transparent text-neutral-900 hover:bg-neutral-900/10"
              onPress={() => {
                finish(false);
              }}
            >
              {t("signatureCancel")}
            </Button>
            <Button
              className="bg-neutral-900 text-white hover:bg-neutral-700"
              onPress={() => {
                finish(true);
              }}
            >
              {t("signatureSign")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    );
  return [confirm, element] as const;
}
