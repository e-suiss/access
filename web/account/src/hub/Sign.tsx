// X11, TN-131: the signature screen renders only what the Kernel decoded from the bytes about to
// be signed, as text nodes; nothing is signed until the person presses Sign. There is no
// "remember this" (XI-19).
import { Button } from "@suiss/access-ui/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@suiss/access-ui/components/ui/dialog";
import { useCallback, useState, type ReactElement } from "react";

import { t } from "../lib/i18n.js";
import type { Confirm, SignatureView } from "../lib/instance.js";
import { MONO } from "../lib/ui.js";

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
      <Dialog
        isOpen
        onOpenChange={(open) => {
          if (!open) close(false);
        }}
      >
        <DialogContent showCloseButton={false} isDismissable={false} className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>{t("sign.title")}</DialogTitle>
          </DialogHeader>
          {pending.view.intents.map((i) => (
            <dl key={i.digest} className="flex flex-col gap-2 rounded-xl bg-muted p-4">
              <dt className="font-semibold">
                {t("sign.action", { action: `${i.action.namespace}.${i.action.name}` })}
              </dt>
              <dd>
                <ul className="flex flex-col gap-1">
                  {i.resources.map((r) => (
                    <li key={`${r.namespace}:${r.path.join("/")}`} className={MONO}>
                      {t("sign.resource", { resource: `${r.namespace}:${r.path.join("/")}` })}
                    </li>
                  ))}
                </ul>
              </dd>
            </dl>
          ))}
          <DialogFooter>
            <Button
              variant="outline"
              onPress={() => {
                close(false);
              }}
            >
              {t("action.cancel")}
            </Button>
            <Button
              onPress={() => {
                close(true);
              }}
            >
              {t("action.sign")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    );
  return { confirm, dialog };
}
