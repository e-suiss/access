// OP-156 m.3 (v), m.24 (b), (g), §8.17.5.11, §7.9.9.3, S1, X10, X11, XI-3: "save my card". A
// merchant's request names the Grant it asks for; the page previews it from that authority
// alone (per-order limit, end, purpose), refuses anything that is not a bounded payment Grant to
// the merchant, and commits the customer's own grant.issue from their self-anchor, agency own,
// after the signature screen. It is shown done only once Access recorded it.
import { pay } from "@esuiss/access";
import { payment } from "@suiss/access-react";
import { useState, type ReactElement } from "react";

import { commitMeta, type Revoking } from "../lib/adp.js";
import { fromB64url } from "../lib/api.js";
import { at, catalogue, locale, t } from "../lib/i18n.js";
import type { Confirm, Instance } from "../lib/instance.js";

/** What the merchant hands the page in `#request=<base64url JSON>`. */
interface Request {
  readonly merchant: string;
  /** The merchant's Party, base64url. */
  readonly party: string;
  /** The customer's self-anchor the Grant rests on. */
  readonly anchor: string;
  /** The canonical authority JSON of the Grant. */
  readonly authority: unknown;
}

function requestOf(hash: string): Request | undefined {
  const raw = new URLSearchParams(hash.replace(/^#/, "")).get("request");
  if (raw === null) return undefined;
  try {
    const v = JSON.parse(new TextDecoder().decode(fromB64url(raw))) as Record<string, unknown>;
    const { merchant, party, anchor, authority } = v;
    if (typeof merchant !== "string" || typeof party !== "string" || typeof anchor !== "string") {
      return undefined;
    }
    return { merchant, party, anchor, authority };
  } catch {
    return undefined;
  }
}

export function SaveCardPage({
  instance,
  confirm,
}: {
  readonly instance: Instance;
  readonly confirm: Confirm;
}): ReactElement {
  const [request] = useState(() => requestOf(location.hash));
  const [done, setDone] = useState<Revoking | null>(null);
  const [failed, setFailed] = useState(false);
  if (request === undefined) return <p role="alert">{t("shell.unavailable")}</p>;
  const card = pay.saveCardOf(request.authority, request.party);
  if (typeof card === "string") {
    return (
      <p role="alert" data-refused={card}>
        {t("merchants.save_card_refused", { merchant: request.merchant })}
      </p>
    );
  }
  if (done !== null) {
    return (
      <p role="status" data-testid="outcome">
        {t(done.shown)}
      </p>
    );
  }
  return (
    <div data-testid="save-card-page">
      <payment.SaveCard
        merchant={request.merchant}
        perOrder={card.perOrder}
        until={at(card.until)}
        locale={locale}
        catalogue={catalogue}
        onConfirm={() => {
          commitMeta(instance, confirm, "grant_issue", {
            grant_issue: {
              basis: { anchor: request.anchor },
              holder: { party: request.party },
              authority: request.authority,
              agency: ["own"],
            },
          })
            .then(setDone)
            .catch(() => {
              setFailed(true);
            });
        }}
        onCancel={() => {
          history.back();
        }}
      />
      {failed && <p role="alert">{t("outcome.not_recorded")}</p>}
    </div>
  );
}
